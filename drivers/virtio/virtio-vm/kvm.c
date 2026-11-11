// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/err.h>
#include <linux/hw_random.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/virtio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/virtio_config.h>
#include <linux/kvm_host.h>
#include <linux/miscdevice.h>
#include <linux/anon_inodes.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/refcount.h>
#include <linux/idr.h>
#include <linux/sched/signal.h>

#include <uapi/linux/kvm.h>
#include <uapi/asm/kvm.h>

#include "common.h"
#include "kvm.h"
#include "inode.h"
#include "trace.h"

#undef pr_fmt
#define pr_fmt(fmt) "virtio-vm: kvm: " fmt

struct virtio_kvm_dev_ctx {
	u64 handle;
	u64 partition_id;
	struct virtio_kvm_partition *part;
};

struct virtio_kvm_mem_region {
	struct list_head link;
	int slot;
	size_t memory_size;
};

struct virtio_kvm_vm {
	u64 handle;
	u64 partition_id;
	struct virtio_kvm_partition *part;
	struct mutex region_lock;
	struct list_head memory_regions;

	spinlock_t fd_lock;
	struct vhost_task *irqfd_thread;
	struct list_head ioeventfds;
	struct list_head irqfds;
	struct file *file;

	struct vcpu_shared_memory *shm;
	u64 shm_phys_offset;
	size_t shm_size;
	struct virtio_kvm_eventfd *run_notify;
};

struct virtio_kvm_vcpu {
	u64 handle;
	struct virtio_kvm_vm *vm;
	u32 vcpu_id;
	struct mutex mutex;
	struct list_head active_link;
	wait_queue_head_t wait;
	bool completed;
	int err;
	u64 poll_ns;		/* Current adaptive polling window */
};

struct virtio_kvm_ioeventfd_link {
	struct list_head link;
	struct virtio_kvm_vm *vm;
	struct virtio_kvm_eventfd *evfd;
	u64 l1_handle;
	/* Store a copy of the original ioeventfd, since we need
	 * addr/datamatch/len to deassign */
	struct kvm_ioeventfd orig;
};

struct virtio_kvm_irqfd_link {
	struct list_head link;
	struct virtio_kvm_vm *vm;
	struct virtio_kvm_eventfd *evfd;
	u64 handle;
	poll_table pt;
	wait_queue_entry_t wait;
	int gsi;
	struct work_struct inject;
	struct work_struct shutdown;
	struct virtio_kvm_eventfd *resample_evfd;
	u64 resample_efd_handle;
};

static int virtio_kvm_ioeventfd_deassign(struct virtio_kvm_vm *vm,
			      struct virtio_kvm_ioeventfd *ioeventfd);

static int poll_idle_timeout_us = 1000;
module_param(poll_idle_timeout_us, int, 0644);

/*
 * If false, KVM_RUN completions are not busy-polled. Instead, Tachyon signals
 * a per-VM eventfd on completion and the polling thread only scans the shared
 * memory when notified. Only takes effect for VMs created afterwards.
 */
static bool vcpu_poll = true;
module_param(vcpu_poll, bool, 0644);

/*
 * Adaptive per-vCPU polling, used when vcpu_poll is false. After submitting
 * KVM_RUN, the vCPU thread polls for completion for up to its current window
 * before blocking for the notification. Like KVM halt-polling, the window
 * grows (from vcpu_poll_start_ns, doubling) while completions arrive within
 * vcpu_poll_max_ns, and shrinks (halving to 0) when they take longer.
 * vcpu_poll_max_ns = 0 disables it.
 */
static unsigned long vcpu_poll_max_ns;
module_param(vcpu_poll_max_ns, ulong, 0644);
static unsigned long vcpu_poll_start_ns = 10000;
module_param(vcpu_poll_start_ns, ulong, 0644);

/* Statistics (racy, informational): polls that hit, missed, or were skipped. */
static unsigned long vcpu_poll_hits, vcpu_poll_misses, vcpu_poll_skipped;
module_param(vcpu_poll_hits, ulong, 0444);
module_param(vcpu_poll_misses, ulong, 0444);
module_param(vcpu_poll_skipped, ulong, 0444);

#define VIRTKVM_MAX_MSR_ENTRIES		4096
#define VIRTKVM_MAX_CPUID_ENTRIES	2048
#define VIRTKVM_MAX_NESTED_STATE_SIZE	(64 * 1024)
#define VIRTKVM_MAX_PMU_EVENTS		4096
#define VIRTKVM_MAX_IRQ_ROUTES		4096

static int
virtio_kvm_handle_msr_list(u64 handle, unsigned int ioctl, unsigned long arg, u64 *data)
{
	struct kvm_msr_list __user *msr_list = u64_to_user_ptr((u64)arg);
	struct kvm_msr_list *klist;
	size_t size;
	u32 nmsrs;
	int err;

	if (get_user(nmsrs, &msr_list->nmsrs))
		return -EFAULT;

	if (nmsrs > VIRTKVM_MAX_MSR_ENTRIES)
		return -E2BIG;

	size = struct_size(klist, indices, nmsrs);
	klist = kzalloc(size, GFP_KERNEL);
	if (!klist)
		return -ENOMEM;

	if (copy_from_user(klist, msr_list, size)) {
		kfree(klist);
		return -EFAULT;
	}
	klist->nmsrs = nmsrs;

	err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl,
				      __pa(klist), data);
	if (copy_to_user(msr_list, klist, size))
		err = -EFAULT;

	kfree(klist);
	return err;
}

static int
virtio_kvm_handle_msrs(u64 handle, unsigned int ioctl, unsigned long arg, u64 *data)
{
	struct kvm_msrs __user *msrs = u64_to_user_ptr((u64)arg);
	struct kvm_msrs *kmsrs;
	size_t size;
	u32 nmsrs;
	int err;

	if (get_user(nmsrs, &msrs->nmsrs))
		return -EFAULT;

	if (nmsrs > VIRTKVM_MAX_MSR_ENTRIES)
		return -E2BIG;

	size = struct_size(kmsrs, entries, nmsrs);
	kmsrs = kzalloc(size, GFP_KERNEL);
	if (!kmsrs)
		return -ENOMEM;

	if (copy_from_user(kmsrs, msrs, size)) {
		kfree(kmsrs);
		return -EFAULT;
	}
	kmsrs->nmsrs = nmsrs;

	err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl,
				      __pa(kmsrs), data);
	if (!err && copy_to_user(msrs, kmsrs, size))
		err = -EFAULT;

	kfree(kmsrs);
	return err;
}

static int
virtio_kvm_handle_device_attr(u64 handle, unsigned int ioctl, unsigned long arg,
			      u64 *data)
{
	struct kvm_device_attr __user *uattr = u64_to_user_ptr((u64)arg);
	struct kvm_device_attr *attr = NULL;
	u64 __user *uattr_data = NULL;
	const bool has_data = ioctl != KVM_HAS_DEVICE_ATTR;
	u64 *attr_data = NULL;
	int ret;

	ret = -ENOMEM;
	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr)
		goto out;

	ret = -EFAULT;
	if (copy_from_user(attr, uattr, sizeof(*attr)))
		goto out;

	if (has_data) {
		ret = -ENOMEM;
		attr_data = kzalloc(sizeof(*attr_data), GFP_KERNEL);
		if (!attr_data)
			goto out;

		ret = -EFAULT;
		uattr_data = (u64 __user *)attr->addr;
		if (copy_from_user(attr_data, uattr_data, sizeof(*attr_data)))
			goto out;

		attr->addr = __pa(attr_data);
	}

	ret = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl,
				      __pa(attr), data);

	if (ioctl == KVM_GET_DEVICE_ATTR && !ret) {
		if (copy_to_user(uattr_data, attr_data, sizeof(*attr_data)))
			ret = -EFAULT;
	}
out:
	kfree(attr_data);
	kfree(attr);
	return ret;
}

static int
virtio_kvm_handle_cpuid(u64 handle, unsigned int ioctl, unsigned long arg, u64 *data)
{
	struct kvm_cpuid2 __user *cpuid2 = u64_to_user_ptr((u64)arg);
	struct kvm_cpuid2 *kcpuid;
	size_t size;
	u32 nent;
	int err;

	if (get_user(nent, &cpuid2->nent))
		return -EFAULT;

	if (nent > VIRTKVM_MAX_CPUID_ENTRIES)
		return -E2BIG;

	size = struct_size(kcpuid, entries, nent);
	kcpuid = kzalloc(size, GFP_KERNEL);
	if (!kcpuid)
		return -ENOMEM;

	if (copy_from_user(kcpuid, cpuid2, size)) {
		kfree(kcpuid);
		return -EFAULT;
	}
	kcpuid->nent = nent;

	err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl,
				      __pa(kcpuid), data);
	if (!err && copy_to_user(cpuid2, kcpuid, size))
		err = -EFAULT;

	kfree(kcpuid);
	return err;
}

static int
virtio_kvm_handle_nested_state(u64 handle, unsigned int ioctl, unsigned long arg, u64 *data)
{
	struct kvm_nested_state __user *state = u64_to_user_ptr((u64)arg);
	struct kvm_nested_state *kstate;
	u32 size;
	int err;

	if (get_user(size, &state->size))
		return -EFAULT;

	if (size < sizeof(struct kvm_nested_state) ||
	    size > VIRTKVM_MAX_NESTED_STATE_SIZE)
		return -EINVAL;

	kstate = kzalloc(size, GFP_KERNEL);
	if (!kstate)
		return -ENOMEM;

	if (copy_from_user(kstate, state, size)) {
		kfree(kstate);
		return -EFAULT;
	}
	kstate->size = size;

	err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl,
				      __pa(kstate), data);
	if (!err && copy_to_user(state, kstate, size))
		err = -EFAULT;

	kfree(kstate);
	return err;
}

static int
virtio_kvm_set_pmu_event_filter(u64 handle, unsigned int ioctl, unsigned long arg)
{
	struct kvm_pmu_event_filter __user *filter = u64_to_user_ptr((u64)arg);
	struct kvm_pmu_event_filter *kfilter;
	size_t size;
	u32 nevents;
	int err;

	if (get_user(nevents, &filter->nevents))
		return -EFAULT;

	if (nevents > VIRTKVM_MAX_PMU_EVENTS)
		return -E2BIG;

	size = struct_size(kfilter, events, nevents);
	kfilter = kzalloc(size, GFP_KERNEL);
	if (!kfilter)
		return -ENOMEM;

	if (copy_from_user(kfilter, filter, size)) {
		kfree(kfilter);
		return -EFAULT;
	}
	kfilter->nevents = nevents;

	err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl,
				      __pa(kfilter), NULL);
	kfree(kfilter);
	return err;
}

static int
virtio_kvm_set_gsi_routing(u64 handle, unsigned int ioctl, unsigned long arg)
{
	struct kvm_irq_routing __user *routing = u64_to_user_ptr((u64)arg);
	struct kvm_irq_routing *krouting;
	size_t size;
	u32 nr;
	int err;

	if (get_user(nr, &routing->nr))
		return -EFAULT;

	if (nr > VIRTKVM_MAX_IRQ_ROUTES)
		return -EINVAL;

	size = struct_size(krouting, entries, nr);
	krouting = kzalloc(size, GFP_KERNEL);
	if (!krouting)
		return -ENOMEM;

	if (copy_from_user(krouting, routing, size)) {
		kfree(krouting);
		return -EFAULT;
	}
	krouting->nr = nr;

	err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl,
				      __pa(krouting), NULL);
	kfree(krouting);
	return err;
}

static int
virtio_kvm_handle_xsave(struct virtio_kvm_vcpu *vcpu, unsigned int ioctl,
			unsigned long arg, u64 *data)
{
	u64 size = sizeof(struct kvm_xsave);
	int ret;

	if (ioctl != KVM_GET_XSAVE) {
		/*
		 * KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2) returns the size of the
		 * extended xsave state when dynamic XSAVE features are enabled.
		 */
		ret = virtio_kvm_send_command(vcpu->vm->handle, VIRTIO_VM_IOCTL,
					      KVM_CHECK_EXTENSION,
					      KVM_CAP_XSAVE2, &size);
		if (ret)
			return ret;

		if (size < sizeof(struct kvm_xsave))
			size = sizeof(struct kvm_xsave);
	}

	return virtio_kvm_send_command_ucopy(vcpu->handle, VIRTIO_VM_IOCTL,
					     ioctl, arg, size, NULL);
}

static int
virtio_kvm_handle_enable_cap(u64 handle, unsigned int ioctl, unsigned long arg, u64 *data)
{
	struct kvm_enable_cap __user *ucap = u64_to_user_ptr((u64)arg);
	struct kvm_enable_cap *cap;
	int ret;

	ret = -ENOMEM;
	cap = kzalloc(sizeof(*cap), GFP_KERNEL);
	if (!cap)
		return ret;

	ret = -EFAULT;
	if (copy_from_user(cap, ucap, sizeof(*cap)))
		goto out;

	switch (cap->cap) {
	case KVM_CAP_HYPERV_ENLIGHTENED_VMCS:
	    {
		void __user *user_vmcs_version;
		uint16_t *vmcs_version;

		ret = -ENOMEM;
		vmcs_version = kzalloc(sizeof(*vmcs_version), GFP_KERNEL);
		if (!vmcs_version)
			goto out;

		user_vmcs_version = (void __user *)(uintptr_t)cap->args[0];
		cap->args[0] = __pa(vmcs_version);

		ret = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl,
					      __pa(cap), data);
		if (ret)
			goto free_vmcs_version;

		ret = -EFAULT;
		/* Only need to copy out the vmcs version */
		if (copy_to_user(user_vmcs_version, vmcs_version,
				 sizeof(*vmcs_version)))
			goto free_vmcs_version;

		ret = 0;
free_vmcs_version:
		kfree(vmcs_version);
		goto out;
	    }
	default:
		/* Just a flat ucopy ioctl */
		ret = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl,
					      __pa(cap), data);
		if (copy_to_user(ucap, cap, sizeof(*cap)))
			ret = -EFAULT;
	}

out:
	kfree(cap);
	return ret;
}

static int
virtio_kvm_open(struct inode *inode, struct file *filp)
{
	struct miscdevice *misc = filp->private_data;
	struct virtio_kvm_partition *part;
	struct virtio_kvm_dev_ctx *ctx;
	u64 partition_id, data;
	int ret;

	part = container_of(misc, struct virtio_kvm_partition, misc_dev);
	partition_id = part->partition_id;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	if (part->vi) {
		mutex_lock(&part->vi->partition_lock);
		if (part->dying || list_empty(&part->link)) {
			mutex_unlock(&part->vi->partition_lock);
			kfree(ctx);
			return -ENODEV;
		}
		virtkvm_partition_get(part);
		mutex_unlock(&part->vi->partition_lock);
	}

	ret = virtio_kvm_send_command(-1, VIRTIO_VM_OPEN, partition_id, 0, &data);
	if (ret) {
		virtkvm_partition_put(part);
		kfree(ctx);
		return ret;
	}

	ctx->handle = data;
	ctx->partition_id = partition_id;
	ctx->part = part;
	filp->private_data = ctx;

	return 0;
}

static int
virtio_kvm_release(struct inode *inode, struct file *filp)
{
	struct virtio_kvm_dev_ctx *ctx = filp->private_data;
	int ret = 0;

	if (ctx) {
		u64 handle = ctx->handle;

		ret = virtio_kvm_send_command_async(handle, VIRTIO_VM_CLOSE,
						    0, 0, NULL);
		WARN_ONCE(ret, "Failed to start releasing kvm dev %llx: %d\n", handle, ret);
		virtkvm_partition_put(ctx->part);
		kfree(ctx);
	}

	return ret;
}

static const struct vm_operations_struct vcpu_vm_ops = {
	.open = virtio_vm_vma_open,
	.close = virtio_vm_vma_close,
	.may_split = virtio_vm_vma_may_split,
};

static int
virtio_kvm_vcpu_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct virtio_kvm_vcpu *vcpu = filp->private_data;

	return virtio_kvm_generic_mmap(vcpu->handle, vma, &vcpu_vm_ops);
}

static int
virtio_kvm_stats_release(struct inode *inode, struct file *filp)
{
	u64 handle = (u64)filp->private_data;
	int ret;

	ret = virtio_kvm_send_command_async(handle, VIRTIO_VM_CLOSE,
					    0, 0, NULL);
	WARN_ONCE(ret, "Failed to start releasing stats %llx: %d\n",
			handle, ret);

	return ret;
}

static ssize_t
virtio_kvm_stats_read(struct file *filp, char __user *user_buffer,
		     size_t size, loff_t *offset)
{
	u64 handle = (u64)filp->private_data;

	return virtio_kvm_file_read(handle, user_buffer, size, offset);
}

static const struct file_operations kvm_stats_fops = {
	.release = virtio_kvm_stats_release,
	.read = virtio_kvm_stats_read,
	.llseek = noop_llseek,
};

/* Marks @vcpu's KVM_RUN as completed outside the polling thread. */
static void virtio_kvm_vcpu_complete(struct virtio_kvm_vcpu *vcpu)
{
	spin_lock(&vi_device->vcpu_lock);
	list_del_init(&vcpu->active_link);
	/* Pairs with smp_load_acquire() in virtio_kvm_vcpu_run() */
	smp_store_release(&vcpu->completed, true);
	spin_unlock(&vi_device->vcpu_lock);
}

/*
 * Polls for completion of @vcpu's KVM_RUN for up to its polling window.
 * FLAG_GUEST_POLLING is set in the state word while polling; Tachyon skips the
 * completion notification if it observes the flag when publishing
 * STATE_COMPLETED. Clearing the flag is a fully ordered RMW that is re-checked
 * against the state, so a completion is either seen here or notified.
 */
static bool virtio_kvm_vcpu_poll(struct virtio_kvm_vcpu *vcpu,
				 struct per_vcpu_state *state, u64 start)
{
	bool done = false;
	u32 old;

	do {
		/* Pairs with the release of STATE_COMPLETED in the host */
		if ((virt_load_acquire(&state->state) & STATE_MASK) == STATE_COMPLETED) {
			done = true;
			break;
		}
		cpu_relax();
	} while (ktime_get_ns() - start < vcpu->poll_ns &&
		 !need_resched() && !signal_pending(current));

	old = READ_ONCE(state->state);
	while (!try_cmpxchg(&state->state, &old, old & ~FLAG_GUEST_POLLING))
		;
	if ((old & STATE_MASK) == STATE_COMPLETED)
		done = true;

	if (done)
		virtio_kvm_vcpu_complete(vcpu);
	return done;
}

static void virtio_kvm_vcpu_adjust_poll(struct virtio_kvm_vcpu *vcpu, bool hit, u64 waited)
{
	u64 max = READ_ONCE(vcpu_poll_max_ns);
	u64 start = READ_ONCE(vcpu_poll_start_ns);
	u64 val = vcpu->poll_ns;

	if (hit)
		vcpu_poll_hits++;
	else if (val)
		vcpu_poll_misses++;
	else
		vcpu_poll_skipped++;

	if (waited <= max) {
		if (!hit)
			val = val ? min(val * 2, max) : min(start, max);
	} else {
		val /= 2;
		if (val < start)
			val = 0;
	}
	vcpu->poll_ns = val;
}

static int virtio_kvm_vcpu_run(struct virtio_kvm_vcpu *vcpu)
{
	struct per_vcpu_state *state;
	u32 old_s, new_s, prev;
	u64 handle = vcpu->handle;
	bool wake_thread = false;
	bool adaptive, guest_poll, hit = false;
	u64 start = 0;
	int err;

	if (mutex_lock_killable(&vcpu->mutex))
		return -EINTR;

	adaptive = !READ_ONCE(vcpu_poll) && vcpu->vm->run_notify;
	guest_poll = adaptive && vcpu->poll_ns;

	trace_virtio_vm_vcpu_run_entry(handle, vcpu->vcpu_id);

	state = &vcpu->vm->shm->vcpus[vcpu->vcpu_id];

	smp_store_release(&vcpu->completed, false);

	spin_lock(&vi_device->vcpu_lock);
	if (list_empty(&vcpu->active_link)) {
		wake_thread = list_empty(&vi_device->active_vcpus);
		list_add(&vcpu->active_link, &vi_device->active_vcpus);
	}
	spin_unlock(&vi_device->vcpu_lock);

	/* 1. Set request state */
	old_s = virt_load_acquire(&state->state);
	for (;;) {
		new_s = (old_s & ~STATE_MASK) | STATE_RUN_REQUESTED;
		if (guest_poll)
			new_s |= FLAG_GUEST_POLLING;
		prev = cmpxchg(&state->state, old_s, new_s);
		if (prev == old_s)
			break;
		old_s = prev;
	}

	/* 2. Host Wakeup (Kick) */
	if (!(old_s & FLAG_HOST_POLLING)) {
		trace_virtio_vm_ready(handle);
		err = virtio_kvm_send_command_async(handle, VIRTIO_VM_READY, 0, 0, NULL);
		if (err) {
			spin_lock(&vi_device->vcpu_lock);
			list_del_init(&vcpu->active_link);
			spin_unlock(&vi_device->vcpu_lock);
			smp_store_release(&vcpu->completed, true);
			goto out_reset_state;
		}
	}

	if (wake_thread)
		wake_up(&vi_device->vcpu_poll_wait);

	if (adaptive) {
		start = ktime_get_ns();
		if (guest_poll)
			hit = virtio_kvm_vcpu_poll(vcpu, state, start);
	}

	/* 3. Wait for completion */
	err = wait_event_interruptible(vcpu->wait, smp_load_acquire(&vcpu->completed));
	if (!err && adaptive)
		virtio_kvm_vcpu_adjust_poll(vcpu, hit, ktime_get_ns() - start);
	if (err == -ERESTARTSYS) {
		struct virtkvm_cmd *int_cmd;
		int int_err = -ENOMEM;

		/* Reflect interruption into host and wait for it to complete. */
		trace_virtio_vm_cmd_int(handle);
		int_cmd = kzalloc(sizeof(*int_cmd), GFP_KERNEL);
		if (int_cmd) {
			int_err = __virtio_kvm_send_command(int_cmd, handle, VIRTIO_VM_CMD_INT, 0,
							    0, NULL, COMMAND_ASYNC);
			if (int_err)
				kfree(int_cmd);
		}
		if (!int_err) {
			wait_event(vcpu->wait, smp_load_acquire(&vcpu->completed));
		} else {
			spin_lock(&vi_device->vcpu_lock);
			list_del_init(&vcpu->active_link);
			spin_unlock(&vi_device->vcpu_lock);
			smp_store_release(&vcpu->completed, true);
			err = int_err;
			goto out_reset_state;
		}
	}

	/* 4. Result Processing */
	err = state->status;
out_reset_state:
	/* Pair with virt_store_release in host */
	old_s = smp_load_acquire(&state->state);
	for (;;) {
		new_s = (old_s & ~STATE_MASK) | STATE_IDLE;
		prev = cmpxchg_release(&state->state, old_s, new_s);
		if (prev == old_s)
			break;
		old_s = prev;
	}

	trace_virtio_vm_vcpu_run_exit(handle, vcpu->vcpu_id, err);
	mutex_unlock(&vcpu->mutex);

	return err;
}

static long
virtio_kvm_vcpu_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct virtio_kvm_vcpu *vcpu = filp->private_data;
	u64 handle = vcpu->handle;
	struct file *file;
	u64 data = 0;
	int err;
	int fd;

#define CASE_KVM_IOCTL_BASIC(ioc_name) \
	case ioc_name: \
		err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, \
					      ioctl, arg, &data); \
		break

#define CASE_KVM_IOCTL_UCOPY(ioc_name, arg_t) \
	case ioc_name: \
		err = virtio_kvm_send_command_ucopy(handle, VIRTIO_VM_IOCTL, \
						    ioctl, arg, sizeof(arg_t), \
						    &data); \
		break

	switch (ioctl) {
	CASE_KVM_IOCTL_UCOPY(KVM_SET_XCRS,	struct kvm_xcrs);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_XCRS,	struct kvm_xcrs);
	CASE_KVM_IOCTL_UCOPY(KVM_TRANSLATE,	struct kvm_translation);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_LAPIC,	struct kvm_lapic_state);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_LAPIC,	struct kvm_lapic_state);
	CASE_KVM_IOCTL_UCOPY(KVM_VCPU_TSC_CTRL,	u64);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_GUEST_DEBUG,	struct kvm_guest_debug);
	CASE_KVM_IOCTL_UCOPY(KVM_PRE_FAULT_MEMORY,	struct kvm_pre_fault_memory);
#ifdef KVM_X86_SETUP_MCE
	CASE_KVM_IOCTL_UCOPY(KVM_X86_SETUP_MCE,	u64);
#endif
#ifdef KVM_X86_SET_MCE
	CASE_KVM_IOCTL_UCOPY(KVM_X86_SET_MCE,	struct kvm_x86_mce);
#endif
	CASE_KVM_IOCTL_BASIC(KVM_SET_TSC_KHZ);
	CASE_KVM_IOCTL_BASIC(KVM_GET_TSC_KHZ);
	CASE_KVM_IOCTL_BASIC(KVM_KVMCLOCK_CTRL);
	CASE_KVM_IOCTL_BASIC(KVM_SMI);
	case KVM_RUN:
		err = virtio_kvm_vcpu_run(vcpu);
		break;
	case KVM_SET_SIGNAL_MASK:
		err = 0;
		pr_warn_once("KVM_SET_SIGNAL_MASK unimplemented!\n");
		break;
	CASE_KVM_IOCTL_UCOPY(KVM_SET_SREGS,	struct kvm_sregs);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_SREGS,	struct kvm_sregs);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_SREGS2,	struct kvm_sregs2);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_SREGS2,	struct kvm_sregs2);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_REGS,	struct kvm_regs);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_REGS,	struct kvm_regs);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_MP_STATE,	struct kvm_mp_state);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_MP_STATE,	struct kvm_mp_state);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_VCPU_EVENTS,	struct kvm_vcpu_events);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_VCPU_EVENTS,	struct kvm_vcpu_events);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_DEBUGREGS,	struct kvm_debugregs);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_DEBUGREGS,	struct kvm_debugregs);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_FPU,	struct kvm_fpu);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_FPU,	struct kvm_fpu);
	CASE_KVM_IOCTL_UCOPY(KVM_TPR_ACCESS_REPORTING,	struct kvm_tpr_access_ctl);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_VAPIC_ADDR,	struct kvm_vapic_addr);
	CASE_KVM_IOCTL_UCOPY(KVM_INTERRUPT,	struct kvm_interrupt);
	case KVM_SET_XSAVE:
	case KVM_GET_XSAVE:
	case KVM_GET_XSAVE2:
		err = virtio_kvm_handle_xsave(vcpu, ioctl, arg, &data);
		break;
	case KVM_ENABLE_CAP:
		err = virtio_kvm_handle_enable_cap(handle, ioctl, arg, &data);
		break;
	case KVM_SET_NESTED_STATE:
	case KVM_GET_NESTED_STATE:
		err = virtio_kvm_handle_nested_state(handle, ioctl, arg, &data);
		break;
	case KVM_SET_CPUID2:
	case KVM_GET_CPUID2:
		err = virtio_kvm_handle_cpuid(handle, ioctl, arg, &data);
		break;
	case KVM_SET_MSRS:
	case KVM_GET_MSRS:
		err = virtio_kvm_handle_msrs(handle, ioctl, arg, &data);
		break;
	case KVM_GET_STATS_FD:
		err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL,
					      ioctl, arg, &data);
		break;
	case KVM_SET_DEVICE_ATTR:
	case KVM_GET_DEVICE_ATTR:
	case KVM_HAS_DEVICE_ATTR:
		err = virtio_kvm_handle_device_attr(handle, ioctl, arg, &data);
		break;

	default:
		pr_err("virtio_kvm_vcpu_ioctl: cannot translate unknown ioctl:"
		       " 0x%x\n", ioctl);
		return -EINVAL;
	}

#undef CASE_KVM_IOCTL_UCOPY
#undef CASE_KVM_IOCTL_BASIC

	if (err)
		return err;

	switch (ioctl) {
	case KVM_GET_STATS_FD:
		fd = get_unused_fd_flags(O_CLOEXEC);
		if (fd < 0) {
			virtio_kvm_send_command_async(data, VIRTIO_VM_CLOSE, 0, 0, NULL);
			return fd;
		}
		file = anon_inode_getfile_fmode("kvm-vcpu-stats",
						&kvm_stats_fops,
						(void *)data, O_RDONLY,
						FMODE_PREAD);
		if (IS_ERR(file)) {
			put_unused_fd(fd);
			virtio_kvm_send_command_async(data, VIRTIO_VM_CLOSE, 0, 0, NULL);
			return PTR_ERR(file);
		}
		fd_install(fd, file);
		return fd;
	}

	return data;
}

static int
virtio_kvm_vcpu_release(struct inode *inode, struct file *filp)
{
	struct virtio_kvm_vcpu *vcpu = filp->private_data;
	int ret;

	spin_lock(&vi_device->vcpu_lock);
	if (!list_empty(&vcpu->active_link))
		list_del(&vcpu->active_link);
	spin_unlock(&vi_device->vcpu_lock);

	ret = virtio_kvm_send_command_async(vcpu->handle, VIRTIO_VM_CLOSE,
					    0, 0, NULL);
	WARN_ONCE(ret, "Failed to start releasing vcpu %llx: %d\n",
			vcpu->handle, ret);

	fput(vcpu->vm->file);

	kfree(vcpu);

	return ret;
}

static const struct file_operations kvm_vcpu_fops = {
	.release = virtio_kvm_vcpu_release,
	.unlocked_ioctl = virtio_kvm_vcpu_ioctl,
	.mmap = virtio_kvm_vcpu_mmap,
};

static int
virtio_kvm_device_release(struct inode *inode, struct file *filp)
{
	u64 handle = (u64)filp->private_data;
	int ret;

	ret = virtio_kvm_send_command_async(handle, VIRTIO_VM_CLOSE,
					    0, 0, NULL);
	WARN_ONCE(ret, "Failed to start releasing generic device %llx: %d\n",
			handle, ret);

	return ret;
}

static const struct vm_operations_struct device_vm_ops = {
	.open = virtio_vm_vma_open,
	.close = virtio_vm_vma_close,
	.may_split = virtio_vm_vma_may_split,
};

static int
virtio_kvm_device_mmap(struct file *filp, struct vm_area_struct *vma)
{
	u64 handle = (u64)filp->private_data;

	return virtio_kvm_generic_mmap(handle, vma, &device_vm_ops);
}

static long
virtio_kvm_device_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	/* u64 handle = (u64)filp->private_data; */

	/*
	 * FIXME: To properly handle ioctl, we need to know which device we are
	 * and which ioctl is being made. Do this later.
	 */
	pr_err("virtio_kvm_device_ioctl: not implemented!");

	return -ENOTSUPP;
}

static const struct file_operations kvm_device_fops = {
	.release = virtio_kvm_device_release,
	.unlocked_ioctl = virtio_kvm_device_ioctl,
	.mmap = virtio_kvm_device_mmap,
};

static struct virtio_kvm_mem_region *
find_mem_region(struct virtio_kvm_vm *vm,
		int slot)
{
	struct virtio_kvm_mem_region *lreg;
	struct list_head *p;

	lockdep_assert_held(&vm->region_lock);

	list_for_each(p, &vm->memory_regions) {
		lreg = container_of(p,
				struct virtio_kvm_mem_region,
				link);
		if (lreg->slot == slot)
			break;
	}
	if (list_is_head(p, &vm->memory_regions))
		return NULL;

	return lreg;
}

static void
update_mem_regions(struct virtio_kvm_vm *vm,
		   struct kvm_userspace_memory_region2 *reg,
		   struct virtio_kvm_mem_region *mem_region)
{
	struct virtio_kvm_mem_region *existing;

	mutex_lock(&vm->region_lock);

	existing = find_mem_region(vm, reg->slot);
	if (mem_region) {
		if (existing) {
			existing->memory_size = reg->memory_size;
			mutex_unlock(&vm->region_lock);
			kfree(mem_region);
			return;
		}
		/* Add */
		mem_region->slot = reg->slot;
		mem_region->memory_size = reg->memory_size;
		list_add(&mem_region->link, &vm->memory_regions);
	} else {
		/* Remove */
		if (!WARN_ON_ONCE(!existing)) {
			list_del(&existing->link);
			mutex_unlock(&vm->region_lock);
			kfree(existing);
			return;
		}
	}

	mutex_unlock(&vm->region_lock);
}

static long
virtio_kvm_set_user_memory_region(struct virtio_kvm_vm *vm, unsigned int ioctl,
				  unsigned long arg)
{
	struct kvm_userspace_memory_region2 *ureg, reg, *reg_io;
	struct virtio_kvm_mem_region *mem_region = NULL;
	u64 handle = vm->handle;
	int ret;

	ureg = u64_to_user_ptr((u64)arg);

	switch (ioctl) {
	case KVM_SET_USER_MEMORY_REGION:
		/* Don't leak anything */
		memset(&reg, 0, sizeof(reg));
		ret = copy_from_user(&reg, ureg, sizeof(struct kvm_userspace_memory_region));
		break;
	case KVM_SET_USER_MEMORY_REGION2:
		ret = copy_from_user(&reg, ureg, sizeof(struct kvm_userspace_memory_region2));
		break;
	default:
		return -EINVAL;
	}
	if (ret)
		return -EFAULT;

	if (reg.flags & KVM_MEM_GUEST_MEMFD) {
		/* We don't support guest_memfd yet */
		return -ENOTSUPP;
	}

	if (reg.memory_size > 0) {
		mem_region = kmalloc(sizeof(*mem_region), GFP_KERNEL);
		if (!mem_region)
			return -ENOMEM;
	}

	reg_io = kzalloc(sizeof(*reg_io), GFP_KERNEL);

	ret = -ENOMEM;
	if (!reg_io)
		goto free_mem_region;

	memcpy(reg_io, &reg, sizeof(reg));

	if (reg.memory_size) {
		/* Need to translate VA to PA unless deleting. */
		unsigned long phys_addr;

		ret = translate_va_to_pa(reg.userspace_addr,
					 &phys_addr, reg.memory_size);
		if (ret)
			goto err;

		reg_io->userspace_addr = phys_addr;
	} else {
		/*
		 * userspace_addr should be ignored by the host, but let's
		 * zero it out anyway.
		 */
		reg_io->userspace_addr = 0;
	}

	ret = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl,
				      __pa(reg_io), NULL);

	if (!ret)
		update_mem_regions(vm, &reg, mem_region);

	kfree(reg_io);
	return ret;

err:
	kfree(reg_io);
free_mem_region:
	if (mem_region)
		kfree(mem_region);
	return ret;
}

static int
get_dirty_log_size(struct virtio_kvm_vm *vm, int slot, size_t *size)
{
	struct virtio_kvm_mem_region *region;

	guard(mutex)(&vm->region_lock);

	/* KVM returns ENOENT for invalid slots. */
	region = find_mem_region(vm, slot);
	if (!region)
		return -ENOENT;

	*size = bitmap_size(region->memory_size >> PAGE_SHIFT);
	return 0;
}

/*
 * virtio_kvm_clear_dirty_log is the same as virtio_kvm_get_dirty_log but with
 * struct kvm_clear_dirty_log instead of kvm_dirty_log.
 */
static long
virtio_kvm_clear_dirty_log(struct virtio_kvm_vm *vm, unsigned int ioctl,
			   unsigned long arg)
{
	struct kvm_clear_dirty_log __user *ulog;
	struct kvm_clear_dirty_log *klog;
	unsigned long dirty_log_va;
	unsigned long dirty_log_pa;
	size_t log_size;
	int ret;

	klog = kzalloc(sizeof(*klog), GFP_KERNEL);
	if (!klog)
		return -ENOMEM;

	ulog = u64_to_user_ptr((u64)arg);

	ret = -EFAULT;
	if (copy_from_user(klog, ulog, sizeof(*klog)))
		goto free;

	ret = get_dirty_log_size(vm, klog->slot, &log_size);
	if (ret)
		goto free;

	dirty_log_va = (unsigned long __force)klog->dirty_bitmap;
	ret = translate_va_to_pa(dirty_log_va, &dirty_log_pa, log_size);
	if (ret)
		goto free;

	klog->dirty_bitmap = (char __user * __force)dirty_log_pa;

	ret = virtio_kvm_send_command(vm->handle, VIRTIO_VM_IOCTL, ioctl,
				      __pa(klog), NULL);

free:
	kfree(klog);
	return ret;
}

static long
virtio_kvm_get_dirty_log(struct virtio_kvm_vm *vm, unsigned int ioctl,
			 unsigned long arg)
{
	struct kvm_dirty_log __user *ulog;
	struct kvm_dirty_log *klog;
	unsigned long dirty_log_va;
	unsigned long dirty_log_pa;
	size_t log_size;
	int ret;

	klog = kzalloc(sizeof(*klog), GFP_KERNEL);
	if (!klog)
		return -ENOMEM;

	ulog = u64_to_user_ptr((u64)arg);

	ret = -EFAULT;
	if (copy_from_user(klog, ulog, sizeof(*klog)))
		goto free;

	ret = get_dirty_log_size(vm, klog->slot, &log_size);
	if (ret)
		goto free;

	dirty_log_va = (unsigned long __force)klog->dirty_bitmap;
	ret = translate_va_to_pa(dirty_log_va, &dirty_log_pa, log_size);
	if (ret)
		goto free;

	klog->dirty_bitmap = (char __user * __force)dirty_log_pa;

	ret = virtio_kvm_send_command(vm->handle, VIRTIO_VM_IOCTL, ioctl,
				      __pa(klog), NULL);

free:
	kfree(klog);
	return ret;
}

#ifdef KVM_X86_SET_MSR_FILTER
static long
virtio_kvm_set_msr_filter(u64 handle, unsigned int ioctl, unsigned long arg)
{
	struct kvm_msr_filter __user *ufilter;
	struct kvm_msr_filter *kfilter;
	size_t bitmap_cur, num_u8s = 0;
	size_t bitmap_size;
	__u8 *bitmaps;
	int ret;
	int i;

	ufilter = u64_to_user_ptr((u64)arg);

	ret = -ENOMEM;
	kfilter = kzalloc(sizeof(*kfilter), GFP_KERNEL);
	if (!kfilter)
		goto out;

	ret = -EFAULT;
	if (copy_from_user(kfilter, ufilter, sizeof(*kfilter)))
		goto free_kfilter;

	ret = -EINVAL;
	for (i = 0; i < ARRAY_SIZE(kfilter->ranges); ++i) {
		struct kvm_msr_filter_range *user_range = &kfilter->ranges[i];

		if (user_range->nmsrs > KVM_MSR_FILTER_MAX_BITMAP_SIZE * BITS_PER_BYTE)
			goto free_kfilter;

		bitmap_size = BITS_TO_LONGS((size_t)user_range->nmsrs) * sizeof(long);
		if (bitmap_size > KVM_MSR_FILTER_MAX_BITMAP_SIZE)
			goto free_kfilter;

		num_u8s += bitmap_size;
	}

	ret = -ENOMEM;
	bitmaps = kzalloc(sizeof(__u8) * num_u8s, GFP_KERNEL);
	if (!bitmaps)
		goto free_kfilter;

	ret = -EFAULT;
	bitmap_cur = 0;
	for (i = 0; i < ARRAY_SIZE(kfilter->ranges); ++i) {
		struct kvm_msr_filter_range *user_range = &kfilter->ranges[i];
		__u8 *bitmap = &bitmaps[bitmap_cur];

		/*
		 * user_range->bitmap contains a user pointer that must be
		 * translated. Copy it into memory from the direct map and
		 * translate it to a PA here to provide to L0. L0 will
		 * translate the PA to a usable L0 user pointer.
		 */
		bitmap_size = BITS_TO_LONGS((size_t)user_range->nmsrs) * sizeof(long);
		bitmap_cur += bitmap_size;

		if (bitmap_size && copy_from_user(bitmap,
						  kfilter->ranges[i].bitmap,
						  bitmap_size))
			goto free;

		/*
		 * Provide the physical address as a pointer. Ideally we use a
		 * different type, but making another struct that looks just
		 * like kvm_msr_filter_range is a pain.
		 */
		kfilter->ranges[i].bitmap = bitmap_size ? (__u8 *)__pa(bitmap)
							: (__u8 *)-1UL;
	}

	ret = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl,
				      __pa(kfilter), NULL);
	/*
	 * There's no need to copy the bitmaps back to the user, as they are
	 * not changed.
	 */
free:
	kfree(bitmaps);
free_kfilter:
	kfree(kfilter);
out:
	return ret;
}
#endif /* KVM_X86_SET_MSR_FILTER */

static void
irqfd_ptable_queue_proc(struct file *file, wait_queue_head_t *wqh,
			poll_table *pt)
{
	struct virtio_kvm_irqfd_link *irqfd =
		container_of(pt, struct virtio_kvm_irqfd_link, pt);
	add_wait_queue_priority(wqh, &irqfd->wait);
}

static bool
irqfd_is_active(struct virtio_kvm_irqfd_link *irqfd)
{
	return list_empty(&irqfd->link) ? false : true;
}

static void
deactivate_irqfd(struct virtio_kvm_irqfd_link *irqfd)
{
	struct virtio_kvm_vm *vm = irqfd->vm;

	lockdep_assert_held(&vm->fd_lock);
	if (!irqfd_is_active(irqfd))
		return;

	list_del_init(&irqfd->link);

	queue_work(eventfd_cleanup_wq, &irqfd->shutdown);
}

/*
 * Called with wqh->lock held and interrupts disabled
 */
static int
irqfd_wakeup(wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
	struct virtio_kvm_irqfd_link *irqfd =
		container_of(wait, struct virtio_kvm_irqfd_link, wait);
	struct virtio_kvm_vm *vm = irqfd->vm;
	__poll_t flags = key_to_poll(key);

	if (flags & EPOLLIN) {
		u64 cnt;
		eventfd_ctx_do_read(irqfd->evfd->ctx, &cnt);

		schedule_work(&irqfd->inject);
	}

	if (flags & EPOLLHUP) {
		unsigned long iflags;

		/* The eventfd is closing, detach from virtio-kvm */
		spin_lock_irqsave(&vm->fd_lock, iflags);
		deactivate_irqfd(irqfd);
		spin_unlock_irqrestore(&vm->fd_lock, iflags);
	}

	return 0;
}

static void
irqfd_inject(struct work_struct *work)
{
	struct virtio_kvm_irqfd_link *irqfd =
		container_of(work, struct virtio_kvm_irqfd_link, inject);

	virtio_kvm_send_command_async(irqfd->handle,
				      VIRTIO_VM_EVENTFD_WRITE,
				      0, 0, NULL);
}

static void
irqfd_shutdown(struct work_struct *work)
{
	struct virtio_kvm_irqfd_link *irqfd =
		container_of(work, struct virtio_kvm_irqfd_link, shutdown);
	u64 cnt;

	/*
	 * Synchronize with the wait-queue and unhook ourselves to prevent
	 * further events.
	 */
	eventfd_ctx_remove_wait_queue(irqfd->evfd->ctx, &irqfd->wait, &cnt);

	/*
	 * We know no new events will be scheduled at this point, so block
	 * until all previously outstanding events have completed
	 */
	flush_work(&irqfd->inject);

	virtio_kvm_put_evfd(irqfd->evfd);
	if (irqfd->resample_evfd)
		virtio_kvm_put_evfd(irqfd->resample_evfd);

	kfree(irqfd);
}

static long
virtio_kvm_irqfd_link_deassign(struct virtio_kvm_vm *vm, struct kvm_irqfd *args)
{
	struct virtio_kvm_irqfd *irqfd_args_for_host;
	struct virtio_kvm_irqfd_link *irqfd;
	struct eventfd_ctx *eventfd;
	struct list_head *p;
	bool found;
	int ret;

	ret = -EBADF;
	CLASS(fd, f)(args->fd);
	if (fd_empty(f))
		return ret;

	eventfd = eventfd_ctx_fileget(fd_file(f));
	if (IS_ERR(eventfd)) {
		ret = PTR_ERR(eventfd);
		return ret;
	}

	ret = -ENOMEM;
	irqfd_args_for_host = kmalloc(sizeof(*irqfd_args_for_host), GFP_KERNEL);
	if (!irqfd_args_for_host) {
		eventfd_ctx_put(eventfd);
		return ret;
	}

retry:
	found = false;
	spin_lock_irq(&vm->fd_lock);
	list_for_each(p, &vm->irqfds) {
		irqfd = container_of(p,
				     struct virtio_kvm_irqfd_link,
				     link);
		if (irqfd->evfd->ctx == eventfd && irqfd->gsi == args->gsi) {
			list_del_init(p);
			found = true;
			break;
		}
	}
	/*
	 * We must drop the lock to send blocking commands to L0 to drop our
	 * eventfd references. So search one-by-one, and restart searching
	 * after we drop each irqfd.
	 */
	spin_unlock_irq(&vm->fd_lock);
	if (!found)
		goto out;

	irqfd_args_for_host->kvm.flags = args->flags;
	irqfd_args_for_host->kvm.gsi = args->gsi;
	irqfd_args_for_host->kvm.fd = -1;
	irqfd_args_for_host->fd_handle = irqfd->handle;
	irqfd_args_for_host->kvm.resamplefd = -1;
	irqfd_args_for_host->resamplefd_handle = irqfd->resample_efd_handle;
	ret = virtio_kvm_send_command(vm->handle, VIRTIO_VM_IOCTL, KVM_IRQFD,
				      __pa(irqfd_args_for_host), NULL);
	WARN_ONCE(ret, "KVM_IRQFD deassign failed: %d\n", ret);

	queue_work(eventfd_cleanup_wq, &irqfd->shutdown);
	flush_workqueue(eventfd_cleanup_wq);

	goto retry;

out:
	kfree(irqfd_args_for_host);
	eventfd_ctx_put(eventfd);
	return 0;
}

static int
virtio_kvm_irqfd_link_assign(struct virtio_kvm_vm *vm, struct kvm_irqfd *args)
{
	struct virtio_kvm_irqfd *irqfd_args_for_host = NULL;
	struct virtio_kvm_irqfd_link *irqfd = NULL;

	struct eventfd_ctx *resample_eventfd = NULL;
	struct eventfd_ctx *eventfd = NULL;
	struct virtio_kvm_eventfd *evfd = NULL;
	struct virtio_kvm_eventfd *resample_evfd = NULL;
	u64 resample_efd_handle = -1ULL;
	u64 handle = -1ULL;
	int events, ret;

	ret = -EBADF;
	CLASS(fd, f)(args->fd);
	if (fd_empty(f))
		goto err;

	ret = -ENOMEM;
	irqfd = kmalloc(sizeof(*irqfd), GFP_KERNEL);
	if (!irqfd)
		goto err;

	INIT_LIST_HEAD(&irqfd->link);

	irqfd_args_for_host = kmalloc(sizeof(*irqfd_args_for_host), GFP_KERNEL);
	if (!irqfd_args_for_host)
		goto err;

	eventfd = eventfd_ctx_fileget(fd_file(f));
	if (IS_ERR(eventfd)) {
		ret = PTR_ERR(eventfd);
		goto err;
	}

	evfd = virtio_kvm_get_evfd(vm->partition_id, eventfd);
	if (IS_ERR(evfd)) {
		eventfd_ctx_put(eventfd);
		ret = PTR_ERR(evfd);
		goto err;
	}
	handle = evfd->handle;

	if (args->flags & KVM_IRQFD_FLAG_RESAMPLE) {
		/* Set up the resampler */
		ret = -EBADF;
		CLASS(fd, r)(args->resamplefd);
		if (fd_empty(r))
			goto err;
		resample_eventfd = eventfd_ctx_fileget(fd_file(r));
		if (IS_ERR(resample_eventfd)) {
			ret = PTR_ERR(resample_eventfd);
			goto err;
		}
		resample_evfd = virtio_kvm_get_evfd(vm->partition_id, resample_eventfd);
		if (IS_ERR(resample_evfd)) {
			eventfd_ctx_put(resample_eventfd);
			ret = PTR_ERR(resample_evfd);
			goto err;
		}
		resample_efd_handle = resample_evfd->handle;
	} else {
		resample_efd_handle = -1ULL;
	}

	/* Now call KVM_IRQFD in L0 */
	irqfd_args_for_host->kvm.fd = -1;
	irqfd_args_for_host->fd_handle = handle; /* handle is the host eventfd */
	irqfd_args_for_host->kvm.gsi = args->gsi;
	irqfd_args_for_host->kvm.flags = args->flags;
	irqfd_args_for_host->kvm.resamplefd = -1;
	irqfd_args_for_host->resamplefd_handle = resample_efd_handle;
	ret = virtio_kvm_send_command(vm->handle, VIRTIO_VM_IOCTL, KVM_IRQFD,
				      __pa(irqfd_args_for_host), NULL);
	if (ret)
		goto err;

	/* Finish setup of the irqfd in L1 */
	irqfd->evfd = evfd;
	irqfd->resample_evfd = resample_evfd;
	irqfd->resample_efd_handle = resample_efd_handle;
	irqfd->handle = handle;
	irqfd->vm = vm;
	irqfd->gsi = args->gsi;

	INIT_WORK(&irqfd->shutdown, irqfd_shutdown);
	INIT_WORK(&irqfd->inject, irqfd_inject);

	/*
	 * Install our own custom wake-up handling so we are notified via
	 * a callback whenever someone signals the underlying eventfd
	 */
	init_waitqueue_func_entry(&irqfd->wait, irqfd_wakeup);
	init_poll_funcptr(&irqfd->pt, irqfd_ptable_queue_proc);

	events = vfs_poll(fd_file(f), &irqfd->pt);

	/* Finally add the irqfd to the VM's list */
	spin_lock_irq(&vm->fd_lock);
	list_add(&irqfd->link, &vm->irqfds);
	spin_unlock_irq(&vm->fd_lock);

	if (events & EPOLLIN)
		schedule_work(&irqfd->inject);

	kfree(irqfd_args_for_host);
	return 0;
err:
	if (resample_evfd && !IS_ERR(resample_evfd))
		virtio_kvm_put_evfd(resample_evfd);
	if (evfd && !IS_ERR(evfd))
		virtio_kvm_put_evfd(evfd);
	kfree(irqfd_args_for_host);
	kfree(irqfd);
	return ret;
}

static long
virtio_kvm_irqfd_link_ioc(struct virtio_kvm_vm *vm, unsigned int ioctl,
		     unsigned long arg)
{
	struct kvm_irqfd __user *args = u64_to_user_ptr((u64)arg);
	struct kvm_irqfd irqfd;

	if (copy_from_user(&irqfd, args, sizeof(irqfd)))
		return -EFAULT;

	if (irqfd.flags & ~(KVM_IRQFD_FLAG_DEASSIGN | KVM_IRQFD_FLAG_RESAMPLE))
		return -EINVAL;

	if (irqfd.flags & KVM_IRQFD_FLAG_DEASSIGN)
		return virtio_kvm_irqfd_link_deassign(vm, &irqfd);

	return virtio_kvm_irqfd_link_assign(vm, &irqfd);
}

static long
virtio_kvm_check_extension(u64 handle, unsigned int ioctl, unsigned long arg,
			   u64 *data)
{
	int ret;
	switch (arg) {
	/* no ioctls to proxy */
	case KVM_CAP_SYNC_MMU:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
	case KVM_CAP_NR_VCPUS:
	case KVM_CAP_NR_MEMSLOTS:
	case KVM_CAP_CLOCKSOURCE:
	case KVM_CAP_INTERNAL_ERROR_DATA:
	case KVM_CAP_X86_ROBUST_SINGLESTEP:
	case KVM_CAP_ASYNC_PF:
	case KVM_CAP_MAX_VCPUS:
	case KVM_CAP_NOP_IO_DELAY:
	case KVM_CAP_TSC_DEADLINE_TIMER:
	case KVM_CAP_SYNC_REGS:
	case KVM_CAP_READONLY_MEM:
	case KVM_CAP_IOAPIC_POLARITY_IGNORED:
	case KVM_CAP_MULTI_ADDRESS_SPACE:
	case KVM_CAP_GUEST_DEBUG_HW_BPS:
	case KVM_CAP_GUEST_DEBUG_HW_WPS:
	case KVM_CAP_DISABLE_QUIRKS:
	case KVM_CAP_DISABLE_QUIRKS2:
	case KVM_CAP_SPLIT_IRQCHIP:
	case KVM_CAP_IOEVENTFD_NO_LENGTH:
	case KVM_CAP_IOEVENTFD_ANY_LENGTH:
	case KVM_CAP_MAX_VCPU_ID:
	case KVM_CAP_X2APIC_API:
	case KVM_CAP_MSI_DEVID:
	case KVM_CAP_IMMEDIATE_EXIT:
	case KVM_CAP_X86_DISABLE_EXITS:
	case KVM_CAP_MSR_PLATFORM_INFO:
	case KVM_CAP_EXCEPTION_PAYLOAD:
	case KVM_CAP_HALT_POLL:
	case KVM_CAP_LAST_CPU:
	case KVM_CAP_STEAL_TIME:
	case KVM_CAP_X86_USER_SPACE_MSR:
	case KVM_CAP_ENFORCE_PV_FEATURE_CPUID:
	case KVM_CAP_X86_BUS_LOCK_EXIT:
	case KVM_CAP_SET_GUEST_DEBUG2:
	case KVM_CAP_SGX_ATTRIBUTE:
	case KVM_CAP_VM_COPY_ENC_CONTEXT_FROM:
	case KVM_CAP_VM_MOVE_ENC_CONTEXT_FROM:
	case KVM_CAP_PTP_KVM:
	case KVM_CAP_EXIT_HYPERCALL:
	case KVM_CAP_EXIT_ON_EMULATION_FAILURE:
	case KVM_CAP_VM_GPA_BITS:
	case KVM_CAP_PMU_CAPABILITY:
	case KVM_CAP_SYSTEM_EVENT_DATA:
	case KVM_CAP_X86_TRIPLE_FAULT_EVENT:
	case KVM_CAP_X86_NOTIFY_VMEXIT:
	case KVM_CAP_VM_DISABLE_NX_HUGE_PAGES:
	case KVM_CAP_DIRTY_LOG_RING_ACQ_REL:
	case KVM_CAP_DIRTY_LOG_RING_WITH_BITMAP:
	case KVM_CAP_PMU_EVENT_MASKED_EVENTS:
	case KVM_CAP_MEMORY_FAULT_INFO:
	case KVM_CAP_VM_TYPES:
	case KVM_CAP_X86_APIC_BUS_CYCLES_NS:
	case KVM_CAP_X86_GUEST_MODE:
	case KVM_CAP_HYPERV_ENLIGHTENED_VMCS:

	/* have ioctls to proxy */
	case KVM_CAP_IRQCHIP:
	case KVM_CAP_HLT:
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_SET_TSS_ADDR:
	case KVM_CAP_EXT_CPUID:
	case KVM_CAP_PIT:
	case KVM_CAP_MP_STATE:
	case KVM_CAP_COALESCED_MMIO:
	case KVM_CAP_SET_GUEST_DEBUG:
	case KVM_CAP_IRQ_ROUTING:
	case KVM_CAP_MCE:
	case KVM_CAP_IRQFD: /* FIXME: missing resample */
	case KVM_CAP_SET_BOOT_CPU_ID:
	case KVM_CAP_PIT2:
	case KVM_CAP_PIT_STATE2:
	case KVM_CAP_SET_IDENTITY_MAP_ADDR:
	case KVM_CAP_ADJUST_CLOCK:
	case KVM_CAP_VCPU_EVENTS:
	case KVM_CAP_INTR_SHADOW:
	case KVM_CAP_DEBUGREGS:
	case KVM_CAP_ENABLE_CAP:
	case KVM_CAP_XSAVE:
	case KVM_CAP_XSAVE2:
	case KVM_CAP_XCRS:
	case KVM_CAP_TSC_CONTROL:
	case KVM_CAP_VM_TSC_CONTROL:
	case KVM_CAP_GET_TSC_KHZ:
	case KVM_CAP_KVMCLOCK_CTRL:
	case KVM_CAP_VM_ATTRIBUTES:
	case KVM_CAP_VCPU_ATTRIBUTES:
	case KVM_CAP_SYS_ATTRIBUTES:
	case KVM_CAP_ENABLE_CAP_VM:
	case KVM_CAP_CHECK_EXTENSION_VM:
	case KVM_CAP_GET_MSR_FEATURES:
	case KVM_CAP_NESTED_STATE:
	case KVM_CAP_COALESCED_PIO:
	case KVM_CAP_MANUAL_DIRTY_LOG_PROTECT:
	case KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2:
	case KVM_CAP_PMU_EVENT_FILTER:
	case KVM_CAP_X86_MSR_FILTER:
	case KVM_CAP_DIRTY_LOG_RING:
	case KVM_CAP_BINARY_STATS_FD:
	case KVM_CAP_USER_MEMORY2:
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_VAPIC:
	case KVM_CAP_SREGS2:
	case KVM_CAP_X86_SMM:
	/* undocumented -- supported */
	case KVM_CAP_IRQ_INJECT_STATUS:
	case KVM_CAP_ASSIGN_DEV_IRQ:
	case KVM_CAP_ASYNC_PF_INT:
	case KVM_CAP_SMALLER_MAXPHYADDR:
	case KVM_CAP_SIGNAL_MSI:
		break;

	/* undocumented -- unsupported */
	case KVM_CAP_PCI_SEGMENT:
	/* deprecated */
	case KVM_CAP_MMU_SHADOW_CACHE_CONTROL: /* KVM_GET_NR_MMU_PAGES */
	case KVM_CAP_IOMMU:
	case KVM_CAP_PV_MMU:
	case KVM_CAP_PCI_2_3:
	/* unsupported */
	case KVM_CAP_REINJECT_CONTROL:
	case KVM_CAP_XEN_HVM:
	case KVM_CAP_ONE_REG:
	case KVM_CAP_USER_NMI:
	case KVM_CAP_IRQFD_RESAMPLE:
	case KVM_CAP_DEVICE_CTRL: /* FIXME: move this to supported when
				     CREATE_DEVICE returns failure for all
				     devices. */
	case KVM_CAP_EXT_EMUL_CPUID:
	case KVM_CAP_MEMORY_ATTRIBUTES:
	case KVM_CAP_GUEST_MEMFD:
	case KVM_CAP_PRE_FAULT_MEMORY:

	/* unsupported -- hyperv */
	case KVM_CAP_HYPERV:
	case KVM_CAP_HYPERV_VAPIC:
	case KVM_CAP_HYPERV_SPIN:
	case KVM_CAP_HYPERV_TIME:
	case KVM_CAP_HYPERV_SYNIC:
	case KVM_CAP_HYPERV_SYNIC2:
	case KVM_CAP_HYPERV_VP_INDEX:
	case KVM_CAP_HYPERV_EVENTFD:
	case KVM_CAP_HYPERV_TLBFLUSH:
	case KVM_CAP_HYPERV_SEND_IPI:
	case KVM_CAP_HYPERV_CPUID:
	case KVM_CAP_HYPERV_DIRECT_TLBFLUSH:
	case KVM_CAP_SYS_HYPERV_CPUID:
	case KVM_CAP_HYPERV_ENFORCE_CPUID:

	/* unsupported -- s390 */
	case KVM_CAP_S390_PSW:
	case KVM_CAP_S390_GMAP:
	case KVM_CAP_S390_UCONTROL:
	case KVM_CAP_S390_COW:
	case KVM_CAP_S390_CSS_SUPPORT:
	case KVM_CAP_S390_IRQCHIP:
	case KVM_CAP_S390_USER_SIGP:
	case KVM_CAP_S390_VECTOR_REGISTERS:
	case KVM_CAP_S390_MEM_OP:
	case KVM_CAP_S390_USER_STSI:
	case KVM_CAP_S390_SKEYS:
	case KVM_CAP_S390_INJECT_IRQ:
	case KVM_CAP_S390_IRQ_STATE:
	case KVM_CAP_S390_RI:
	case KVM_CAP_S390_USER_INSTR0:
	case KVM_CAP_S390_GS:
	case KVM_CAP_S390_AIS:
	case KVM_CAP_S390_CMMA_MIGRATION:
	case KVM_CAP_S390_AIS_MIGRATION:
	case KVM_CAP_S390_BPB:
	case KVM_CAP_S390_HPAGE_1M:
	case KVM_CAP_S390_VCPU_RESETS:
	case KVM_CAP_S390_PROTECTED:
	case KVM_CAP_S390_DIAG318:
	case KVM_CAP_S390_MEM_OP_EXTENSION:
	case KVM_CAP_S390_PROTECTED_DUMP:
	case KVM_CAP_S390_ZPCI_OP:
	case KVM_CAP_S390_CPU_TOPOLOGY:
	case KVM_CAP_S390_PROTECTED_ASYNC_DISABLE:

	/* unsupported -- ppc */
	case KVM_CAP_SPAPR_TCE:
	case KVM_CAP_SW_TLB:
	case KVM_CAP_IRQ_MPIC:
	case KVM_CAP_IRQ_XICS:
	case KVM_CAP_SPAPR_MULTITCE:
	case KVM_CAP_SPAPR_TCE_64:
	case KVM_CAP_SPAPR_RESIZE_HPT:
	case KVM_CAP_SPAPR_TCE_VFIO:
	case KVM_CAP_PPC_SEGSTATE:
	case KVM_CAP_PPC_PAIRED_SINGLES:
	case KVM_CAP_PPC_OSI:
	case KVM_CAP_PPC_UNSET_IRQ:
	case KVM_CAP_PPC_GET_PVINFO:
	case KVM_CAP_PPC_IRQ_LEVEL:
	case KVM_CAP_PPC_BOOKE_SREGS:
	case KVM_CAP_PPC_RMA:
	case KVM_CAP_PPC_HIOR:
	case KVM_CAP_PPC_PAPR:
	case KVM_CAP_PPC_GET_SMMU_INFO:
	case KVM_CAP_PPC_ALLOC_HTAB:
	case KVM_CAP_PPC_BOOKE_WATCHDOG:
	case KVM_CAP_PPC_HTAB_FD:
	case KVM_CAP_PPC_EPR:
	case KVM_CAP_PPC_RTAS:
	case KVM_CAP_PPC_FIXUP_HCALL:
	case KVM_CAP_PPC_ENABLE_HCALL:
	case KVM_CAP_PPC_HWRNG:
	case KVM_CAP_PPC_HTM:
	case KVM_CAP_PPC_MMU_RADIX:
	case KVM_CAP_PPC_MMU_HASH_V3:
	case KVM_CAP_PPC_FWNMI:
	case KVM_CAP_PPC_SMT_POSSIBLE:
	case KVM_CAP_PPC_GET_CPU_CHAR:
	case KVM_CAP_PPC_NESTED_HV:
	case KVM_CAP_PPC_IRQ_XIVE:
	case KVM_CAP_PPC_GUEST_DEBUG_SSTEP:
	case KVM_CAP_PPC_SECURE_GUEST:
	case KVM_CAP_PPC_DAWR1:
	case KVM_CAP_PPC_RPT_INVALIDATE:
	case KVM_CAP_PPC_AIL_MODE_3:

	/* unsupported -- arm */
	case KVM_CAP_ARM_PSCI:
	case KVM_CAP_ARM_SET_DEVICE_ADDR:
	case KVM_CAP_ARM_EL1_32BIT:
	case KVM_CAP_ARM_PSCI_0_2:
	case KVM_CAP_ARM_PMU_V3:
	case KVM_CAP_ARM_USER_IRQ:
	case KVM_CAP_ARM_INJECT_SERROR_ESR:
	case KVM_CAP_ARM_VM_IPA_SIZE:
	case KVM_CAP_ARM_SVE:
	case KVM_CAP_ARM_PTRAUTH_ADDRESS:
	case KVM_CAP_ARM_PTRAUTH_GENERIC:
	case KVM_CAP_ARM_IRQ_LINE_LAYOUT_2:
	case KVM_CAP_ARM_NISV_TO_USER:
	case KVM_CAP_ARM_INJECT_EXT_DABT:
	case KVM_CAP_ARM_MTE:
	case KVM_CAP_ARM_SYSTEM_SUSPEND:
	case KVM_CAP_ARM_EAGER_SPLIT_CHUNK_SIZE:
	case KVM_CAP_ARM_SUPPORTED_BLOCK_SIZES:
	case KVM_CAP_ARM_SUPPORTED_REG_MASK_RANGES:
	case KVM_CAP_ARM_WRITABLE_IMP_ID_REGS:
	case KVM_CAP_COUNTER_OFFSET:

	/* unsupported -- mips */
	case KVM_CAP_MIPS_FPU:
	case KVM_CAP_MIPS_MSA:
	case KVM_CAP_MIPS_VZ:
	case KVM_CAP_MIPS_TE:
	case KVM_CAP_MIPS_64BIT:

	default:
		pr_err("virtio-kvm: unimplemented extension %lu\n", arg);
		*data = 0;  /* unsupported */
		return 0;
	}

	ret = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl, arg,
				       data);
	if (ret)
		return ret;

	if (arg == KVM_CAP_MAX_VCPUS || arg == KVM_CAP_NR_VCPUS) {
		if (*data > MAX_VCPUS)
			*data = MAX_VCPUS;
	} else if (arg == KVM_CAP_MAX_VCPU_ID) {
		if (*data > MAX_VCPUS - 1)
			*data = MAX_VCPUS - 1;
	}

	return 0;
}

static void
deactivate_ioeventfd(struct virtio_kvm_ioeventfd_link *ioeventfd)
{
	struct virtio_kvm_ioeventfd *cmd;
	int ret;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (cmd) {
		cmd->kvm = ioeventfd->orig;
		cmd->kvm.flags |= KVM_IOEVENTFD_FLAG_DEASSIGN;
		cmd->kvm.fd = -1;
		cmd->fd_handle = ioeventfd->evfd->handle;
		ret = virtio_kvm_send_command(ioeventfd->vm->handle, VIRTIO_VM_IOCTL,
					      KVM_IOEVENTFD, __pa(cmd), NULL);
		WARN_ONCE(ret, "KVM_IOEVENTFD_FLAG_DEASSIGN failed %d\n", ret);
		kfree(cmd);
	}

	virtio_kvm_put_evfd(ioeventfd->evfd);
}

static int
virtio_kvm_ioeventfd_assign(struct virtio_kvm_vm *vm,
			    struct virtio_kvm_ioeventfd *ioeventfd)
{
	struct virtio_kvm_ioeventfd_link *link = NULL;
	struct virtio_kvm_eventfd *evfd = NULL;
	struct eventfd_ctx *ctx = NULL;
	int ret;

	CLASS(fd, f)(ioeventfd->kvm.fd);
	if (fd_empty(f))
		return -EBADF;
	ctx = eventfd_ctx_fileget(fd_file(f));
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	evfd = virtio_kvm_get_evfd(vm->partition_id, ctx);
	if (IS_ERR(evfd)) {
		eventfd_ctx_put(ctx);
		return PTR_ERR(evfd);
	}

	ret = -ENOMEM;
	link = kmalloc(sizeof(*link), GFP_KERNEL);
	if (!link)
		goto out_put_evfd;

	INIT_LIST_HEAD(&link->link);
	link->vm = vm;
	link->evfd = evfd;
	link->l1_handle = ioeventfd->kvm.fd;
	link->orig = ioeventfd->kvm;

	ioeventfd->kvm.fd = -1;
	ioeventfd->fd_handle = evfd->handle;
	ret = virtio_kvm_send_command(vm->handle, VIRTIO_VM_IOCTL, KVM_IOEVENTFD,
				      __pa(ioeventfd), NULL);
	if (ret)
		goto out_put_link;

	spin_lock_irq(&vm->fd_lock);
	list_add(&link->link, &vm->ioeventfds);
	spin_unlock_irq(&vm->fd_lock);

	return 0;

out_put_link:
	kfree(link);
out_put_evfd:
	virtio_kvm_put_evfd(evfd);
	return ret;
}

static int
virtio_kvm_ioeventfd_deassign(struct virtio_kvm_vm *vm,
			      struct virtio_kvm_ioeventfd *ioeventfd)
{
	struct virtio_kvm_ioeventfd_link *link = NULL, *tmp;
	struct eventfd_ctx *eventfd;
	int ret;

	eventfd = eventfd_ctx_fdget(ioeventfd->kvm.fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	spin_lock_irq(&vm->fd_lock);
	list_for_each_entry(tmp, &vm->ioeventfds, link) {
		bool pio_match = (tmp->orig.flags & KVM_IOEVENTFD_FLAG_PIO) ==
				 (ioeventfd->kvm.flags & KVM_IOEVENTFD_FLAG_PIO);
		bool data_match = !(ioeventfd->kvm.flags & KVM_IOEVENTFD_FLAG_DATAMATCH) ||
				  tmp->orig.datamatch == ioeventfd->kvm.datamatch;

		if (tmp->evfd->ctx == eventfd &&
		    tmp->orig.addr == ioeventfd->kvm.addr &&
		    tmp->orig.len == ioeventfd->kvm.len &&
		    pio_match && data_match) {
			link = tmp;
			list_del(&link->link);
			break;
		}
	}
	spin_unlock_irq(&vm->fd_lock);

	eventfd_ctx_put(eventfd);

	if (!link)
		return -ENOENT;

	ioeventfd->kvm.fd = -1;
	ioeventfd->fd_handle = link->evfd->handle;
	ret = virtio_kvm_send_command(vm->handle, VIRTIO_VM_IOCTL, KVM_IOEVENTFD,
				      __pa(ioeventfd), NULL);

	virtio_kvm_put_evfd(link->evfd);
	kfree(link);

	return ret;
}

static long
virtio_kvm_ioeventfd_ioc(struct virtio_kvm_vm *vm, unsigned int ioctl,
			 unsigned long arg)
{
	struct kvm_ioeventfd __user *args = u64_to_user_ptr((u64) arg);
	struct virtio_kvm_ioeventfd *ioeventfd;
	int ret;

	ioeventfd = kmalloc(sizeof(*ioeventfd), GFP_KERNEL);
	if (!ioeventfd)
		return -ENOMEM;

	if (copy_from_user(&ioeventfd->kvm, args, sizeof(struct kvm_ioeventfd))) {
		kfree(ioeventfd);
		return -EFAULT;
	}

	if (ioeventfd->kvm.flags & KVM_IOEVENTFD_FLAG_DEASSIGN)
		ret = virtio_kvm_ioeventfd_deassign(vm, ioeventfd);
	else
		ret = virtio_kvm_ioeventfd_assign(vm, ioeventfd);

	kfree(ioeventfd);

	return ret;
}

static long
virtio_kvm_vm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct virtio_kvm_vm *vm = (struct virtio_kvm_vm *)filp->private_data;
	struct virtio_kvm_vcpu *vcpu;
	u64 handle = vm->handle;
	struct file *file;
	u64 data = 0;
	int err;
	int fd;

#define CASE_KVM_IOCTL_BASIC(ioc_name) \
	case ioc_name: \
		err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, \
					      ioctl, arg, &data); \
		break

#define CASE_KVM_IOCTL_UCOPY(ioc_name, arg_t) \
	case ioc_name: \
		err = virtio_kvm_send_command_ucopy(handle, VIRTIO_VM_IOCTL, \
						    ioctl, arg, sizeof(arg_t), \
						    &data); \
		break

	switch (ioctl) {
	case KVM_SET_USER_MEMORY_REGION:
	case KVM_SET_USER_MEMORY_REGION2:
		return virtio_kvm_set_user_memory_region(vm, ioctl, arg);
	case KVM_GET_DIRTY_LOG:
		return virtio_kvm_get_dirty_log(vm, ioctl, arg);
	case KVM_CLEAR_DIRTY_LOG:
		return virtio_kvm_clear_dirty_log(vm, ioctl, arg);
	case KVM_SET_GSI_ROUTING:
		return virtio_kvm_set_gsi_routing(handle, ioctl, arg);
#ifdef KVM_X86_SET_MSR_FILTER
	case KVM_X86_SET_MSR_FILTER:
		return virtio_kvm_set_msr_filter(handle, ioctl, arg);
#endif
	case KVM_IRQFD:
		return virtio_kvm_irqfd_link_ioc(vm, ioctl, arg);
	case KVM_IOEVENTFD:
		return virtio_kvm_ioeventfd_ioc(vm, ioctl, arg);
	case KVM_ENABLE_CAP:
		err = virtio_kvm_handle_enable_cap(handle, ioctl, arg, &data);
		break;
	case KVM_SET_PMU_EVENT_FILTER:
		return virtio_kvm_set_pmu_event_filter(handle, ioctl, arg);
	case KVM_CREATE_VCPU:
		if (arg >= MAX_VCPUS || !vm->shm)
			return -EINVAL;
		vcpu = kmalloc(sizeof(*vcpu), GFP_KERNEL);
		if (!vcpu)
			return -ENOMEM;
		vcpu->vcpu_id = arg;
		vcpu->poll_ns = 0;
		err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL,
					      ioctl, arg, &data);
		if (err)
			kfree(vcpu);
		break;
	CASE_KVM_IOCTL_UCOPY(KVM_CREATE_DEVICE,	struct kvm_create_device);
	case KVM_GET_STATS_FD:
		err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL,
					      ioctl, arg, &data);
		break;
	case KVM_SET_DEVICE_ATTR:
	case KVM_GET_DEVICE_ATTR:
	case KVM_HAS_DEVICE_ATTR:
		err = virtio_kvm_handle_device_attr(handle, ioctl, arg, &data);
		break;
	case KVM_CHECK_EXTENSION:
		err = virtio_kvm_check_extension(handle, ioctl, arg, &data);
		break;
	CASE_KVM_IOCTL_BASIC(KVM_CREATE_PIT);
	CASE_KVM_IOCTL_BASIC(KVM_CREATE_IRQCHIP);
	CASE_KVM_IOCTL_BASIC(KVM_SET_NR_MMU_PAGES);
	CASE_KVM_IOCTL_BASIC(KVM_SET_TSS_ADDR);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_PIT,	struct kvm_pit_state);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_PIT,	struct kvm_pit_state);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_PIT2,	struct kvm_pit_state2);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_PIT2,	struct kvm_pit_state2);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_IRQCHIP,	struct kvm_irqchip);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_IRQCHIP,	struct kvm_irqchip);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_IDENTITY_MAP_ADDR, u64);
	CASE_KVM_IOCTL_UCOPY(KVM_CREATE_PIT2,	struct kvm_pit_config);
	CASE_KVM_IOCTL_UCOPY(KVM_IRQ_LINE,	struct kvm_irq_level);
	CASE_KVM_IOCTL_UCOPY(KVM_IRQ_LINE_STATUS,	struct kvm_irq_level);
	CASE_KVM_IOCTL_UCOPY(KVM_REGISTER_COALESCED_MMIO,	struct kvm_coalesced_mmio_zone);
	CASE_KVM_IOCTL_UCOPY(KVM_UNREGISTER_COALESCED_MMIO,	struct kvm_coalesced_mmio_zone);
	CASE_KVM_IOCTL_UCOPY(KVM_SIGNAL_MSI,	struct kvm_msi);
	CASE_KVM_IOCTL_UCOPY(KVM_SET_CLOCK,	struct kvm_clock_data);
	CASE_KVM_IOCTL_UCOPY(KVM_GET_CLOCK,	struct kvm_clock_data);
	CASE_KVM_IOCTL_BASIC(KVM_SET_TSC_KHZ);
	CASE_KVM_IOCTL_BASIC(KVM_GET_TSC_KHZ);
	CASE_KVM_IOCTL_BASIC(KVM_RESET_DIRTY_RINGS);
	CASE_KVM_IOCTL_BASIC(KVM_SET_BOOT_CPU_ID);
	default:
		pr_err("virtio_kvm_vm_ioctl: cannot translate unknown ioctl "
		       "0x%x\n", ioctl);
#if defined(CONFIG_X86) || defined(CONFIG_S390)
		return -ENOTTY;
#else
		return -EINVAL;
#endif
	}

	if (err)
		return err;

	switch (ioctl) {
	case KVM_CREATE_VCPU:
		/*
		 * Grab a ref on the vm file so that vcpu->vm is always valid.
		 */
		if (WARN_ON_ONCE(filp != vm->file)) {
			virtio_kvm_send_command_async(data, VIRTIO_VM_CLOSE, 0, 0, NULL);
			kfree(vcpu);
			return -EINVAL;
		}
		get_file(filp);

		fd = get_unused_fd_flags(O_CLOEXEC);
		if (fd < 0) {
			virtio_kvm_send_command_async(data, VIRTIO_VM_CLOSE, 0, 0, NULL);
			fput(filp);
			kfree(vcpu);
			return fd;
		}
		vcpu->vm = vm;
		vcpu->handle = data;
		mutex_init(&vcpu->mutex);
		init_waitqueue_head(&vcpu->wait);
		INIT_LIST_HEAD(&vcpu->active_link);
		vcpu->completed = true;
		file = anon_inode_getfile("kvm-vcpu", &kvm_vcpu_fops,
					  (void *)vcpu, O_RDWR);
		if (IS_ERR(file)) {
			put_unused_fd(fd);
			virtio_kvm_send_command_async(data, VIRTIO_VM_CLOSE, 0, 0, NULL);
			fput(filp);
			kfree(vcpu);
			return PTR_ERR(file);
		}
		fd_install(fd, file);
		return fd;
	case KVM_GET_STATS_FD:
		fd = get_unused_fd_flags(O_CLOEXEC);
		if (fd < 0) {
			virtio_kvm_send_command_async(data, VIRTIO_VM_CLOSE, 0, 0, NULL);
			return fd;
		}
		file = anon_inode_getfile_fmode("kvm-vm-stats",
						&kvm_stats_fops,
						(void *)data, O_RDONLY,
						FMODE_PREAD);
		if (IS_ERR(file)) {
			put_unused_fd(fd);
			virtio_kvm_send_command_async(data, VIRTIO_VM_CLOSE, 0, 0, NULL);
			return PTR_ERR(file);
		}
		fd_install(fd, file);
		return fd;
	case KVM_CREATE_DEVICE:
		fd = get_unused_fd_flags(O_CLOEXEC);
		if (fd < 0) {
			virtio_kvm_send_command_async(data, VIRTIO_VM_CLOSE, 0, 0, NULL);
			return fd;
		}
		file = anon_inode_getfile("kvm-generic-device",
					  &kvm_device_fops,
					  (void *)data, O_RDWR | O_CLOEXEC);
		if (IS_ERR(file)) {
			put_unused_fd(fd);
			virtio_kvm_send_command_async(data, VIRTIO_VM_CLOSE, 0, 0, NULL);
			return PTR_ERR(file);
		}
		fd_install(fd, file);
		return fd;
	}
	return data;

#undef CASE_KVM_IOCTL_UCOPY
#undef CASE_KVM_IOCTL_BASIC
}

static int
virtio_kvm_vm_release(struct inode *inode, struct file *filp)
{
	struct virtio_kvm_vm *vm = (struct virtio_kvm_vm *) filp->private_data;
	struct virtio_kvm_mem_region *reg, *tmp_reg;
	struct virtio_kvm_ioeventfd_link *ioeventfd, *tmp_ioeventfd;
	struct virtio_kvm_irqfd_link *irqfd, *tmp_irqfd;
	u64 handle = vm->handle;
	int ret;

	/* Free all memory regions. No need to grab the lock. */
	list_for_each_entry_safe(reg, tmp_reg, &vm->memory_regions, link) {
		list_del(&reg->link);
		kfree(reg);
	}

	list_for_each_entry_safe(ioeventfd, tmp_ioeventfd, &vm->ioeventfds, link) {
		deactivate_ioeventfd(ioeventfd);
		list_del(&ioeventfd->link);
		kfree(ioeventfd);
	}

	/* Free all irqfds. */
	spin_lock_irq(&vm->fd_lock);
	list_for_each_entry_safe(irqfd, tmp_irqfd, &vm->irqfds, link) {
		deactivate_irqfd(irqfd);
	}
	spin_unlock_irq(&vm->fd_lock);
	flush_workqueue(eventfd_cleanup_wq);

	if (vm->run_notify)
		virtio_kvm_put_evfd(vm->run_notify);

	if (vm->shm) {
		memunmap(vm->shm);
		send_dev_munmap(handle, vm->shm_phys_offset, vm->shm_size);
		virtio_vm_put_unused_phys_offset(vm->shm_phys_offset, vm->shm_size);
	}

	ret = virtio_kvm_send_command_async(handle, VIRTIO_VM_CLOSE, 0, 0, NULL);
	WARN_ON_ONCE(ret);

	virtkvm_partition_put(vm->part);
	kfree(vm);

	return ret;
}

static const struct file_operations kvm_vm_fops = {
	.release = virtio_kvm_vm_release,
	.unlocked_ioctl = virtio_kvm_vm_ioctl,
};

static int virtio_kvm_vm_setup_shm(struct virtio_kvm_vm *vm)
{
	struct virtio_kvm_mmap_device {
		__le64 size;
		__le64 device_offset;
		__le64 phys_offset;
	} __packed;
	struct virtio_kvm_mmap_device *mmap_device;
	int err;

	vm->shm_size = sizeof(struct vcpu_shared_memory);
	vm->shm_phys_offset = virtio_vm_get_unused_phys_offset(vm->shm_size, PAGE_SHIFT);
	if (vm->shm_phys_offset == INVALID_PHYS_OFFSET)
		return -ENOMEM;

	mmap_device = kzalloc(sizeof(*mmap_device), GFP_KERNEL);
	if (!mmap_device) {
		virtio_vm_put_unused_phys_offset(vm->shm_phys_offset, vm->shm_size);
		return -ENOMEM;
	}

	mmap_device->size = cpu_to_le64(vm->shm_size);
	mmap_device->device_offset = cpu_to_le64(0);
	mmap_device->phys_offset = cpu_to_le64(vm->shm_phys_offset);

	err = virtio_kvm_send_command(vm->handle, VIRTIO_VM_DEVICE_MMAP, 0,
				      __pa(mmap_device), NULL);
	kfree(mmap_device);

	if (err) {
		virtio_vm_put_unused_phys_offset(vm->shm_phys_offset, vm->shm_size);
		return err;
	}

	vm->shm = memremap(vi_device->phys_start + vm->shm_phys_offset,
			   vm->shm_size, MEMREMAP_WB);
	if (!vm->shm) {
		send_dev_munmap(vm->handle, vm->shm_phys_offset, vm->shm_size);
		virtio_vm_put_unused_phys_offset(vm->shm_phys_offset, vm->shm_size);
		return -ENOMEM;
	}
	memset(vm->shm, 0, vm->shm_size);

	return 0;
}

static void virtio_kvm_run_notify(struct virtio_kvm_eventfd *evfd)
{
	atomic_set(&vi_device->vcpu_scan_pending, 1);
	wake_up(&vi_device->vcpu_poll_wait);
}

/* Asks Tachyon to signal an eventfd whenever a vCPU of @vm completes KVM_RUN. */
static int virtio_kvm_vm_setup_run_notify(struct virtio_kvm_vm *vm)
{
	struct virtio_kvm_eventfd *evfd;
	int err;

	evfd = virtio_kvm_get_notify_evfd(vm->partition_id, virtio_kvm_run_notify, vm);
	if (IS_ERR(evfd))
		return PTR_ERR(evfd);

	err = virtio_kvm_send_command(vm->handle, VIRTIO_VM_SET_RUN_NOTIFY,
				      evfd->handle, 0, NULL);
	if (err) {
		virtio_kvm_put_evfd(evfd);
		return err;
	}
	vm->run_notify = evfd;
	return 0;
}

static void
init_vm(struct virtio_kvm_vm *vm, u64 handle, struct file *filp,
	struct virtio_kvm_partition *part, u64 partition_id)
{
	vm->handle = handle;
	vm->partition_id = partition_id;
	vm->part = part;
	virtkvm_partition_get(part);
	INIT_LIST_HEAD(&vm->memory_regions);
	mutex_init(&vm->region_lock);
	INIT_LIST_HEAD(&vm->irqfds);
	INIT_LIST_HEAD(&vm->ioeventfds);
	spin_lock_init(&vm->fd_lock);
	vm->file = filp;
	vm->shm = NULL;
	vm->run_notify = NULL;
}

static long
virtio_kvm_dev_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct virtio_kvm_dev_ctx *ctx = filp->private_data;
	u64 handle = ctx ? ctx->handle : 0;
	u64 partition_id = ctx ? ctx->partition_id : 0;
	struct virtio_kvm_partition *part = ctx ? ctx->part : NULL;
	struct virtio_kvm_vm *vm;
	struct file *file;
	u64 data;
	int err;
	int fd;

#define CASE_KVM_IOCTL_BASIC(ioc_name) \
	case ioc_name: \
		err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, \
					      ioctl, arg, &data); \
		break

#define CASE_KVM_IOCTL_UCOPY(ioc_name, arg_t) \
	case ioc_name: \
		err = virtio_kvm_send_command_ucopy(handle, VIRTIO_VM_IOCTL, \
						    ioctl, arg, sizeof(arg_t), \
						    &data); \
		break

	switch (ioctl) {
	case VIRTIO_VM_IOC_CREATE_MEMORY_FILE:
		err = virtio_kvm_create_memory_anonfile(arg, partition_id);
		break;
	CASE_KVM_IOCTL_BASIC(KVM_GET_VCPU_MMAP_SIZE);
	CASE_KVM_IOCTL_BASIC(KVM_GET_API_VERSION);
	case KVM_CHECK_EXTENSION:
		err = virtio_kvm_check_extension(handle, ioctl, arg, &data);
		break;
	case KVM_SET_DEVICE_ATTR:
	case KVM_GET_DEVICE_ATTR:
	case KVM_HAS_DEVICE_ATTR:
		err = virtio_kvm_handle_device_attr(handle, ioctl, arg, &data);
		break;
	case KVM_CREATE_VM:
		vm = kzalloc(sizeof(*vm), GFP_KERNEL);
		if (!vm)
			return -ENOMEM;
		err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL,
					      ioctl, arg, &data);
		if (err) {
			kfree(vm);
			break;
		}
		break;
	case KVM_GET_SUPPORTED_CPUID:
		err = virtio_kvm_handle_cpuid(handle, ioctl, arg, &data);
		break;
#ifdef KVM_X86_GET_MCE_CAP_SUPPORTED
	CASE_KVM_IOCTL_UCOPY(KVM_X86_GET_MCE_CAP_SUPPORTED, u64);
#endif
	case KVM_GET_MSR_FEATURE_INDEX_LIST:
	case KVM_GET_MSR_INDEX_LIST:
		err = virtio_kvm_handle_msr_list(handle, ioctl, arg, &data);
		break;
	case KVM_GET_MSRS:
		err = virtio_kvm_handle_msrs(handle, ioctl, arg, &data);
		break;

	default:
		pr_err("virtio_kvm_dev_ioctl: cannot translate unknown ioctl: "
		       "0x%x\n", ioctl);
		err = -EINVAL;
	}

	if (err)
		return err;

	switch (ioctl) {
	case KVM_CREATE_VM:
		fd = get_unused_fd_flags(O_CLOEXEC);
		if (fd < 0) {
			virtio_kvm_send_command_async(data, VIRTIO_VM_CLOSE, 0, 0, NULL);
			kfree(vm);
			return fd;
		}
		file = anon_inode_getfile("kvm-vm", &kvm_vm_fops,
					  (void *) vm, O_RDWR);
		if (IS_ERR(file)) {
			put_unused_fd(fd);
			virtio_kvm_send_command_async(data, VIRTIO_VM_CLOSE, 0, 0, NULL);
			kfree(vm);
			return PTR_ERR(file);
		}
		init_vm(vm, data, file, part, partition_id);
		err = virtio_kvm_vm_setup_shm(vm);
		if (!err && !READ_ONCE(vcpu_poll))
			err = virtio_kvm_vm_setup_run_notify(vm);
		if (err) {
			fput(file);
			put_unused_fd(fd);
			return err;
		}
		fd_install(fd, file);

		return fd;
	}

	return data;

#undef CASE_KVM_IOCTL_UCOPY
#undef CASE_KVM_IOCTL_BASIC
}

/*
 * The current vcpu_polling_thread implementation is a proof of concept
 * primarily for performance testing.
 *
 * TODO: The thread iterates over every single vCPU across all VMs in the
 * system. The design should be improved to maintain a list of only actively
 * vCPUs.
 */
/* Completes every active vCPU whose KVM_RUN finished. Returns true if none are active. */
static bool vcpu_poll_scan(struct virtkvm_info *vi)
{
	struct virtio_kvm_vcpu *vcpu, *tmp;
	struct per_vcpu_state *state;
	bool empty;

	spin_lock(&vi->vcpu_lock);
	empty = list_empty(&vi->active_vcpus);
	list_for_each_entry_safe(vcpu, tmp, &vi->active_vcpus, active_link) {
		state = &vcpu->vm->shm->vcpus[vcpu->vcpu_id];

		if (!READ_ONCE(vcpu->completed)) {
			/* Pair with virt_store_release() in host */
			u32 s = virt_load_acquire(&state->state);

			if ((s & STATE_MASK) != STATE_COMPLETED)
				continue;

			list_del_init(&vcpu->active_link);
			/* Pairs with smp_load_acquire() in virtio_kvm_vcpu_run() */
			smp_store_release(&vcpu->completed, true);
			wake_up(&vcpu->wait);
		} else {
			/* Should not be in active list if completed */
			list_del_init(&vcpu->active_link);
		}
	}
	spin_unlock(&vi->vcpu_lock);

	return empty;
}

static int vcpu_polling_thread(void *data)
{
	struct virtkvm_info *vi = data;
	ktime_t idle_since = 0;

	while (!kthread_should_stop()) {
		bool empty;

		if (!READ_ONCE(vcpu_poll)) {
			wait_event_interruptible(vi->vcpu_poll_wait,
				atomic_xchg(&vi->vcpu_scan_pending, 0) ||
				kthread_should_stop());
			vcpu_poll_scan(vi);
			continue;
		}

		empty = vcpu_poll_scan(vi);
		if (!empty) {
			idle_since = 0;
		} else if (idle_since == 0) {
			idle_since = ktime_get();
		} else if (ktime_us_delta(ktime_get(), idle_since) >= poll_idle_timeout_us) {
			/* Suspend polling */
			trace_virtio_vm_poll_stop(true);
			wait_event_interruptible(vi->vcpu_poll_wait,
				!list_empty(&vi->active_vcpus) || kthread_should_stop());
			trace_virtio_vm_poll_start(true);
			idle_since = 0;
			continue;
		}

		cond_resched();
		cpu_relax();
	}
	return 0;
}

static const struct file_operations virtio_kvm_dev_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = virtio_kvm_dev_ioctl,
	.open = virtio_kvm_open,
	.release = virtio_kvm_release
};

int virtkvm_partition_init_kvm(struct virtio_kvm_partition *part)
{
	snprintf(part->name, sizeof(part->name), "tachyon-%llu-kvm", part->partition_id);
	snprintf(part->nodename, sizeof(part->nodename), "tachyon-%llu/kvm", part->partition_id);
	part->misc_dev.minor = MISC_DYNAMIC_MINOR;
	part->misc_dev.name = part->name;
	part->misc_dev.nodename = part->nodename;
	part->misc_dev.mode = 0666;
	part->misc_dev.fops = &virtio_kvm_dev_ops;

	return misc_register(&part->misc_dev);
}

void virtkvm_partition_cleanup_kvm(struct virtio_kvm_partition *part)
{
	misc_deregister(&part->misc_dev);
}

int virtkvm_kvm_init(struct virtkvm_info *vi) {
	int err;

	spin_lock_init(&vi->vcpu_lock);
	INIT_LIST_HEAD(&vi->active_vcpus);
	init_waitqueue_head(&vi->vcpu_poll_wait);
	init_waitqueue_head(&vi->vq_wait);
	vi->vq_full = false;
	vi->polling_thread = kthread_run(vcpu_polling_thread, vi, "virtio-kvm-poll");
	if (IS_ERR(vi->polling_thread)) {
		err = PTR_ERR(vi->polling_thread);
		return err;
	}

	return 0;
}

void virtkvm_kvm_cleanup(struct virtkvm_info *vi) {
	if (vi->polling_thread)
		kthread_stop(vi->polling_thread);
}
