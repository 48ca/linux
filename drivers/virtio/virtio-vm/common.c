// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/virtio.h>
#include <linux/miscdevice.h>

#include "common.h"
#include "vfio.h"
#include "kvm.h"
#include "inode.h"

#include "../virtio_pci_common.h"

#define CREATE_TRACE_POINTS
#include "trace.h"

#undef pr_fmt
#define pr_fmt(fmt) "virtio-vm: " fmt

struct virtio_kvm_file_io {
	u64 buffer;
	ssize_t size;
	loff_t offset;
};

struct virtkvm_info *vi_device;

struct workqueue_struct *eventfd_cleanup_wq;

u64 virtio_vm_get_unused_phys_offset(u64 size, int alignment_order)
{
	unsigned long align = 1UL << alignment_order;
	unsigned long offset = INVALID_PHYS_OFFSET;
	unsigned long min = PAGE_SIZE; /* guard page */
	unsigned long max;
	int err;

	if (!vi_device)
		return offset;

	MA_STATE(mas, &vi_device->allocinfo.mt, 0, 0);
	max = vi_device->allocinfo.range_size;

	mas_lock(&mas);
retry:
	if (alignment_order >= BAR_GUEST_MEM_ALIGNMENT_ORDER) {
		/* Search from the right */
		err = mas_empty_area_rev(&mas, min, max, size);
		while (!err) {
			unsigned long cand = round_down(mas.last + 1 - size, align);

			if (cand >= mas.index) {
				mas.index = cand;
				mas.last = cand + size - 1;
				goto found;
			}

			/* Try again, limiting the max to the next possible aligned end */
			if (cand < min) {
				err = -ENOMEM;
				break;
			}
			mas_reset(&mas);
			err = mas_empty_area_rev(&mas, min, cand + size - 1, size);
		}
	} else {
		/* Search from the left */
		err = mas_empty_area(&mas, min, max, size);
		while (!err) {
			unsigned long cand = round_up(mas.index, align);

			if (cand + size - 1 <= mas.last) {
				mas.index = cand;
				mas.last = cand + size - 1;
				goto found;
			}

			/* Try again, starting from the next possible aligned start */
			if (cand > max - size) {
				err = -ENOMEM;
				break;
			}
			mas_reset(&mas);
			err = mas_empty_area(&mas, cand, max, size);
		}
	}

	if (err) {
		mas_unlock(&mas);
		mas_destroy(&mas);
		return INVALID_PHYS_OFFSET;
	}

found:
	mas_store(&mas, (void *)1);
	if (mas_nomem(&mas, GFP_KERNEL))
		goto retry;

	if (mas_is_err(&mas)) {
		mas_unlock(&mas);
		mas_destroy(&mas);
		return INVALID_PHYS_OFFSET;
	}

	offset = mas.index;
	mas_unlock(&mas);
	mas_destroy(&mas);

	return offset;
}

void virtio_vm_put_unused_phys_offset(u64 offset, u64 size)
{
	unsigned long last = offset + size - 1;
	int err;

	err = mtree_store_range(&vi_device->allocinfo.mt, offset, last, NULL, GFP_KERNEL);
	WARN_ON_ONCE(err);
}

void virtio_kvm_eventfd_poll_done(struct virtio_kvm_poll *poll)
{
	struct virtio_kvm_eventfd *evfd;
	int i, j;

	rcu_read_lock();
	for (i = 0; i < VIRTIO_KVM_POLL_BATCH; i++) {
		if (poll->handle[i] != -1) {
			evfd = xa_load(&vi_device->ioeventfds, poll->handle[i]);
			if (!evfd)	/* Race w/ close */
				continue;
			for (j = 0; j < poll->vals[i]; j++) {
				trace_virtio_vm_ioeventfd_signal(evfd->handle, evfd->id);
				eventfd_signal(evfd->ctx);
			}
		}
	}
	rcu_read_unlock();

	atomic_set(&vi_device->poll_pending, 0);
	if (!xa_empty(&vi_device->ioeventfds))
		queue_work(eventfd_cleanup_wq, &vi_device->poll_refill);
}

static void kvm_request_done(struct virtkvm_cmd *cmd)
{
	struct virtio_kvm_reqresp *buf = &cmd->r;
	bool free_on_done = cmd->free_on_done;

	switch (buf->req.operation) {
	case VIRTIO_VM_EVENTFD_POLL:
		virtio_kvm_eventfd_poll_done(&buf->poll);
		break;
	default:
		complete(&cmd->acked);
		break;
	}

	if (free_on_done)
		kfree(cmd);
}

static void kvm_requestq_done(struct virtqueue *vq)
{
	struct virtkvm_cmd *cmd;
	struct virtio_kvm_reqresp *buf;
	unsigned long flags;
	unsigned int len;

	spin_lock_irqsave(&vi_device->virtkvm_lock, flags);
	do {
		virtqueue_disable_cb(vq);
		for (;;) {
			buf = virtqueue_get_buf(vq, &len);
			if (!buf)
				break;

			cmd = container_of(buf, struct virtkvm_cmd, r);
			trace_virtio_vm_vq_remove(le64_to_cpu(cmd->r.req.handle),
						  le64_to_cpu(cmd->r.req.operation),
						  le64_to_cpu(cmd->r.req.arg),
						  le64_to_cpu(cmd->r.req.longarg),
						  -(int)le64_to_cpu(cmd->r.resp.status));
			kvm_request_done(cmd);
		}
	} while (!virtqueue_enable_cb(vq));
	vi_device->vq_full = false;
	wake_up(&vi_device->vq_wait);
	spin_unlock_irqrestore(&vi_device->virtkvm_lock, flags);
}

long
__virtio_kvm_send_command(struct virtkvm_cmd *cmd, u64 handle, unsigned int operation, unsigned int oparg,
			unsigned long longarg, u64 *data_out,
			enum virtio_command_mode mode)
{
	struct virtio_kvm_resp *resp;
	struct virtio_kvm_req *req;
	struct scatterlist *sgs[2], out, in;
	unsigned long flags;
	int interrupted;
	int needs_kick;
	int ret;
	int i;

	pr_debug("virtio_kvm_send_command: h:%llx, o:%x, oa:%x, la:%lx\n",
		 handle, operation, oparg, longarg);

	init_completion(&cmd->acked);

	req = &cmd->r.req;
	resp = &cmd->r.resp;
	req->handle = handle;
	req->operation = operation;
	req->arg = oparg;
	req->longarg = longarg;

	sg_init_one(&out, req, sizeof(*req));
	sgs[0] = &out;
	sg_init_one(&in, resp, sizeof(*resp));
	sgs[1] = &in;

	cmd->free_on_done = mode == COMMAND_ASYNC;

	for (;;) {
		spin_lock_irqsave(&vi_device->virtkvm_lock, flags);
		ret = virtqueue_add_sgs(vi_device->vq, sgs, 1, 1, req, GFP_ATOMIC);
		if (ret != -ENOSPC) {
			if (!ret) {
				trace_virtio_vm_vq_add(handle, operation, oparg, longarg);
				needs_kick = virtqueue_kick_prepare(vi_device->vq);
			}
			spin_unlock_irqrestore(&vi_device->virtkvm_lock, flags);
			if (!ret && needs_kick)
				virtqueue_notify(vi_device->vq);
			break;
		}
		vi_device->vq_full = true;
		spin_unlock_irqrestore(&vi_device->virtkvm_lock, flags);

		ret = wait_event_interruptible(vi_device->vq_wait, !vi_device->vq_full);
		if (ret == -ERESTARTSYS)
			return -EINTR;
	}

	switch (mode) {
	case COMMAND_ASYNC:
		return 0;
	case COMMAND_NORMAL:
		for (i = 0;; ++i) {
			if (wait_for_completion_timeout(&cmd->acked,
							msecs_to_jiffies(250)))
				break;
			pr_err("virtio-kvm: slow command (%d): "
			       "h:%llx, o:%x, oa:%x, la:%lx\n",
			       i, handle, operation, oparg, longarg);
		}
		break;
	case COMMAND_INTERRUPTIBLE:
		interrupted = wait_for_completion_interruptible(&cmd->acked);
		if (interrupted == -ERESTARTSYS) {
			struct virtkvm_cmd *int_cmd;
			/* We are here because the wait for KVM_RUN (or
			 * another interruptible command) was broken by a
			 * signal in L1. Reflect into L0 and wait for the
			 * original command to complete - it will do so
			 * 'promptly', with a valid status.
			 */
			trace_virtio_vm_cmd_int(handle);
			int_cmd = kzalloc(sizeof(*int_cmd), GFP_KERNEL);
			if (int_cmd) {
				ret = __virtio_kvm_send_command(int_cmd, handle, VIRTIO_VM_CMD_INT, 0,
								0, NULL, COMMAND_ASYNC);
				if (ret)
					kfree(int_cmd);
			}
			wait_for_completion(&cmd->acked);
		}
		break;
	}

	/* status is the positive errno */
	ret = -(int)resp->status;

	WARN_ON_ONCE(ret > 0);

	if (!ret && data_out)
		*data_out = resp->data;

	return ret;
}

int virtio_kvm_send_command(u64 handle, unsigned int operation,
			    unsigned int oparg, unsigned long longarg,
			    u64 *data_out)
{
	struct virtkvm_cmd *cmd;
	int ret;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	ret = __virtio_kvm_send_command(cmd, handle, operation, oparg, longarg,
					 data_out, COMMAND_NORMAL);
	kfree(cmd);
	return ret;
}

int virtio_kvm_send_command_async(u64 handle, unsigned int operation,
				  unsigned int oparg,
				  unsigned long longarg,
				  u64 *data_out)
{
	struct virtkvm_cmd *cmd;
	int ret;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	ret = __virtio_kvm_send_command(cmd, handle, operation, oparg, longarg,
					 data_out, COMMAND_ASYNC);
	if (ret)
		kfree(cmd);
	return ret;
}

int
__virtio_kvm_send_command_ucopy(u64 handle, unsigned int operation,
				unsigned int ioctl, unsigned long arg,
				size_t size, u64 *data, int always_copy)
{
	void * __user user_struct;
	void *kern_struct;
	int err;

	user_struct = u64_to_user_ptr((u64)arg);

	kern_struct = kzalloc(size, GFP_KERNEL);
	if (!kern_struct)
		return -ENOMEM;

	if (copy_from_user(kern_struct, user_struct, size)) {
		err = -EFAULT;
		goto free;
	}

	err = virtio_kvm_send_command(handle, VIRTIO_VM_IOCTL, ioctl,
				      __pa(kern_struct), data);
	if (err && !always_copy)
		goto free;

	if (copy_to_user(user_struct, kern_struct, size))
		err = -EFAULT;

free:
	kfree(kern_struct);
	return err;
}

int
virtio_kvm_send_command_ucopy(u64 handle, unsigned int operation, unsigned int ioctl,
			      unsigned long arg, size_t size, u64 *data)
{
	return __virtio_kvm_send_command_ucopy(handle, operation, ioctl, arg,
					       size, data, 0);
}

int
virtio_kvm_send_command_ucopy_async(u64 handle, unsigned int operation,
				    unsigned int ioctl, unsigned long arg,
				    size_t size)
{
	void __user *user_struct = u64_to_user_ptr((u64)arg);
	/*
	 * Allocate cmd and data together so that kvm_request_done()
	 * can free both at once via kfree(cmd).
	 */
	struct virtkvm_cmd_async {
		struct virtkvm_cmd cmd;
		char data[];
	} *cmd_async;
	int ret;

	cmd_async = kzalloc(sizeof(*cmd_async) + size, GFP_KERNEL);
	if (!cmd_async)
		return -ENOMEM;

	if (copy_from_user(cmd_async->data, user_struct, size)) {
		kfree(cmd_async);
		return -EFAULT;
	}

	ret = __virtio_kvm_send_command(&cmd_async->cmd, handle, operation, ioctl,
					__pa(cmd_async->data), NULL, COMMAND_ASYNC);
	if (ret) {
		kfree(cmd_async);
		return ret;
	}

	return 0;
}

int virtio_kvm_generic_mmap(u64 handle, struct vm_area_struct *vma,
			    const struct vm_operations_struct *vm_ops)
{
	struct virtio_kvm_mmap_device {
		__le64 size;
		__le64 device_offset;
		__le64 phys_offset;
	} __attribute__((packed));

	struct virtio_kvm_mmap_device *mmap_device;
	size_t size = vma->vm_end - vma->vm_start;
	u64 new_offset;
	u64 new_pa;
	int err;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	mmap_device = kzalloc(sizeof(*mmap_device), GFP_KERNEL);
	if (!mmap_device)
		return -ENOMEM;

	new_offset = virtio_vm_get_unused_phys_offset(size, PAGE_SHIFT);
	if (new_offset == INVALID_PHYS_OFFSET) {
		kfree(mmap_device);
		return -ENOMEM;
	}

	mmap_device->size = size;
	mmap_device->device_offset = vma->vm_pgoff << PAGE_SHIFT;
	mmap_device->phys_offset = new_offset;

	err = virtio_kvm_send_command(handle, VIRTIO_VM_DEVICE_MMAP, 0,
				      __pa(mmap_device), NULL);

	kfree(mmap_device);

	if (err) {
		virtio_vm_put_unused_phys_offset(new_offset, size);
		return err;
	}

	new_pa = new_offset + vi_device->phys_start;

	vma->vm_ops = vm_ops;

	err = remap_pfn_range(vma, vma->vm_start, new_pa >> PAGE_SHIFT,
			      vma->vm_end - vma->vm_start, vma->vm_page_prot);
	if (err)
		goto undo;

	vma->vm_private_data = (void *)new_offset;

	return 0;

undo:
	{
		int ret;

		ret = send_dev_munmap(handle, new_offset,
				      vma->vm_end - vma->vm_start);
		if (ret)
			pr_warn_once("Failed to unmap VMA: %llx\n", handle);
		virtio_vm_put_unused_phys_offset(new_offset, size);
	}

	return err;
}

static ssize_t
virtio_kvm_file_chunk_io(u64 handle, char __user *user_buffer,
			 loff_t file_offset, size_t size,
			 struct virtio_kvm_file_io *file_io,
			 int direction)
{
	unsigned long offset_into_page;
	struct page *page;
	u64 amount_read;
	ssize_t ret;

	ret = get_user_pages_unlocked((unsigned long)user_buffer, 1, &page,
				      FOLL_WRITE);
	if (ret != 1) {
		WARN_ON_ONCE(ret >= 0);
		return ret;
	}

	offset_into_page = (unsigned long)user_buffer & (PAGE_SIZE - 1);

	file_io->offset = file_offset;
	file_io->size = min_t(size_t, size, PAGE_SIZE - offset_into_page);
	file_io->buffer = (u64)((page_to_pfn(page) << PAGE_SHIFT) +
				 offset_into_page);

	ret = virtio_kvm_send_command(handle, VIRTIO_VM_FILE_IO, direction,
				      __pa(file_io), &amount_read);
	if (ret)
		WARN_ON_ONCE(ret > 0);
	else
		ret = amount_read;

	if (WARN_ON_ONCE(ret > size))
		ret = size;

	put_page(page);

	return ret;
}

static ssize_t
virtio_kvm_file_do_io(u64 handle, char __user *user_buffer, size_t size,
		      loff_t *offset, int direction)
{
	struct virtio_kvm_file_io *file_io;
	loff_t curr_offset = *offset;
	ssize_t amount_done = 0, total_amount_done = 0;

	file_io = kmalloc(sizeof(*file_io), GFP_KERNEL);
	if (!file_io)
		return -ENOMEM;

	while (size > 0) {
		/*
		 * Although it is valid to return after only completing a single
		 * chunk, userspace may be expecting reads of certain sizes to
		 * always succeed.
		 */
		amount_done = virtio_kvm_file_chunk_io(handle, user_buffer,
						       curr_offset, size,
						       file_io, direction);
		if (amount_done <= 0)
			break;

		total_amount_done += amount_done;
		user_buffer += amount_done;
		curr_offset += amount_done;
		size -= amount_done;
	}

	kfree(file_io);

	if (total_amount_done) {
		*offset = curr_offset;
		return total_amount_done;
	}

	if (amount_done < 0)
		return amount_done;

	return 0;
}

ssize_t virtio_kvm_file_read(u64 handle, char __user *user_buffer, size_t size,
			     loff_t *offset)
{
	return virtio_kvm_file_do_io(handle, user_buffer, size, offset,
				     VIRTIO_VM_FILEIO_READ);
}

ssize_t virtio_kvm_file_write(u64 handle, const char __user *user_buffer,
			      size_t size, loff_t *offset)
{
	return virtio_kvm_file_do_io(handle, (char __user *)user_buffer,
				     size, offset, VIRTIO_VM_FILEIO_WRITE);
}

/*
 * Translate a userspace virtual address from a virtio-vm-file-backed VMA into
 * the virtual address in the VMM providing virtio-vm (i.e., the "host" virtual
 * address).
 */
int translate_va_to_pa(unsigned long va, unsigned long *phys_addr,
		       size_t size)
{
	struct vm_area_struct *vma;
	off_t vma_offset;
	u64 file_offset;
	int ret;

	ret = -EFAULT;
	mmap_read_lock(current->mm);
	vma = find_vma(current->mm, va);
	if (!vma)
		goto unlock;

	if (va < vma->vm_start || vma->vm_end <= va)
		goto unlock;

	ret = -ENOTSUPP;
	if (!vma->vm_file)
		goto unlock;

	/* Memory region must lie within a single VMA for now */
	ret = -E2BIG;
	if (va + size > vma->vm_end)
		goto unlock;

	vma_offset = va - vma->vm_start;
	file_offset = (vma->vm_pgoff << PAGE_SHIFT) + vma_offset;

	if (virtio_kvm_is_vkvmfs(vma->vm_file)) {
		ret = vkvmfs_offset_to_pa(vma->vm_file, file_offset, size,
					  phys_addr);
	} else if (virtio_kvm_is_vfio_device(vma)) {
		/* This works for any generic device mmap; used for VFIO. */
		ret = 0;
		*phys_addr = (unsigned long)vma->vm_private_data +
			     vi_device->phys_start + vma_offset;
	} else {
		ret = -ENOTSUPP;
	}

unlock:
	mmap_read_unlock(current->mm);
	return ret;
}

long send_dev_munmap(u64 handle, unsigned long phys_offset, unsigned long size)
{
	struct virtio_kvm_munmap_device {
		__le64 size;
		__le64 phys_offset;
	} __attribute__((packed));
	struct virtio_kvm_munmap_device *munmap_dev;
	long ret;

	munmap_dev = kzalloc(sizeof(*munmap_dev), GFP_KERNEL);
	if (!munmap_dev)
		return -ENOMEM;

	munmap_dev->phys_offset = phys_offset;
	munmap_dev->size = size;

	ret = virtio_kvm_send_command(handle, VIRTIO_VM_DEVICE_MUNMAP, 0,
				      __pa(munmap_dev), NULL);

	kfree(munmap_dev);
	return ret;
}

static void refill_work(struct work_struct *work)
{
	struct virtkvm_info *vi;
	int ret;

	vi = container_of(work, struct virtkvm_info, poll_refill);

	if (xa_empty(&vi->ioeventfds))
		return;

	if (atomic_cmpxchg_relaxed(&vi->poll_pending, 0, 1))
		return;

	ret = virtio_kvm_send_command_async(-1, VIRTIO_VM_EVENTFD_POLL, 0, 0, NULL);
	if (ret)
		atomic_set(&vi->poll_pending, 0);
	WARN_ON(ret != 0);
}

static void virtio_kvm_evfd_rcu_free(struct rcu_head *rcu)
{
	struct virtio_kvm_eventfd *evfd = container_of(rcu, struct virtio_kvm_eventfd, rcu);

	eventfd_ctx_put(evfd->ctx);
	kfree(evfd);
}

/*
 * Returns a virtio_kvm_eventfd for the given eventfd_ctx.
 * On success, this function consumes the caller's reference to ctx.
 * On error, the caller is responsible for calling eventfd_ctx_put(ctx).
 */
struct virtio_kvm_eventfd *virtio_kvm_get_evfd(struct eventfd_ctx *ctx)
{
	struct virtio_kvm_eventfd *evfd = NULL, *new_evfd = NULL;
	u64 handle = -1ULL;
	int ret, id;

	spin_lock(&vi_device->evfd_lock);
	hash_for_each_possible(vi_device->evfd_hash, evfd, hnode, (unsigned long)ctx) {
		if (evfd->ctx != ctx)
			continue;

		if (!refcount_inc_not_zero(&evfd->refcnt))
			continue;
		spin_unlock(&vi_device->evfd_lock);
		eventfd_ctx_put(ctx);
		return evfd;
	}
	spin_unlock(&vi_device->evfd_lock);

	new_evfd = kzalloc(sizeof(*new_evfd), GFP_KERNEL);
	if (!new_evfd)
		return ERR_PTR(-ENOMEM);

	id = ida_alloc(&vi_device->evfd_ida, GFP_KERNEL);
	if (id < 0) {
		kfree(new_evfd);
		return ERR_PTR(id);
	}

	new_evfd->id = id;
	new_evfd->ctx = ctx;
	refcount_set(&new_evfd->refcnt, 1);

	ret = virtio_kvm_send_command(-1, VIRTIO_VM_EVENTFD_GET, 0,
				      (u64) id, &handle);
	if (ret) {
		ida_free(&vi_device->evfd_ida, id);
		kfree(new_evfd);
		return ERR_PTR(ret);
	}
	new_evfd->handle = handle;

	ret = xa_insert(&vi_device->ioeventfds, handle, new_evfd, GFP_KERNEL);
	if (ret) {
		virtio_kvm_send_command(-1, VIRTIO_VM_EVENTFD_PUT, 0,
					handle, NULL);
		ida_free(&vi_device->evfd_ida, id);
		kfree(new_evfd);
		return ERR_PTR(ret);
	}

	/* Check again if it was already added. */
	spin_lock(&vi_device->evfd_lock);
	hash_for_each_possible(vi_device->evfd_hash, evfd, hnode, (unsigned long)ctx) {
		if (evfd->ctx != ctx)
			continue;
		/* It is already here */
		if (!refcount_inc_not_zero(&evfd->refcnt))
			continue;
		spin_unlock(&vi_device->evfd_lock);

		xa_erase(&vi_device->ioeventfds, handle);
		virtio_kvm_send_command(-1, VIRTIO_VM_EVENTFD_PUT, 0,
					handle, NULL);
		ida_free(&vi_device->evfd_ida, id);
		call_rcu(&new_evfd->rcu, virtio_kvm_evfd_rcu_free);
		return evfd;
	}

	/* Still not there, add our new one */
	trace_virtio_vm_ioeventfd_add(handle, id);
	hash_add(vi_device->evfd_hash, &new_evfd->hnode, (unsigned long)ctx);
	spin_unlock(&vi_device->evfd_lock);

	queue_work(eventfd_cleanup_wq, &vi_device->poll_refill);

	return new_evfd;
}

void virtio_kvm_put_evfd(struct virtio_kvm_eventfd *evfd)
{
	if (!refcount_dec_and_test(&evfd->refcnt))
		return;

	spin_lock(&vi_device->evfd_lock);
	hash_del(&evfd->hnode);
	trace_virtio_vm_ioeventfd_remove(evfd->handle, evfd->id);
	xa_erase(&vi_device->ioeventfds, evfd->handle);
	spin_unlock(&vi_device->evfd_lock);

	virtio_kvm_send_command(-1, VIRTIO_VM_EVENTFD_PUT, 0,
				evfd->handle, NULL);
	ida_free(&vi_device->evfd_ida, evfd->id);
	call_rcu(&evfd->rcu, virtio_kvm_evfd_rcu_free);
}

static int virtio_vm_init(struct virtio_device *vdev)
{
	int err;
	struct virtkvm_info *vi = NULL;
	struct virtio_pci_device *vp;

	vi = kzalloc(sizeof(struct virtkvm_info), GFP_KERNEL);
	if (!vi)
		return -ENOMEM;

	eventfd_cleanup_wq = NULL;
	atomic_set(&vi->poll_pending, 0);

	vdev->priv = vi;

	/* virtio-kvm is always a virtio-pci device. */
	vp = to_vp_device(vdev);
	err = pci_request_region(vp->pci_dev, 4, "virtio-kvm");
	if (err) {
		pr_err("failed to request virtio-kvm BAR4\n");
		goto err;
	}

	vi->phys_start = pci_resource_start(vp->pci_dev, 4);
	vi->phys_end = pci_resource_end(vp->pci_dev, 4);

	vi->allocinfo.range_size = vi->phys_end - vi->phys_start;
	mt_init_flags(&vi->allocinfo.mt, MT_FLAGS_ALLOC_RANGE | MT_FLAGS_USE_RCU);

	/* We expect a single virtqueue. */
	vi->vq = virtio_find_single_vq(vdev, kvm_requestq_done, "requestq");
	if (IS_ERR(vi->vq)) {
		err = PTR_ERR(vi->vq);
		goto err;
	}

	xa_init(&vi->ioeventfds);
	hash_init(vi->evfd_hash);
	ida_init(&vi->evfd_ida);
	spin_lock_init(&vi->evfd_lock);
	INIT_WORK(&vi->poll_refill, refill_work);
	spin_lock_init(&vi->virtkvm_lock);

	err = -ENOMEM;
	eventfd_cleanup_wq = alloc_workqueue("virtio-kvm-eventfd-cleanup", 0, 0);
	if (!eventfd_cleanup_wq)
		return err;

	err = virtkvm_kvm_init(vi);
	if (err)
		goto err;

	err = virtkvm_vfio_init(vi);
	if (err) {
		virtkvm_kvm_cleanup(vi);
		goto err;
	}

	virtio_device_ready(vdev);
	vi_device = vi;

	return 0;

err:
	if (eventfd_cleanup_wq)
		destroy_workqueue(eventfd_cleanup_wq);
	mtree_destroy(&vi->allocinfo.mt);
	vp = to_vp_device(vdev);
	pci_release_region(vp->pci_dev, 4);
	kfree(vi);
	return err;
}

static void remove_common(struct virtio_device *vdev)
{
	struct virtkvm_info *vi = vdev->priv;
	struct virtio_pci_device *vp;

	if (eventfd_cleanup_wq)
		destroy_workqueue(eventfd_cleanup_wq);

	virtio_reset_device(vdev);
	vdev->config->del_vqs(vdev);

	vp = to_vp_device(vdev);
	pci_release_region(vp->pci_dev, 4);

	mtree_destroy(&vi->allocinfo.mt);
	ida_destroy(&vi->evfd_ida);
	kfree(vi);
}

static int virtkvm_probe(struct virtio_device *vdev)
{
	return virtio_vm_init(vdev);
}

static void virtkvm_remove(struct virtio_device *vdev)
{
	virtkvm_vfio_cleanup(vi_device);

	virtkvm_kvm_cleanup(vi_device);

	remove_common(vdev);
}

#define VIRTIO_ID_KVM 0xb
static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_KVM, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_kvm_driver = {
	.driver.name =	KBUILD_MODNAME,
	.id_table =	id_table,
	.probe =	virtkvm_probe,
	.remove =	virtkvm_remove,
};

module_virtio_driver(virtio_kvm_driver);
MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio KVM Driver");
MODULE_LICENSE("GPL");
