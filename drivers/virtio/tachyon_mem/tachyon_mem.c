// SPDX-License-Identifier: GPL-2.0
/*
 * /dev/tachyon-mem: L0 memory-indirection driver for Tachyon L1-overcommit.
 *
 * Each L2 memslot gets a single contiguous VM_PFNMAP VMA backed by a private
 * inode. On fault, vm_ops->fault() reads the shared L2->L1 GFN table, translates
 * the L1 GPA to Tachyon's HVA of L1's memory, and inserts the L0 PFN.
 * Invalidations from L1 call unmap_mapping_range() on the slot's inode,
 * triggering L0 KVM's mmu_notifier to zap L2 EPT entries.
 */

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/pseudo_fs.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

#include "tachyon_mem.h"

#define TACHYON_MEM_MAX_L1_REGIONS	64
#define TACHYON_MEM_PSEUDO_MAGIC	0x54414348

struct tachyon_mem_fault_entry {
	struct list_head list;
	u64 tag;
	u64 offset;
	u64 seq;
	bool in_flight;
	bool done;
};

struct tachyon_mem_ctx {
	struct kref ref;
	struct mutex lock;
	u32 nr_regions;
	struct tachyon_mem_l1_region *regions;
	spinlock_t fault_lock;
	struct list_head fault_list;
	wait_queue_head_t fault_get_wq;
	wait_queue_head_t fault_done_wq;
	u64 next_seq;
	bool closed;
};

struct tachyon_mem_slot {
	struct kref ref;
	struct tachyon_mem_ctx *ctx;
	struct inode *inode;
	u64 size;
	u64 nr_pages;
	u64 tag;
	u64 *table;
	struct page **table_pages;
	unsigned long nr_table_pages;
};

static struct vfsmount *tachyon_mem_mnt;
static int tachyon_mem_mnt_cnt;

static int tachyon_mem_init_fs_context(struct fs_context *fc)
{
	return init_pseudo(fc, TACHYON_MEM_PSEUDO_MAGIC) ? 0 : -ENOMEM;
}

static struct file_system_type tachyon_mem_fs_type = {
	.name = "tachyon_mem_fs",
	.init_fs_context = tachyon_mem_init_fs_context,
	.kill_sb = kill_anon_super,
};

static void tachyon_mem_ctx_release(struct kref *ref)
{
	struct tachyon_mem_ctx *ctx = container_of(ref, struct tachyon_mem_ctx, ref);

	kfree(ctx->regions);
	kfree(ctx);
}

static int tachyon_mem_lookup_l1_hva(struct tachyon_mem_ctx *ctx, u64 l1_gpa,
				     u64 *out_hva)
{
	u32 i;
	int ret = -EFAULT;

	mutex_lock(&ctx->lock);
	for (i = 0; i < ctx->nr_regions; i++) {
		struct tachyon_mem_l1_region *r = &ctx->regions[i];

		if (l1_gpa >= r->l1_gpa && l1_gpa < r->l1_gpa + r->size) {
			*out_hva = r->hva + (l1_gpa - r->l1_gpa);
			ret = 0;
			break;
		}
	}
	mutex_unlock(&ctx->lock);
	return ret;
}

static void tachyon_mem_slot_free(struct kref *ref)
{
	struct tachyon_mem_slot *slot =
		container_of(ref, struct tachyon_mem_slot, ref);

	if (slot->table)
		vunmap(slot->table);
	if (slot->table_pages) {
		unpin_user_pages(slot->table_pages, slot->nr_table_pages);
		kvfree(slot->table_pages);
	}
	if (slot->inode)
		iput(slot->inode);
	kref_put(&slot->ctx->ref, tachyon_mem_ctx_release);
	kfree(slot);
}

static void tachyon_mem_wait_fault(struct tachyon_mem_ctx *ctx, u64 tag,
				   u64 offset)
{
	struct tachyon_mem_fault_entry entry = {
		.tag = tag,
		.offset = offset,
	};

	spin_lock(&ctx->fault_lock);
	if (ctx->closed) {
		spin_unlock(&ctx->fault_lock);
		return;
	}
	entry.seq = ++ctx->next_seq;
	list_add_tail(&entry.list, &ctx->fault_list);
	wake_up(&ctx->fault_get_wq);
	spin_unlock(&ctx->fault_lock);

	wait_event_killable(ctx->fault_done_wq,
			    READ_ONCE(entry.done) || READ_ONCE(ctx->closed));

	spin_lock(&ctx->fault_lock);
	list_del(&entry.list);
	spin_unlock(&ctx->fault_lock);
}

static vm_fault_t tachyon_mem_fault(struct vm_fault *vmf)
{
	struct tachyon_mem_slot *slot = vmf->vma->vm_private_data;
	pgoff_t idx = vmf->pgoff;
	struct page *page = NULL;
	u64 entry, l1_gpa, l1_hva;
	unsigned int foll_flags;
	long ret;

	if (idx >= slot->nr_pages)
		return VM_FAULT_SIGBUS;

	entry = READ_ONCE(slot->table[idx]);
	if (!(entry & TACHYON_MEM_PTE_PRESENT)) {
		if (!slot->tag ||
		    !(vmf->flags & FAULT_FLAG_ALLOW_RETRY) ||
		    (vmf->flags & FAULT_FLAG_RETRY_NOWAIT))
			return VM_FAULT_SIGBUS;

		kref_get(&slot->ref);
		mmap_read_unlock(vmf->vma->vm_mm);
		tachyon_mem_wait_fault(slot->ctx, slot->tag,
				       (u64)idx << PAGE_SHIFT);
		kref_put(&slot->ref, tachyon_mem_slot_free);
		return VM_FAULT_RETRY;
	}

	l1_gpa = entry & TACHYON_MEM_PFN_MASK;
	if (tachyon_mem_lookup_l1_hva(slot->ctx, l1_gpa, &l1_hva))
		return VM_FAULT_SIGBUS;

	foll_flags = (entry & TACHYON_MEM_PTE_WRITABLE) ? FOLL_WRITE : 0;
	/* mmap_read_lock(current->mm) is held by the page fault handler. */
	ret = get_user_pages(l1_hva, 1, foll_flags, &page);
	if (ret != 1)
		return VM_FAULT_SIGBUS;

	ret = vmf_insert_pfn(vmf->vma, vmf->address, page_to_pfn(page));
	put_page(page);
	return ret;
}

static const struct vm_operations_struct tachyon_mem_vm_ops = {
	.fault = tachyon_mem_fault,
};

static int tachyon_mem_slot_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct tachyon_mem_slot *slot = filp->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;

	if (vma->vm_pgoff || size > slot->size)
		return -EINVAL;
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	vm_flags_set(vma, VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_private_data = slot;
	vma->vm_ops = &tachyon_mem_vm_ops;
	return 0;
}

static long tachyon_mem_slot_ioctl(struct file *filp, unsigned int cmd,
				   unsigned long arg)
{
	struct tachyon_mem_slot *slot = filp->private_data;
	struct tachyon_mem_invalidate inv;

	if (cmd != TACHYON_MEM_INVALIDATE)
		return -ENOTTY;

	if (copy_from_user(&inv, (void __user *)arg, sizeof(inv)))
		return -EFAULT;

	if (inv.offset >= slot->size || inv.size > slot->size - inv.offset)
		return -EINVAL;

	if (inv.size)
		unmap_mapping_range(slot->inode->i_mapping, inv.offset,
				    inv.size, 1);
	return 0;
}

static int tachyon_mem_slot_release(struct inode *inode, struct file *filp)
{
	struct tachyon_mem_slot *slot = filp->private_data;

	if (slot)
		kref_put(&slot->ref, tachyon_mem_slot_free);
	return 0;
}

static const struct file_operations tachyon_mem_slot_fops = {
	.owner = THIS_MODULE,
	.mmap = tachyon_mem_slot_mmap,
	.unlocked_ioctl = tachyon_mem_slot_ioctl,
	.release = tachyon_mem_slot_release,
};

static int tachyon_mem_set_l1_regions(struct tachyon_mem_ctx *ctx,
				      unsigned long arg)
{
	struct tachyon_mem_set_l1_regions req;
	struct tachyon_mem_l1_region *regions;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	if (req.count > TACHYON_MEM_MAX_L1_REGIONS)
		return -EINVAL;

	if (req.count) {
		regions = memdup_user((void __user *)req.regions_ptr,
				      array_size(req.count, sizeof(*regions)));
		if (IS_ERR(regions))
			return PTR_ERR(regions);
	} else {
		regions = NULL;
	}

	mutex_lock(&ctx->lock);
	kfree(ctx->regions);
	ctx->regions = regions;
	ctx->nr_regions = req.count;
	mutex_unlock(&ctx->lock);
	return 0;
}

static long tachyon_mem_create_slot_common(struct tachyon_mem_ctx *ctx,
					   const struct tachyon_mem_create_slot_ex *req)
{
	struct tachyon_mem_slot *slot;
	struct file *file;
	unsigned long nr_table_pages;
	long pinned;
	int fd, ret;

	if (!req->size || !PAGE_ALIGNED(req->size) ||
	    !PAGE_ALIGNED(req->table_hva))
		return -EINVAL;

	nr_table_pages = DIV_ROUND_UP(req->table_size, PAGE_SIZE);
	if (!nr_table_pages ||
	    req->table_size < (req->size >> PAGE_SHIFT) * sizeof(u64))
		return -EINVAL;

	slot = kzalloc(sizeof(*slot), GFP_KERNEL);
	if (!slot)
		return -ENOMEM;

	kref_init(&slot->ref);
	slot->size = req->size;
	slot->nr_pages = req->size >> PAGE_SHIFT;
	slot->tag = req->tag;
	kref_get(&ctx->ref);
	slot->ctx = ctx;

	slot->table_pages = kvcalloc(nr_table_pages, sizeof(struct page *),
				     GFP_KERNEL);
	if (!slot->table_pages) {
		ret = -ENOMEM;
		goto err_free_slot;
	}

	pinned = pin_user_pages_fast(req->table_hva, nr_table_pages,
				     FOLL_WRITE | FOLL_LONGTERM,
				     slot->table_pages);
	if (pinned != nr_table_pages) {
		if (pinned > 0)
			unpin_user_pages(slot->table_pages, pinned);
		ret = pinned < 0 ? pinned : -EFAULT;
		goto err_free_pages;
	}
	slot->nr_table_pages = nr_table_pages;

	slot->table = vmap(slot->table_pages, nr_table_pages, VM_MAP,
			   PAGE_KERNEL);
	if (!slot->table) {
		ret = -ENOMEM;
		goto err_unpin;
	}

	slot->inode = alloc_anon_inode(tachyon_mem_mnt->mnt_sb);
	if (IS_ERR(slot->inode)) {
		ret = PTR_ERR(slot->inode);
		slot->inode = NULL;
		goto err_vunmap;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto err_iput;
	}

	/*
	 * alloc_file_pseudo() does not take a module reference, but __fput()
	 * drops f_op->owner when the file is closed.
	 */
	if (!try_module_get(THIS_MODULE)) {
		ret = -ENODEV;
		put_unused_fd(fd);
		goto err_iput;
	}

	file = alloc_file_pseudo(slot->inode, tachyon_mem_mnt,
				 "tachyon-mem-slot", O_RDWR,
				 &tachyon_mem_slot_fops);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		module_put(THIS_MODULE);
		put_unused_fd(fd);
		goto err_iput;
	}

	/* alloc_file_pseudo took ownership of slot->inode; keep a ref for slot->inode. */
	ihold(slot->inode);
	file->private_data = slot;
	fd_install(fd, file);
	return fd;

err_iput:
	iput(slot->inode);
err_vunmap:
	vunmap(slot->table);
err_unpin:
	unpin_user_pages(slot->table_pages, slot->nr_table_pages);
err_free_pages:
	kvfree(slot->table_pages);
err_free_slot:
	kref_put(&ctx->ref, tachyon_mem_ctx_release);
	kfree(slot);
	return ret;
}

static long tachyon_mem_create_slot(struct tachyon_mem_ctx *ctx,
				    unsigned long arg)
{
	struct tachyon_mem_create_slot req;
	struct tachyon_mem_create_slot_ex req_ex;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	req_ex.size = req.size;
	req_ex.table_hva = req.table_hva;
	req_ex.table_size = req.table_size;
	req_ex.tag = 0;
	return tachyon_mem_create_slot_common(ctx, &req_ex);
}

static long tachyon_mem_create_slot_ex(struct tachyon_mem_ctx *ctx,
				       unsigned long arg)
{
	struct tachyon_mem_create_slot_ex req;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	return tachyon_mem_create_slot_common(ctx, &req);
}

static bool tachyon_mem_pop_fault(struct tachyon_mem_ctx *ctx,
				  struct tachyon_mem_fault_req *req)
{
	struct tachyon_mem_fault_entry *entry;
	bool found = false;

	spin_lock(&ctx->fault_lock);
	list_for_each_entry(entry, &ctx->fault_list, list) {
		if (!entry->in_flight && !entry->done) {
			entry->in_flight = true;
			req->tag = entry->tag;
			req->offset = entry->offset;
			req->seq = entry->seq;
			found = true;
			break;
		}
	}
	spin_unlock(&ctx->fault_lock);
	return found;
}

static long tachyon_mem_get_fault(struct tachyon_mem_ctx *ctx,
				  unsigned long arg)
{
	struct tachyon_mem_fault_req req = {};
	int ret;

	ret = wait_event_interruptible(ctx->fault_get_wq,
				       tachyon_mem_pop_fault(ctx, &req) ||
				       READ_ONCE(ctx->closed));
	if (ret)
		return ret;
	if (!req.seq)
		return -EPIPE;

	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

static long tachyon_mem_ack_fault(struct tachyon_mem_ctx *ctx,
				  unsigned long arg)
{
	struct tachyon_mem_fault_req req;
	struct tachyon_mem_fault_entry *entry;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	spin_lock(&ctx->fault_lock);
	list_for_each_entry(entry, &ctx->fault_list, list) {
		if (entry->seq == req.seq) {
			WRITE_ONCE(entry->done, true);
			wake_up_all(&ctx->fault_done_wq);
			break;
		}
	}
	spin_unlock(&ctx->fault_lock);
	return 0;
}

static int tachyon_mem_open(struct inode *inode, struct file *filp)
{
	struct tachyon_mem_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	kref_init(&ctx->ref);
	mutex_init(&ctx->lock);
	spin_lock_init(&ctx->fault_lock);
	INIT_LIST_HEAD(&ctx->fault_list);
	init_waitqueue_head(&ctx->fault_get_wq);
	init_waitqueue_head(&ctx->fault_done_wq);
	filp->private_data = ctx;
	return 0;
}

static int tachyon_mem_release(struct inode *inode, struct file *filp)
{
	struct tachyon_mem_ctx *ctx = filp->private_data;

	if (ctx) {
		spin_lock(&ctx->fault_lock);
		WRITE_ONCE(ctx->closed, true);
		wake_up_all(&ctx->fault_get_wq);
		wake_up_all(&ctx->fault_done_wq);
		spin_unlock(&ctx->fault_lock);
		kref_put(&ctx->ref, tachyon_mem_ctx_release);
	}
	return 0;
}

static long tachyon_mem_ioctl(struct file *filp, unsigned int cmd,
			      unsigned long arg)
{
	struct tachyon_mem_ctx *ctx = filp->private_data;

	switch (cmd) {
	case TACHYON_MEM_SET_L1_REGIONS:
		return tachyon_mem_set_l1_regions(ctx, arg);
	case TACHYON_MEM_CREATE_SLOT:
		return tachyon_mem_create_slot(ctx, arg);
	case TACHYON_MEM_CREATE_SLOT_EX:
		return tachyon_mem_create_slot_ex(ctx, arg);
	case TACHYON_MEM_GET_FAULT:
		return tachyon_mem_get_fault(ctx, arg);
	case TACHYON_MEM_ACK_FAULT:
		return tachyon_mem_ack_fault(ctx, arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations tachyon_mem_fops = {
	.owner = THIS_MODULE,
	.open = tachyon_mem_open,
	.release = tachyon_mem_release,
	.unlocked_ioctl = tachyon_mem_ioctl,
};

static struct miscdevice tachyon_mem_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "tachyon-mem",
	.fops = &tachyon_mem_fops,
	.mode = 0666,
};

static int __init tachyon_mem_init(void)
{
	int ret;

	ret = simple_pin_fs(&tachyon_mem_fs_type, &tachyon_mem_mnt,
			    &tachyon_mem_mnt_cnt);
	if (ret)
		return ret;

	ret = misc_register(&tachyon_mem_dev);
	if (ret) {
		simple_release_fs(&tachyon_mem_mnt, &tachyon_mem_mnt_cnt);
		return ret;
	}

	pr_info("tachyon_mem: registered /dev/tachyon-mem\n");
	return 0;
}

static void __exit tachyon_mem_exit(void)
{
	misc_deregister(&tachyon_mem_dev);
	simple_release_fs(&tachyon_mem_mnt, &tachyon_mem_mnt_cnt);
}

module_init(tachyon_mem_init);
module_exit(tachyon_mem_exit);

MODULE_DESCRIPTION("Tachyon L1-overcommit memory indirection driver");
MODULE_LICENSE("GPL");
