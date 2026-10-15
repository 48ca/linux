#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/vfio.h>
#include <linux/slab.h>

#include "common.h"
#include "kvm.h"
#include "vfio.h"
#include "trace.h"

#undef pr_fmt
#define pr_fmt(fmt) "virtio-vm: vfio: " fmt

#define PCI_ADDRESS_LENGTH	(16)

/*
* Maximum buffer size for extensible VFIO ioctls passed over RPC.
*
* Setting MSI-X interrupts (VFIO_DEVICE_SET_IRQS) expands 32-bit user-space
* file descriptors into 64-bit eventfd handles in-place. Supporting the full
* PCIe specification limit of up to 2048 vectors requires 16,404 bytes
* (20-byte struct vfio_irq_set header + 2048 * 8 bytes).
*
* Capping the buffer size at (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER) (32KB,
* Order-3) accommodates the maximum 2048 MSI-X vectors and capability descriptor
* chains while remaining at or below PAGE_ALLOC_COSTLY_ORDER to prevent
* kmalloc allocation failures under physical memory fragmentation.
*/
#define VIRTKVM_VFIO_MAX_ARGSZ		(32 * 1024)

struct virtkvm_vfio_device {
	char				address[PCI_ADDRESS_LENGTH];
	u64				handle;
	u64				partition_id;
	struct virtkvm_vfio_group	*group;
	struct virtkvm_vfio_container	*container;
	struct virtio_kvm_partition	*part;

	struct xarray			irq_ctx;
};

struct virtkvm_vfio_container {
	struct kref		kref;
	struct list_head	group_list;
	u64			handle;
	u64			partition_id;
	struct virtio_kvm_partition *part;
};

struct virtkvm_vfio_group {
	struct list_head		link;
	struct miscdevice		misc_dev;
	struct kref			kref;
	char				name[32];
	char				nodename[64];
	u64				group_id;
	u64				partition_id;
	u64				handle;
	int				opened;
	int				device_fd_count;

	struct virtkvm_vfio_container	*container;
	struct virtio_kvm_partition	*part;
};

/* Protects container <-> group binding */
static DEFINE_MUTEX(virtkvm_vfio_lock);

static void virtkvm_vfio_container_release(struct kref *kref);

static void virtkvm_vfio_group_release_kref(struct kref *kref)
{
	struct virtkvm_vfio_group *group =
		container_of(kref, struct virtkvm_vfio_group, kref);
	kfree(group);
}

/*
 * Device objects
 */
static int virtkvm_vfio_device_release(struct inode *inode, struct file *filp)
{
	struct virtkvm_vfio_device *device = filp->private_data;
	struct virtkvm_vfio_group *group = device->group;
	struct virtio_kvm_eventfd *evfd;
	unsigned long idx;
	int ret;

	if (group) {
		group->device_fd_count--;
		kref_put(&group->kref, virtkvm_vfio_group_release_kref);
	}

	ret = virtio_kvm_send_command_async(device->handle, VIRTIO_VM_CLOSE, 0, 0, NULL);
	WARN_ON_ONCE(ret);

	/* Pairs with kref_get in GET_DEVICE_FD */
	if (device->container)
		kref_put(&device->container->kref, virtkvm_vfio_container_release);

	xa_for_each(&device->irq_ctx, idx, evfd) {
		virtio_kvm_put_evfd(evfd);
	}
	xa_destroy(&device->irq_ctx);

	virtkvm_partition_put(device->part);
	kfree(device);

	return ret;
}

static ssize_t virtkvm_vfio_device_read(struct file *filp, char __user *buf,
					size_t count, loff_t *ppos)
{
	struct virtkvm_vfio_device *device = filp->private_data;

	return virtio_kvm_file_read(device->handle, buf, count, ppos);
}

static ssize_t virtkvm_vfio_device_write(struct file *filp,
					 const char __user *buf,
					 size_t count, loff_t *ppos)
{
	struct virtkvm_vfio_device *device = filp->private_data;

	return virtio_kvm_file_write(device->handle, buf, count, ppos);
}

static const struct vm_operations_struct vfio_device_vm_ops = {
	.open = virtio_vm_vma_open,
	.close = virtio_vm_vma_close,
	.may_split = virtio_vm_vma_may_split,
};

bool virtio_kvm_is_vfio_device(const struct vm_area_struct *vma)
{
	return vma->vm_ops == &vfio_device_vm_ops;
}

static int
virtkvm_vfio_device_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct virtkvm_vfio_device *device = filp->private_data;

	return virtio_kvm_generic_mmap(device->handle, vma, &vfio_device_vm_ops);
}

static int virtkvm_vfio_set_irqs_get_size(struct vfio_irq_set *irqs,
					  size_t *asize, size_t *usize)
{
	size_t unitsz;
	size_t allocsz;

	if (irqs->argsz < sizeof(*irqs))
		return -EINVAL;

	/* MSI-X supports up to 2048. Use that as the max for now. */
	if (irqs->count > 2048)
		return -EINVAL;

	switch (irqs->flags & VFIO_IRQ_SET_DATA_TYPE_MASK) {
	case VFIO_IRQ_SET_DATA_NONE:
		allocsz = unitsz = 0;
		break;
	case VFIO_IRQ_SET_DATA_BOOL:
		allocsz = unitsz = sizeof(uint8_t);
		break;
	case VFIO_IRQ_SET_DATA_EVENTFD:
		/* More space is needed for the 64-bit eventfd handles. */
		allocsz = sizeof(uint64_t);
		unitsz = sizeof(int32_t);
		break;
	default:
		return -EINVAL;
	}

	if (unitsz * irqs->count > irqs->argsz - sizeof(*irqs))
		return -EINVAL;

	*usize = unitsz * irqs->count + sizeof(*irqs);
	*asize = allocsz * irqs->count + sizeof(*irqs);
	if (*asize > VIRTKVM_VFIO_MAX_ARGSZ)
		return -EINVAL;

	return 0;
}

static void virtkvm_vfio_free_eventfds(struct virtio_kvm_eventfd **evfds,
				       size_t count)
{
	int i;

	for (i = 0; i < count; ++i) {
		if (evfds[i])
			virtio_kvm_put_evfd(evfds[i]);
	}

	kfree(evfds);
}

static int
vfio_translate_eventfds(struct virtkvm_vfio_device *device,
			struct vfio_irq_set *irqs,
			struct virtio_kvm_eventfd ***out_evfds)
{
	struct virtio_kvm_eventfd **evfds;
	u64 *handles = (u64 *)irqs->data;
	int32_t *fds = (int32_t *)irqs->data;
	int ret = 0;
	int i;

	if ((irqs->flags & VFIO_IRQ_SET_DATA_TYPE_MASK) != VFIO_IRQ_SET_DATA_EVENTFD) {
		*out_evfds = NULL;
		return 0;
	}

	/*
	 * Allocate array in reverse because we are converting in-place from
	 * int32 to uint64.
	 */
	evfds = kcalloc(irqs->count, sizeof(*evfds), GFP_KERNEL_ACCOUNT);
	if (!evfds)
		return -ENOMEM;

	for (i = irqs->count - 1; i >= 0; --i) {
		struct virtio_kvm_eventfd *evfd;
		struct eventfd_ctx *eventfd;

		if (fds[i] < 0) {
			evfds[i] = NULL;
			continue;
		}

		CLASS(fd, f)(fds[i]);
		if (fd_empty(f)) {
			ret = -EBADF;
			break;
		}

		eventfd = eventfd_ctx_fileget(fd_file(f));
		if (IS_ERR(eventfd)) {
			ret = PTR_ERR(eventfd);
			break;
		}

		evfd = virtio_kvm_get_evfd(device->partition_id, eventfd);
		if (IS_ERR(evfd)) {
			eventfd_ctx_put(eventfd);
			ret = PTR_ERR(evfd);
			break;
		}
		evfds[i] = evfd;
	}

	if (i < irqs->count) {
		virtkvm_vfio_free_eventfds(evfds, irqs->count);
		return ret;
	}

	for (i = 0; i < irqs->count; ++i) {
		if (!evfds[i]) {
			handles[i] = INVALID_HANDLE;
			continue;
		}

		handles[i] = evfds[i]->handle;
	}

	*out_evfds = evfds;

	return 0;
}

static long virtkvm_vfio_device_set_irqs(struct virtkvm_vfio_device *device,
					 struct vfio_irq_set __user *uirqs)
{
	struct virtio_kvm_eventfd **evfds = NULL;
	struct vfio_irq_set tmp_irqs;
	struct vfio_irq_set *irqs;
	size_t asize, usize;
	int xa_idx = 0;
	int ret;
	int i;

	if (copy_from_user(&tmp_irqs, uirqs, sizeof(tmp_irqs)))
		return -EFAULT;

	ret = virtkvm_vfio_set_irqs_get_size(&tmp_irqs, &asize, &usize);
	if (ret)
		return ret;

	irqs = kzalloc(asize, GFP_KERNEL_ACCOUNT);
	if (!irqs)
		return -ENOMEM;

	ret = -EFAULT;
	if (copy_from_user(irqs, uirqs, usize))
		goto free;

	ret = -EINVAL;
	/* Check that the metadata hasn't changed. */
	if (memcmp(&tmp_irqs, irqs, sizeof(*irqs)))
		goto free;

	ret = vfio_translate_eventfds(device, irqs, &evfds);
	if (ret)
		goto free;

	if (evfds) {
		for (; xa_idx < irqs->count; ++xa_idx) {
			if (!evfds[xa_idx])
				continue;
			ret = xa_reserve(&device->irq_ctx, irqs->start + xa_idx, GFP_KERNEL);
			if (ret)
				goto release;
		}
	}

	/* Make the translation easier for L0 by specifying the new size
	 * to account for 64-bit eventfd handles. */
	irqs->argsz = asize;

	ret = virtio_kvm_send_command(device->handle, VIRTIO_VM_IOCTL,
				      VFIO_DEVICE_SET_IRQS, __pa(irqs), NULL);
	if (WARN_ON(ret))
		goto release;

	if (!evfds) {
		if ((irqs->flags & VFIO_IRQ_SET_ACTION_TRIGGER) &&
		    (irqs->flags & VFIO_IRQ_SET_DATA_NONE)) {
			for (i = 0; i < irqs->count; ++i) {
				struct virtio_kvm_eventfd *old_evfd;

				old_evfd = xa_erase(&device->irq_ctx, irqs->start + i);
				if (old_evfd)
					virtio_kvm_put_evfd(old_evfd);
			}
		}
		/* No need to track eventfds. We are done! */
		goto free;
	}

	for (i = 0; i < irqs->count; ++i) {
		struct virtio_kvm_eventfd *old_evfd;

		if (!evfds[i]) {
			old_evfd = xa_erase(&device->irq_ctx, irqs->start + i);
			if (old_evfd)
				virtio_kvm_put_evfd(old_evfd);
			continue;
		}

		old_evfd = xa_store(&device->irq_ctx, irqs->start + i, evfds[i],
				    GFP_KERNEL);
		/*
		 * xa_store is not expected to fail here because the slot was
		 * pre-allocated by xa_reserve().
		 */
		if (WARN_ON(xa_is_err(old_evfd)))
			continue;

		if (old_evfd)
			virtio_kvm_put_evfd(old_evfd);
	}

	kfree(evfds);
	kfree(irqs);

	return 0;

release:
	if (evfds) {
		for (i = 0; i < xa_idx; ++i) {
			if (evfds[i])
				xa_release(&device->irq_ctx, irqs->start + i);
		}
		virtkvm_vfio_free_eventfds(evfds, irqs->count);
	}
free:
	kfree(irqs);
	return ret;
}

static long virtkvm_vfio_device_ioctl(struct file *filp, unsigned int cmd,
				      unsigned long arg)
{
	struct virtkvm_vfio_device *device = filp->private_data;
	void __user *uarg = (void __user *) arg;
	int ret = -ENOTTY;

	switch (cmd) {
	case VFIO_DEVICE_GET_INFO: {
		struct vfio_device_info __user *udev = uarg;
		struct vfio_device_info *dev;
		u32 argsz;

		if (get_user(argsz, &udev->argsz))
			return -EFAULT;

		if (argsz < offsetofend(struct vfio_device_info, num_irqs) ||
		    argsz > VIRTKVM_VFIO_MAX_ARGSZ)
			return -EINVAL;

		dev = kzalloc(argsz, GFP_KERNEL);
		ret = -ENOMEM;
		if (!dev)
			break;

		if (copy_from_user(dev, udev, argsz)) {
			ret = -EFAULT;
			kfree(dev);
			break;
		}

		ret = virtio_kvm_send_command(device->handle, VIRTIO_VM_IOCTL, cmd, __pa(dev), NULL);

		if (!ret && copy_to_user(udev, dev, argsz))
			ret = -EFAULT;

		kfree(dev);
		break;
	}
	case VFIO_DEVICE_GET_REGION_INFO: {
		struct vfio_region_info __user *ureg = uarg;
		struct vfio_region_info *reg;
		u32 argsz;

		if (get_user(argsz, &ureg->argsz))
			return -EFAULT;

		if (argsz < offsetofend(struct vfio_region_info, offset) ||
		    argsz > VIRTKVM_VFIO_MAX_ARGSZ)
			return -EINVAL;

		reg = kzalloc(argsz, GFP_KERNEL);
		ret = -ENOMEM;
		if (!reg)
			break;

		if (copy_from_user(reg, ureg, argsz)) {
			ret = -EFAULT;
			kfree(reg);
			break;
		}

		ret = virtio_kvm_send_command(device->handle, VIRTIO_VM_IOCTL, cmd, __pa(reg), NULL);

		if (!ret && copy_to_user(ureg, reg, argsz))
			ret = -EFAULT;

		kfree(reg);
		break;
	}
	case VFIO_DEVICE_GET_IRQ_INFO: {
		struct vfio_irq_info __user *uirq = uarg;
		struct vfio_irq_info *irq;
		u32 argsz;

		if (get_user(argsz, &uirq->argsz))
			return -EFAULT;

		if (argsz < offsetofend(struct vfio_irq_info, count) ||
		    argsz > VIRTKVM_VFIO_MAX_ARGSZ)
			return -EINVAL;

		irq = kzalloc(argsz, GFP_KERNEL);
		ret = -ENOMEM;
		if (!irq)
			break;

		if (copy_from_user(irq, uirq, argsz)) {
			ret = -EFAULT;
			kfree(irq);
			break;
		}

		ret = virtio_kvm_send_command(device->handle, VIRTIO_VM_IOCTL, cmd, __pa(irq), NULL);

		if (!ret && copy_to_user(uirq, irq, argsz))
			ret = -EFAULT;

		kfree(irq);
		break;
	}
	case VFIO_DEVICE_RESET: {
		ret = virtio_kvm_send_command(device->handle, VIRTIO_VM_IOCTL, cmd, 0, NULL);
		//WARN_ON(ret);
		/* RESET may legitimately fail, for devices w/o the reset flag */
		break;
	}
	case VFIO_DEVICE_SET_IRQS: {
		struct vfio_irq_set __user *uirqs = u64_to_user_ptr((u64)arg);

		ret = virtkvm_vfio_device_set_irqs(device, uirqs);
		break;
	}
	default:
		break;
	}

	return ret;
}

const struct file_operations virtkvm_vfio_device_fops = {
	.owner = THIS_MODULE,
	.release = virtkvm_vfio_device_release,
	.read = virtkvm_vfio_device_read,
	.write = virtkvm_vfio_device_write,
	.mmap = virtkvm_vfio_device_mmap,
	.unlocked_ioctl = virtkvm_vfio_device_ioctl,
};

static const struct file_operations virtkvm_vfio_fops;

static int virtkvm_vfio_group_open(struct inode *inode, struct file *filp)
{
	struct miscdevice *misc = filp->private_data;
	struct virtkvm_vfio_group *group =
		container_of(misc, struct virtkvm_vfio_group, misc_dev);
	u64 data;
	int ret;

	guard(mutex)(&virtkvm_vfio_lock);

	if (group->opened)
		return -EBUSY;

	if (group->part && group->part->vi) {
		mutex_lock(&group->part->vi->partition_lock);
		if (group->part->dying || list_empty(&group->part->link)) {
			mutex_unlock(&group->part->vi->partition_lock);
			return -ENODEV;
		}
		virtkvm_partition_get(group->part);
		mutex_unlock(&group->part->vi->partition_lock);
	}

	ret = virtio_kvm_send_command(-1, VIRTIO_VM_VFIO_GROUP_OPEN,
				      group->partition_id, group->group_id,
				      &data);
	if (ret) {
		virtkvm_partition_put(group->part);
		return ret;
	}

	group->opened = 1;
	group->handle = data;
	group->container = NULL;
	kref_get(&group->kref);
	filp->private_data = group;

	return 0;
}

static int virtkvm_vfio_group_release(struct inode *inode, struct file *filp)
{
	struct virtkvm_vfio_group *group = filp->private_data;
	struct virtkvm_vfio_container *container;
	int ret;

	guard(mutex)(&virtkvm_vfio_lock);

	container = group->container;
	if (container) {
		/* A container may be associated with more than one group */
		kref_put(&container->kref, virtkvm_vfio_container_release);
		group->container = NULL;
	}

	if (group->opened) {
		ret = virtio_kvm_send_command_async(group->handle, VIRTIO_VM_CLOSE, 0, 0, NULL);
		WARN_ON(ret);

		group->handle = -1;
		group->opened = 0;
		virtkvm_partition_put(group->part);
	}

	kref_put(&group->kref, virtkvm_vfio_group_release_kref);

	return 0;
}

static int virtkvm_vfio_group_ioctl_set_container(struct virtkvm_vfio_group *group,
						  void __user *argp)
{
	struct virtkvm_vfio_container *container;
	int __user *fd_argp = argp;
	int ret;
	int fd; /* container fd */

	lockdep_assert_held(&virtkvm_vfio_lock);

	if (get_user(fd, fd_argp))
		return -EFAULT;

	CLASS(fd, f)(fd);
	if (fd_empty(f))
		return -EBADF;

	if (fd_file(f)->f_op != &virtkvm_vfio_fops)
		return -EBADF;

	if (group->container)
		return -EBUSY;

	if (WARN_ON(!group->opened))
		return -EINVAL;

	container = fd_file(f)->private_data;

	if (group->partition_id != container->partition_id)
		return -EINVAL;

	ret = virtio_kvm_send_command(group->handle, VIRTIO_VM_IOCTL, VFIO_GROUP_SET_CONTAINER, container->handle, NULL);
	if (!ret) {
		group->container = container;
		kref_get(&container->kref);
	}

	return ret;
}

static int virtkvm_vfio_group_ioctl_unset_container(struct virtkvm_vfio_group *group,
						  void __user *argp)
{
	lockdep_assert_held(&virtkvm_vfio_lock);
	return -EOPNOTSUPP;
}

static long virtkvm_vfio_group_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct virtkvm_vfio_group *group = filp->private_data;
	void __user *uarg = (void __user *) arg;
	int ret = -ENOTTY;

	guard(mutex)(&virtkvm_vfio_lock);

	switch (cmd) {
	case VFIO_GROUP_GET_DEVICE_FD: {
		struct virtkvm_vfio_container *container;
		char dev_name[PCI_ADDRESS_LENGTH];
		struct file *filep;
		int fdno;
		u64 data;

		struct virtkvm_vfio_device *device;

		container = group->container;

		if (!container) {
			ret = -EINVAL;
			break;
		}

		if (copy_from_user(dev_name, (void __user *)arg, sizeof(dev_name))) {
			ret = -EFAULT;
			break;
		}
		dev_name[sizeof(dev_name) - 1] = '\0';

		fdno = get_unused_fd_flags(O_CLOEXEC);
		if (fdno < 0) {
			ret = fdno;
			break;
		}

		device = kzalloc(sizeof(*device), GFP_KERNEL);
		if (!device) {
			put_unused_fd(fdno);
			ret = -ENOMEM;
			break;
		}

		memcpy(device->address, dev_name, PCI_ADDRESS_LENGTH);

		filep = anon_inode_getfile_fmode("[virtkvm-vfio-device]", &virtkvm_vfio_device_fops,
				device, O_RDWR, FMODE_PREAD | FMODE_PWRITE);
		if (IS_ERR(filep)) {
			kfree(device);
			put_unused_fd(fdno);
			ret = PTR_ERR(filep);
			break;
		}

		ret = virtio_kvm_send_command(group->handle, VIRTIO_VM_IOCTL,
						VFIO_GROUP_GET_DEVICE_FD,
						__pa(device->address),
						&data);
		if (ret) {
			fput(filep);
			put_unused_fd(fdno);
			break;
		}

		device->handle = data;
		device->partition_id = group->partition_id;
		device->group = group;
		device->container = container;
		device->part = group->part;
		virtkvm_partition_get(device->part);

		kref_get(&group->kref);
		kref_get(&container->kref);
		group->device_fd_count++;
		xa_init(&device->irq_ctx);

		fd_install(fdno, filep);
		ret = fdno;

		break;
	}
	case VFIO_GROUP_GET_STATUS: {
		struct vfio_group_status __user *ug = u64_to_user_ptr((u64)arg);
		struct vfio_group_status *g;
		u32 argsz;

		if (get_user(argsz, &ug->argsz))
			return -EFAULT;

		if (argsz < offsetofend(struct vfio_group_status, flags) ||
		    argsz > VIRTKVM_VFIO_MAX_ARGSZ)
			return -EINVAL;

		g = kzalloc(argsz, GFP_KERNEL);
		ret = -ENOMEM;
		if (!g)
			break;

		if (copy_from_user(g, ug, argsz)) {
			ret = -EFAULT;
			kfree(g);
			break;
		}

		ret = virtio_kvm_send_command(group->handle, VIRTIO_VM_IOCTL, cmd,
						__pa(g), NULL);

		if (!ret && copy_to_user(ug, g, argsz))
			ret = -EFAULT;

		kfree(g);
		break;
	}
	case VFIO_GROUP_SET_CONTAINER:
		ret = virtkvm_vfio_group_ioctl_set_container(group, uarg);
		break;
	case VFIO_GROUP_UNSET_CONTAINER:
		ret = virtkvm_vfio_group_ioctl_unset_container(group, uarg);
		break;
	default:
		break;
	}

	return ret;
}

static const struct file_operations virtkvm_vfio_group_fops = {
	.owner = THIS_MODULE,
	.open = virtkvm_vfio_group_open,
	.release = virtkvm_vfio_group_release,
	.unlocked_ioctl = virtkvm_vfio_group_ioctl,
};

static int virtkvm_vfio_map_dma(struct virtkvm_vfio_container *container,
				unsigned long arg)
{
	struct vfio_iommu_type1_dma_map *map;
	unsigned long phys_addr;
	int ret = -ENOMEM;

	map = kzalloc(sizeof(*map), GFP_KERNEL_ACCOUNT);
	if (!map)
		goto out;

	ret = -EFAULT;
	if (copy_from_user(map, u64_to_user_ptr((u64)arg), sizeof(*map)))
		goto out;

	ret = -EINVAL;
	if (map->flags & ~(VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE))
		goto out;

	ret = translate_va_to_pa(map->vaddr, &phys_addr, map->size);
	if (ret)
		goto out;

	map->vaddr = phys_addr;

	/* map::vaddr is a GPA */
	ret = virtio_kvm_send_command(container->handle, VIRTIO_VM_IOCTL,
				      VFIO_IOMMU_MAP_DMA, __pa(map), NULL);

out:
	kfree(map);
	return ret;
}

static int virtkvm_vfio_unmap_dma(struct virtkvm_vfio_container *container,
				  unsigned long arg)
{
	struct vfio_iommu_type1_dma_unmap *unmap;
	int ret = -ENOMEM;

	unmap = kzalloc(sizeof(*unmap), GFP_KERNEL_ACCOUNT);
	if (!unmap)
		goto out;

	ret = -EFAULT;
	if (copy_from_user(unmap, u64_to_user_ptr((u64)arg), sizeof(*unmap)))
		goto out;

	ret = -EINVAL;
	/* VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP is not yet supported */
	if (unmap->flags & ~(VFIO_DMA_UNMAP_FLAG_VADDR |
			     VFIO_DMA_UNMAP_FLAG_ALL))
		goto out;

	ret = virtio_kvm_send_command(container->handle, VIRTIO_VM_IOCTL,
				      VFIO_IOMMU_UNMAP_DMA, __pa(unmap), NULL);

	if (!ret && copy_to_user(u64_to_user_ptr((u64)arg), unmap, sizeof(*unmap)))
		ret = -EFAULT;

out:
	kfree(unmap);
	return ret;
}

static long virtkvm_vfio_ioctl(struct file *filp, unsigned int cmd,
			       unsigned long arg)
{
	struct virtkvm_vfio_container *container = filp->private_data;
	int ret = -ENOTTY;

	switch (cmd) {
	case VFIO_GET_API_VERSION: {
		ret = virtio_kvm_send_command(container->handle,
						VIRTIO_VM_IOCTL, cmd, 0, NULL);
		break;
	}
	case VFIO_CHECK_EXTENSION: {
		u64 data;
		ret = virtio_kvm_send_command(container->handle,
						VIRTIO_VM_IOCTL, cmd, arg, &data);
		if (ret == 0)
			ret = data;
		break;
	}
	case VFIO_SET_IOMMU: {
		ret = virtio_kvm_send_command(container->handle,
						VIRTIO_VM_IOCTL, cmd, arg, NULL);
		break;
	}
	case VFIO_IOMMU_GET_INFO: {
		struct vfio_iommu_type1_info __user *uinfo = u64_to_user_ptr((u64)arg);
		struct vfio_iommu_type1_info *info;
		u32 argsz;

		if (get_user(argsz, &uinfo->argsz))
			return -EFAULT;

		if (argsz < offsetofend(struct vfio_iommu_type1_info, iova_pgsizes) ||
		    argsz > VIRTKVM_VFIO_MAX_ARGSZ)
			return -EINVAL;

		info = kzalloc(argsz, GFP_KERNEL);
		ret = -ENOMEM;
		if (!info)
			break;

		if (copy_from_user(info, uinfo, argsz)) {
			ret = -EFAULT;
			kfree(info);
			break;
		}

		ret = virtio_kvm_send_command(container->handle,
						VIRTIO_VM_IOCTL, cmd,
						__pa(info), NULL);

		if (!ret && copy_to_user(uinfo, info, argsz))
			ret = -EFAULT;

		kfree(info);
		break;
	}
	case VFIO_IOMMU_MAP_DMA: {
		ret = virtkvm_vfio_map_dma(container, arg);
		break;
	}
	case VFIO_IOMMU_UNMAP_DMA: {
		ret = virtkvm_vfio_unmap_dma(container, arg);
		break;
	}
	default:
		break;
	}

	return ret;
}

static void virtkvm_vfio_container_release(struct kref *kref)
{
	struct virtkvm_vfio_container *container =
		container_of(kref, struct virtkvm_vfio_container, kref);
	int ret;

	ret = virtio_kvm_send_command_async(container->handle, VIRTIO_VM_CLOSE, 0, 0, NULL);
	WARN_ON_ONCE(ret);

	virtkvm_partition_put(container->part);
	kfree(container);
}

static int virtkvm_vfio_open(struct inode *inode, struct file *filp)
{
	struct miscdevice *misc = filp->private_data;
	struct virtio_kvm_partition *part =
		container_of(misc, struct virtio_kvm_partition, vfio_container_dev);
	struct virtkvm_vfio_container *container;
	u64 partition_id = part ? part->partition_id : 0;
	u64 data;
	int ret;

	container = kzalloc(sizeof(*container), GFP_KERNEL_ACCOUNT);
	if (!container)
		return -ENOMEM;

	if (part && part->vi) {
		mutex_lock(&part->vi->partition_lock);
		if (part->dying || list_empty(&part->link)) {
			mutex_unlock(&part->vi->partition_lock);
			kfree(container);
			return -ENODEV;
		}
		virtkvm_partition_get(part);
		mutex_unlock(&part->vi->partition_lock);
	}

	ret = virtio_kvm_send_command(-1, VIRTIO_VM_VFIO_OPEN, partition_id, 0, &data);
	if (ret) {
		virtkvm_partition_put(part);
		kfree(container);
		return ret;
	}

	INIT_LIST_HEAD(&container->group_list);
	kref_init(&container->kref);
	container->handle = data;
	container->partition_id = partition_id;
	container->part = part;

	filp->private_data = container;

	return 0;
}

static int virtkvm_vfio_release(struct inode *inode, struct file *filp)
{
	struct virtkvm_vfio_container *container = filp->private_data;

	filp->private_data = NULL;
	kref_put(&container->kref, virtkvm_vfio_container_release);

	return 0;
}

/* Container objects */
static const struct file_operations virtkvm_vfio_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = virtkvm_vfio_ioctl,
	.open = virtkvm_vfio_open,
	.release = virtkvm_vfio_release,
};

int virtkvm_partition_init_vfio(struct virtio_kvm_partition *part)
{
	u64 *groups;
	u64 num_groups = 0;
	int err, i;

	snprintf(part->vfio_container_name, sizeof(part->vfio_container_name),
		 "tachyon-%llu-vfio", part->partition_id);
	snprintf(part->vfio_container_nodename, sizeof(part->vfio_container_nodename),
		 "tachyon-%llu/vfio/vfio", part->partition_id);
	part->vfio_container_dev.minor = MISC_DYNAMIC_MINOR;
	part->vfio_container_dev.name = part->vfio_container_name;
	part->vfio_container_dev.nodename = part->vfio_container_nodename;
	part->vfio_container_dev.mode = 0666;
	part->vfio_container_dev.fops = &virtkvm_vfio_fops;

	err = misc_register(&part->vfio_container_dev);
	if (err)
		return err;

	err = virtio_kvm_send_command(-1, VIRTIO_VM_VFIO_GET_GROUPS,
				      part->partition_id, 0, &num_groups);
	if (err) {
		pr_warn("Failed to query VFIO groups for partition %llu: %d\n",
			part->partition_id, err);
		return 0;
	}

	if (num_groups == 0)
		return 0;

	groups = kmalloc_array(num_groups, sizeof(u64), GFP_KERNEL);
	if (!groups) {
		misc_deregister(&part->vfio_container_dev);
		return -ENOMEM;
	}

	err = virtio_kvm_send_command(-1, VIRTIO_VM_VFIO_GET_GROUPS,
				      part->partition_id, __pa(groups), &num_groups);
	if (err) {
		pr_warn("Failed to get VFIO groups for partition %llu from host: %d\n",
			part->partition_id, err);
		kfree(groups);
		return 0;
	}

	for (i = 0; i < num_groups; i++) {
		struct virtkvm_vfio_group *group;

		group = kzalloc(sizeof(*group), GFP_KERNEL);
		if (!group)
			continue;

		group->group_id = groups[i];
		group->partition_id = part->partition_id;
		group->part = part;
		kref_init(&group->kref);
		snprintf(group->name, sizeof(group->name),
			 "tachyon-%llu-vfio-%llu", part->partition_id, group->group_id);
		snprintf(group->nodename, sizeof(group->nodename),
			 "tachyon-%llu/vfio/%llu", part->partition_id, group->group_id);
		group->misc_dev.minor = MISC_DYNAMIC_MINOR;
		group->misc_dev.name = group->name;
		group->misc_dev.nodename = group->nodename;
		group->misc_dev.mode = 0666;
		group->misc_dev.fops = &virtkvm_vfio_group_fops;

		err = misc_register(&group->misc_dev);
		if (err) {
			kfree(group);
			continue;
		}

		list_add_tail(&group->link, &part->vfio_groups);
		pr_info("Registered VFIO group device /dev/%s for partition %llu\n",
			group->nodename, part->partition_id);
	}

	kfree(groups);
	return 0;
}

void virtkvm_partition_cleanup_vfio(struct virtio_kvm_partition *part)
{
	struct virtkvm_vfio_group *group, *tmp;

	list_for_each_entry_safe(group, tmp, &part->vfio_groups, link) {
		list_del(&group->link);
		misc_deregister(&group->misc_dev);
		kref_put(&group->kref, virtkvm_vfio_group_release_kref);
	}

	misc_deregister(&part->vfio_container_dev);
}

int virtkvm_vfio_init(struct virtkvm_info *vi)
{
	return 0;
}

void virtkvm_vfio_cleanup(struct virtkvm_info *vi)
{
}
