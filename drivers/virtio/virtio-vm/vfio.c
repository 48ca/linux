#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/vfio.h>

#include "common.h"
#include "vfio.h"
#include "trace.h"

#undef pr_fmt
#define pr_fmt(fmt) "virtio-vm: vfio: " fmt

/* UAPI */
#define PCI_ADDRESS_LENGTH	(16)

struct virtkvm_assignable_device_entry {
	char address[PCI_ADDRESS_LENGTH];	/* "0000:00:00.0" */
	u32 l0_group;
};
struct virtkvm_assignable_device_table {
	int nent;
	struct virtkvm_assignable_device_entry entries[];
};

#define VIRTIO_VM_VFIO_OPEN		(64)
#define VIRTIO_VM_VFIO_GROUP_OPEN	(65)
/* TODO: Partly duplicative with VIRTIO_VM_EVENTFD_WRITE, VIRTIO_VM_STATS_READ */
#define VIRTIO_VM_VFIO_DEVICE_READ	(66)
#define VIRTIO_VM_VFIO_DEVICE_WRITE	(67)

/* TODO: Redefinitions from virtio-kvm */
#define VIRTIO_VM_CLOSE		(1)
#define VIRTIO_VM_IOCTL		(2)

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

/* virtkvm_vfio has a 1:1 relationship between groups and devices */
struct virtkvm_vfio_device {
	char			address[PCI_ADDRESS_LENGTH];
	u64			handle;

	struct xarray		irq_ctx;
};

struct virtkvm_vfio_container {
	struct kref		kref;
	struct list_head	group_list;
	u64			handle;
};

struct virtkvm_vfio_group {
	struct device		dev;
	struct cdev		cdev;
	int			l0_group;
	u64			handle;
	int			opened;
	int			device_fd_count;

	struct virtkvm_vfio_device	assigned_device;
	struct virtkvm_vfio_container	*container;
};

static struct virtkvm_vfio {
	struct class		*class;
	int			group_alloc;
	dev_t			group_devt;
} virtkvm_vfio;

/* Protects container <-> group binding */
static DEFINE_MUTEX(virtkvm_vfio_lock);

static void virtkvm_vfio_container_release(struct kref *kref);

/*
 * Device objects
 */
static int virtkvm_vfio_device_release(struct inode *inode, struct file *filp)
{
	struct virtkvm_vfio_device *device = filp->private_data;
	struct virtkvm_vfio_group *group = container_of(device, struct virtkvm_vfio_group, assigned_device);
	struct virtio_kvm_eventfd *evfd;
	unsigned long idx;
	int ret;

	group->device_fd_count--;
	put_device(&group->dev);

	ret = virtio_kvm_send_command_async(device->handle, VIRTIO_VM_CLOSE, 0, 0, NULL);
	WARN_ON_ONCE(ret);

	/* Pairs with kref_get in GET_DEVICE_FD */
	kref_put(&group->container->kref, virtkvm_vfio_container_release);

	xa_for_each(&device->irq_ctx, idx, evfd) {
		virtio_kvm_put_evfd(evfd);
	}

	return ret;
}

struct virtkvm_vfio_device_rw {		/* ABI */
	loff_t ppos;
	size_t count;
	char kbuf[];
};
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

static void vfio_device_vma_close(struct vm_area_struct *vma)
{
	struct file *filp = vma->vm_file;
	struct virtkvm_vfio_device *device = filp->private_data;
	u64 handle = (u64)device->handle;
	u64 phys_offset = (u64)vma->vm_private_data;
	int ret;

	ret = send_dev_munmap(handle, phys_offset, vma->vm_end - vma->vm_start);
	if (ret)
		pr_warn_once("Failed to unmap VMA: %llx\n", handle);
	virtio_vm_put_unused_phys_offset(phys_offset, vma->vm_end - vma->vm_start);
}

static const struct vm_operations_struct vfio_device_vm_ops = {
	.close = vfio_device_vma_close,
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
				       int count)
{
	int i;

	for (i = 0; i < count; ++i)
		if (evfds[i])
			virtio_kvm_put_evfd(evfds[i]);

	kfree(evfds);
}

static int vfio_translate_eventfds(struct virtkvm_vfio_device *device,
				   struct vfio_irq_set *irqs,
				   struct virtio_kvm_eventfd ***out_evfds)
{

	struct virtio_kvm_eventfd **evfds;
	u64 *handles;
	int *fds;
	int ret = 0;
	int i;

	if (!((irqs->flags & VFIO_IRQ_SET_DATA_TYPE_MASK) &
	      VFIO_IRQ_SET_DATA_EVENTFD))
		return 0;

	evfds = kzalloc(irqs->count * sizeof(*evfds), GFP_KERNEL);
	if (!evfds)
		return -ENOMEM;

	fds = (int *)irqs->data;
	handles = (u64 *)irqs->data;

	for (i = 0; i < irqs->count; ++i) {
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

		evfd = virtio_kvm_get_evfd(eventfd);
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

static long virtkvm_vfio_device_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct virtkvm_vfio_device *device = filp->private_data;
	int ret = -EOPNOTSUPP;

	switch (cmd) {
	case VFIO_DEVICE_RESET: {
		ret = virtio_kvm_send_command(device->handle, VIRTIO_VM_IOCTL, cmd, 0, NULL);
		break;
	}
	case VFIO_DEVICE_GET_INFO: {
		struct vfio_device_info __user *udev = u64_to_user_ptr((u64)arg);
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
		WARN_ON(ret);

		if (copy_to_user(udev, dev, argsz))
			ret = -EFAULT;

		kfree(dev);
		break;
	}
	case VFIO_DEVICE_GET_REGION_INFO: {
		struct vfio_region_info __user *ureg = u64_to_user_ptr((u64)arg);
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

		if (copy_to_user(ureg, reg, argsz))
			ret = -EFAULT;

		kfree(reg);
		break;
	}
	case VFIO_DEVICE_GET_IRQ_INFO: {
		struct vfio_irq_info __user *uirq = u64_to_user_ptr((u64)arg);
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

		if (copy_to_user(uirq, irq, argsz))
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
static const struct file_operations virtkvm_vfio_group_fops;

static void virtkvm_vfio_group_dev_release(struct device *dev)
{
	struct virtkvm_vfio_group *group = container_of(dev, struct virtkvm_vfio_group, dev);
	kfree(group);
}

static int virtkvm_vfio_create_group(struct virtkvm_assignable_device_entry *device)
{
	struct virtkvm_vfio_group *group;
	int num;

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return -ENOMEM;

	num = virtkvm_vfio.group_alloc++;

	device_initialize(&group->dev);
	group->dev.devt = MKDEV(MAJOR(virtkvm_vfio.group_devt), num);
	group->dev.class = virtkvm_vfio.class;
	group->dev.release = virtkvm_vfio_group_dev_release;
	cdev_init(&group->cdev, &virtkvm_vfio_group_fops);
	group->cdev.owner = THIS_MODULE;

	dev_set_name(&group->dev, "group%d", num);
	cdev_device_add(&group->cdev, &group->dev);

	group->l0_group = device->l0_group;
	pr_info("virtio-vm: vfio: Device %s group %d, major:minor %d:%d\n",
		device->address, num, MAJOR(group->dev.devt),
		MINOR(group->dev.devt));
	/* TODO: Generate udev event here? */

	memcpy(group->assigned_device.address, device->address, PCI_ADDRESS_LENGTH);
	group->opened = 0;

	return 0;
}

static int virtkvm_vfio_group_open(struct inode *inode, struct file *filp)
{
	struct virtkvm_vfio_group *group =
		container_of(inode->i_cdev, struct virtkvm_vfio_group, cdev);
	u64 data;
	int ret;

	guard(mutex)(&virtkvm_vfio_lock);

	if (group->opened)
		return -EBUSY;

	ret = virtio_kvm_send_command(-1,
					VIRTIO_VM_VFIO_GROUP_OPEN, group->l0_group, 0, &data);
	if (WARN_ON_ONCE(ret))
		return ret;

	group->opened = 1;
	group->handle = data;
	group->container = NULL;
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
	}

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

	BUG_ON(group->opened == 0);

	container = fd_file(f)->private_data;

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
	return -1;
}

static long virtkvm_vfio_group_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct virtkvm_vfio_group *group = filp->private_data;
	void __user *uarg = (void __user *) arg;
	int ret = -ENOSYS;

	guard(mutex)(&virtkvm_vfio_lock);

	switch (cmd) {
	case VFIO_GROUP_GET_DEVICE_FD: {
		struct virtkvm_vfio_container *container;
		struct file *filep;
		int fdno;
		u64 data;

		container = group->container;

		if (!container) {
			ret = -EINVAL;
			break;
		}

		/* check arg == group->assigned_device.address */

		fdno = get_unused_fd_flags(O_CLOEXEC);
		if (fdno < 0) {
			ret = fdno;
			break;
		}

		filep = anon_inode_getfile_fmode("[virtkvm-vfio-device]", &virtkvm_vfio_device_fops,
				&group->assigned_device, O_RDWR, FMODE_PREAD | FMODE_PWRITE);
		if (IS_ERR(filep)) {
			put_unused_fd(fdno);
			ret = PTR_ERR(filep);
			break;
		}

		/* TODO: Use the argument the user passed instead of
		 * group->assigned_device.address.
		 */
		ret = virtio_kvm_send_command(group->handle, VIRTIO_VM_IOCTL,
						VFIO_GROUP_GET_DEVICE_FD,
						__pa(&group->assigned_device.address),
						&data);
		if (ret) {
			fput(filep);
			put_unused_fd(fdno);
			break;
		}

		group->assigned_device.handle = data;

		kref_get(&container->kref);
		get_device(&group->dev);
		group->device_fd_count++;
		xa_init(&group->assigned_device.irq_ctx);

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

		if (copy_to_user(ug, g, argsz))
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

	if (copy_to_user(u64_to_user_ptr((u64)arg), unmap, sizeof(*unmap)))
		ret = -EFAULT;

out:
	kfree(unmap);
	return ret;
}

static long virtkvm_vfio_ioctl(struct file *filp, unsigned int cmd,
			       unsigned long arg)
{
	struct virtkvm_vfio_container *container = filp->private_data;
	int ret = 0;

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

		if (copy_to_user(uinfo, info, argsz))
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

static void virtkvm_vfio_container_release(struct kref *kref) {
	struct virtkvm_vfio_container *container =
		container_of(kref, struct virtkvm_vfio_container, kref);
	int ret;

	ret = virtio_kvm_send_command_async(container->handle, VIRTIO_VM_CLOSE, 0, 0, NULL);
	WARN_ON_ONCE(ret);

	kfree(container);
}

static int virtkvm_vfio_open(struct inode * inode, struct file *filp)
{
	struct virtkvm_vfio_container *container;
	u64 data;
	int ret;

	printk(KERN_EMERG "virtkvm_vfio_open\n");
	container = kzalloc(sizeof(*container), GFP_KERNEL_ACCOUNT);
	if (!container)
		return -ENOMEM;

	ret = virtio_kvm_send_command(-1, VIRTIO_VM_VFIO_OPEN, 0, 0, &data);
	if (ret) {
		kfree(container);
		return -ENOSYS;
	}

	/* |data| is an L0 handle referencing /dev/vfio/vfio */

	INIT_LIST_HEAD(&container->group_list);
	kref_init(&container->kref);
	container->handle = data;

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

struct miscdevice virtkvm_vfio_dev = {
	.minor = VFIO_MINOR,
	.name = "vfio",
	.fops = &virtkvm_vfio_fops,
	.nodename = "vfio/vfio",
};

static int virtkvm_add_ivb_cbdma(void) {
	struct virtkvm_assignable_device_entry e;

	sprintf(e.address, "0000:00:04.0");
	e.l0_group = 22;  // IVB CBDMA ch0

	return virtkvm_vfio_create_group(&e);
}

int virtkvm_vfio_init(struct virtkvm_info *vi)
{
	int ret;

	virtkvm_vfio.class = class_create("vfio");
	if (IS_ERR(virtkvm_vfio.class))
		return PTR_ERR(virtkvm_vfio.class);

	ret = alloc_chrdev_region(&virtkvm_vfio.group_devt, 0, MINORMASK + 1, "vfio");
	if (ret)
		goto destroy_class;

	ret = misc_register(&virtkvm_vfio_dev);
	if (ret)
		goto err;

	/* XXX: Get table from L0 */
	ret = virtkvm_add_ivb_cbdma();
	if (ret)
		pr_err("Failed to add ivybridge CBDMA device: %d", ret);

	return 0;

err:
	unregister_chrdev_region(virtkvm_vfio.group_devt, MINORMASK + 1);
destroy_class:
	class_destroy(virtkvm_vfio.class);
	return ret;
}

void virtkvm_vfio_cleanup(struct virtkvm_info *vi)
{
	misc_deregister(&virtkvm_vfio_dev);
	unregister_chrdev_region(virtkvm_vfio.group_devt, MINORMASK + 1);
	class_destroy(virtkvm_vfio.class);
}
