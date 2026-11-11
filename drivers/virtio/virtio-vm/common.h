#ifndef __VIRTIO_VM_COMMON_H
#define __VIRTIO_VM_COMMON_H

#include <linux/refcount.h>
#include <linux/rcupdate.h>
#include <linux/eventfd.h>
#include <linux/maple_tree.h>
#include <linux/hashtable.h>
#include <linux/miscdevice.h>

#define VIRTIO_VM_OPEN			(0)
#define VIRTIO_VM_CLOSE			(1)
#define VIRTIO_VM_IOCTL			(2)
#define VIRTIO_VM_CMD_INT		(3)
#define VIRTIO_VM_DEVICE_MMAP		(4)
#define VIRTIO_VM_DEVICE_MUNMAP		(5)
#define VIRTIO_VM_MEMORY_FILE_CREATE	(6)
#define VIRTIO_VM_MEMORY_FILE_DELETE	(7)
#define VIRTIO_VM_EVENTFD_GET		(8)
#define VIRTIO_VM_EVENTFD_PUT		(9)
#define VIRTIO_VM_EVENTFD_WRITE		(10)
#define VIRTIO_VM_EVENTFD_POLL		(11)
#define VIRTIO_VM_FILE_IO		(12)
#define VIRTIO_VM_READY			(13)
#define VIRTIO_VM_SET_RUN_NOTIFY	(14)
#define VIRTIO_VM_VFIO_OPEN		(64)
#define VIRTIO_VM_VFIO_GROUP_OPEN	(65)
#define VIRTIO_VM_VFIO_DEVICE_READ	(66)
#define VIRTIO_VM_VFIO_DEVICE_WRITE	(67)
#define VIRTIO_VM_VFIO_GET_GROUPS	(68)

#define VIRTIO_VM_FILEIO_READ		(1)
#define VIRTIO_VM_FILEIO_WRITE		(2)

#define VIRTIO_VM_IO 0xAF
#define VIRTIO_VM_IOC_CREATE_MEMORY_FILE _IO(VIRTIO_VM_IO, 0x0)

#define TACHYON_CTRL_IO 0xAE
#define TACHYON_IOC_CREATE_PARTITION _IO(TACHYON_CTRL_IO, 0x01)
#define TACHYON_IOC_DESTROY_PARTITION _IO(TACHYON_CTRL_IO, 0x02)

#define BAR_GUEST_MEM_ALIGNMENT_ORDER PUD_SHIFT /* 1GB */

#define INVALID_PHYS_OFFSET (~0ULL)

#define INVALID_HANDLE (~0ULL)

extern struct workqueue_struct *eventfd_cleanup_wq;

struct virtio_kvm_req {
	__le64	handle;
	__le64	operation;
	__le64	arg;
	__le64	longarg;
} __attribute__((packed));

struct virtio_kvm_resp {
	__le64	status;
	__le64	data;
	__le64	pad;
} __attribute__((packed));

#define VIRTIO_KVM_POLL_BATCH (1)
struct virtio_kvm_poll {
	__le64 status;
	__le64 handle[VIRTIO_KVM_POLL_BATCH];
	__le64 vals[VIRTIO_KVM_POLL_BATCH];
} __attribute__((packed));

_Static_assert(sizeof(struct virtio_kvm_resp) == sizeof(struct virtio_kvm_poll),
		"sizeof(virtio_kvm_resp) must match sizeof(virtio_kvm_poll)");

struct virtio_kvm_reqresp {
	struct virtio_kvm_req req;
	union {
		struct virtio_kvm_resp resp;
		struct virtio_kvm_poll poll;
	};
};

struct virtkvm_cmd {
	struct virtio_kvm_reqresp r;
	struct completion acked;
	bool free_on_done;
};

struct virtio_kvm_partition;

struct virtio_kvm_eventfd {
	struct hlist_node hnode;
	struct eventfd_ctx *ctx;
	u64 partition_id;
	struct virtio_kvm_partition *part;
	u64 handle;	/* L0 handle */
	u32 id;		/* L1 synthetic ID */
	/* If set, called on signal instead of signalling ctx (ctx is NULL). */
	void (*notify)(struct virtio_kvm_eventfd *evfd);
	void *priv;
	refcount_t refcnt;
	struct rcu_head rcu;
};

struct virtkvm_alloc_info {
	struct maple_tree mt;
	unsigned long range_size;
};

struct virtkvm_info {
	struct virtqueue *vq;
	char name[25];
	int index;

	resource_size_t phys_start;
	resource_size_t phys_end;

	/* Synchronizes virtqueue */
	spinlock_t virtkvm_lock;

	struct work_struct poll_refill;
	atomic_t poll_pending;
	struct xarray ioeventfds;

	DECLARE_HASHTABLE(evfd_hash, 8);
	struct ida evfd_ida;
	spinlock_t evfd_lock;

	struct virtkvm_alloc_info allocinfo;

	spinlock_t vcpu_lock;
	struct list_head active_vcpus;
	wait_queue_head_t vcpu_poll_wait;
	atomic_t vcpu_scan_pending;
	atomic_t nr_polled_vms;		/* VMs without a run-completion notifier */
	struct task_struct *polling_thread;
	wait_queue_head_t vq_wait;
	bool vq_full;

	struct list_head partitions;
	struct mutex partition_lock;
};

struct virtio_kvm_partition {
	u64 partition_id;
	char name[64];
	char nodename[64];
	struct miscdevice misc_dev;
	struct miscdevice vfio_container_dev;
	char vfio_container_name[64];
	char vfio_container_nodename[64];
	struct list_head vfio_groups;
	struct list_head link;
	struct virtkvm_info *vi;
	refcount_t refcnt;
	bool dying;
};

void virtkvm_partition_get(struct virtio_kvm_partition *part);
void virtkvm_partition_put(struct virtio_kvm_partition *part);
struct virtio_kvm_partition *virtkvm_partition_get_by_id(struct virtkvm_info *vi, u64 partition_id);

int virtkvm_partition_create(struct virtkvm_info *vi, u64 partition_id);
int virtkvm_partition_destroy(struct virtkvm_info *vi, u64 partition_id);
void virtkvm_partitions_cleanup(struct virtkvm_info *vi);

extern struct virtkvm_info *vi_device;

u64 virtio_vm_get_unused_phys_offset(u64 size, int alignment_order);
void virtio_vm_put_unused_phys_offset(u64 offset, u64 size);

enum virtio_command_mode {
	COMMAND_NORMAL = 0,
	COMMAND_INTERRUPTIBLE = 1,
	COMMAND_ASYNC = 2,
};

long __virtio_kvm_send_command(struct virtkvm_cmd *cmd, u64 handle,
			       unsigned int operation, u64 oparg,
			       unsigned long longarg, u64 *data_out,
			       enum virtio_command_mode mode);
int virtio_kvm_send_command(u64 handle, unsigned int operation,
			    u64 oparg, unsigned long longarg,
			    u64 *data_out);
int virtio_kvm_send_command_async(u64 handle, unsigned int operation,
				  u64 oparg, unsigned long longarg,
				  u64 *data_out);
int virtio_kvm_send_command_ucopy(u64 handle, unsigned int operation,
				  unsigned int ioctl, unsigned long arg, size_t size,
				  u64 *data);
int __virtio_kvm_send_command_ucopy(u64 handle, unsigned int operation, unsigned int ioctl,
				    unsigned long arg, size_t size, u64 *data,
				    int always_copy);
int virtio_kvm_send_command_ucopy_async(u64 handle, unsigned int operation,
					unsigned int ioctl, unsigned long arg,
					size_t size);
struct virtio_vm_mmap_region {
	refcount_t refcnt;
	u64 handle;
	u64 phys_offset;
	size_t size;
};

void virtio_vm_vma_open(struct vm_area_struct *vma);
void virtio_vm_vma_close(struct vm_area_struct *vma);
int virtio_vm_vma_may_split(struct vm_area_struct *vma, unsigned long addr);

int virtio_kvm_generic_mmap(u64 handle, struct vm_area_struct *vma,
			    const struct vm_operations_struct *vm_ops);

int translate_va_to_pa(unsigned long va, unsigned long *phys_addr, size_t size);

bool virtio_kvm_is_gfile(struct file *filp);

ssize_t virtio_kvm_file_read(u64 handle, char __user *user_buffer,
			     size_t size, loff_t *offset);
ssize_t virtio_kvm_file_write(u64 handle, const char __user *user_buffer,
			      size_t size, loff_t *offset);
long send_dev_munmap(u64 handle, unsigned long phys_offset, unsigned long size);

struct virtio_kvm_eventfd *virtio_kvm_get_evfd(u64 partition_id, struct eventfd_ctx *ctx);
void virtio_kvm_put_evfd(struct virtio_kvm_eventfd *evfd);
struct virtio_kvm_eventfd *
virtio_kvm_get_notify_evfd(u64 partition_id,
			   void (*notify)(struct virtio_kvm_eventfd *evfd),
			   void *priv);

#endif /* __VIRTIO_VM_COMMON_H */
