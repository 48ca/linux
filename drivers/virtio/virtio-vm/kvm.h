// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __VIRTIO_KVM_H
#define __VIRTIO_KVM_H

#include <linux/mm.h>
#include <linux/types.h>
#include <uapi/linux/kvm.h>
#include <linux/hashtable.h>

#define MAX_VCPUS 1024

// Execution States (Bits 0-3)
#define STATE_IDLE           0x0
#define STATE_RUN_REQUESTED  0x1
#define STATE_COMPLETED      0x2
#define STATE_MASK           0xf

// Status Flags (Bits 4-7)
#define FLAG_HOST_POLLING    0x10

struct per_vcpu_state {
	u32 state;        /* Atomic field for synchronization */
	s32 status;       /* Return code from KVM_RUN */
	u8 padding[56];   /* Pad to 64 bytes */
} __aligned(64);

struct vcpu_shared_memory {
	struct per_vcpu_state vcpus[MAX_VCPUS];
};

struct virtio_kvm_ioeventfd {
	struct kvm_ioeventfd kvm;
	u64 fd_handle;
};

struct virtio_kvm_irqfd {
	struct kvm_irqfd kvm;
	u64 fd_handle;
	u64 resamplefd_handle;
};

int virtkvm_kvm_init(struct virtkvm_info *vi);
void virtkvm_kvm_cleanup(struct virtkvm_info *vi);
void virtio_kvm_eventfd_poll_done(struct virtio_kvm_poll *poll);

#endif /* __VIRTIO_KVM_H */
