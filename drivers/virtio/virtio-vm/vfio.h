// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __VIRTIO_VM_VFIO_H
#define __VIRTIO_VM_VFIO_H

struct virtio_kvm_partition;

int virtkvm_partition_init_vfio(struct virtio_kvm_partition *part);
void virtkvm_partition_cleanup_vfio(struct virtio_kvm_partition *part);

int virtkvm_vfio_init(struct virtkvm_info *vi);
void virtkvm_vfio_cleanup(struct virtkvm_info *vi);

bool virtio_kvm_is_vfio_device(const struct vm_area_struct *vma);

#endif /* __VIRTIO_VM_VFIO_H */
