// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __VIRTIO_VM_INODE_H
#define __VIRTIO_VM_INODE_H

#include <linux/fs.h>

struct kvm_guest_memory_file;

int virtio_kvm_create_memory_anonfile(unsigned long size, u64 partition_id);
bool virtio_kvm_is_vkvmfs(struct file *filp);

int vkvmfs_offset_to_pa(struct file *filp, off_t offset, size_t size, unsigned long *pa);

#endif // __VIRTIO_VM_INODE_H
