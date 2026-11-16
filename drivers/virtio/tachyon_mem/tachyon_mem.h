/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_TACHYON_MEM_H
#define _UAPI_LINUX_TACHYON_MEM_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define TACHYON_MEM_PTE_PRESENT		(1ULL << 0)
#define TACHYON_MEM_PTE_WRITABLE	(1ULL << 1)
#define TACHYON_MEM_PFN_SHIFT		12
#define TACHYON_MEM_PFN_MASK		(((1ULL << 52) - 1) & ~((1ULL << TACHYON_MEM_PFN_SHIFT) - 1))

struct tachyon_mem_l1_region {
	__u64 l1_gpa;
	__u64 size;
	__u64 hva;
};

struct tachyon_mem_set_l1_regions {
	__u32 count;
	__u32 pad;
	__u64 regions_ptr; /* struct tachyon_mem_l1_region __user * */
};

struct tachyon_mem_create_slot {
	__u64 size;
	__u64 table_hva;
	__u64 table_size;
};

struct tachyon_mem_invalidate {
	__u64 offset;
	__u64 size;
};

#define TACHYON_MEM_IOC_MAGIC		0xB0
#define TACHYON_MEM_SET_L1_REGIONS	_IOW(TACHYON_MEM_IOC_MAGIC, 0x01, struct tachyon_mem_set_l1_regions)
#define TACHYON_MEM_CREATE_SLOT		_IOW(TACHYON_MEM_IOC_MAGIC, 0x02, struct tachyon_mem_create_slot)
struct tachyon_mem_create_slot_ex {
	__u64 size;
	__u64 table_hva;
	__u64 table_size;
	__u64 tag;
};

struct tachyon_mem_fault_req {
	__u64 tag;
	__u64 offset;
	__u64 seq;
};

#define TACHYON_MEM_INVALIDATE		_IOW(TACHYON_MEM_IOC_MAGIC, 0x03, struct tachyon_mem_invalidate)
#define TACHYON_MEM_CREATE_SLOT_EX	_IOW(TACHYON_MEM_IOC_MAGIC, 0x04, struct tachyon_mem_create_slot_ex)
#define TACHYON_MEM_GET_FAULT		_IOR(TACHYON_MEM_IOC_MAGIC, 0x05, struct tachyon_mem_fault_req)
#define TACHYON_MEM_ACK_FAULT		_IOW(TACHYON_MEM_IOC_MAGIC, 0x06, struct tachyon_mem_fault_req)

#endif /* _UAPI_LINUX_TACHYON_MEM_H */
