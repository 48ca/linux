/* SPDX-License-Identifier: GPL-2.0-or-later */
#if !defined(__VIRTIO_VM_TRACE_H__) || defined(TRACE_HEADER_MULTI_READ)
#define __VIRTIO_VM_TRACE_H__

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM virtio_vm
#define TRACE_INCLUDE_FILE trace

TRACE_EVENT(virtio_vm_vcpu_run_entry,

	TP_PROTO(u64 handle, u32 vcpu_id),

	TP_ARGS(handle, vcpu_id),

	TP_STRUCT__entry(
		__field(u64, handle)
		__field(u32, vcpu_id)
	),

	TP_fast_assign(
		__entry->handle = handle;
		__entry->vcpu_id = vcpu_id;
	),

	TP_printk("handle=%llx vcpu_id=%u",
		  __entry->handle, __entry->vcpu_id)
);

TRACE_EVENT(virtio_vm_vcpu_run_exit,

	TP_PROTO(u64 handle, u32 vcpu_id, int ret),

	TP_ARGS(handle, vcpu_id, ret),

	TP_STRUCT__entry(
		__field(u64, handle)
		__field(u32, vcpu_id)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->handle = handle;
		__entry->vcpu_id = vcpu_id;
		__entry->ret = ret;
	),

	TP_printk("handle=%llx vcpu_id=%u ret=%d",
		  __entry->handle, __entry->vcpu_id, __entry->ret)
);

TRACE_EVENT(virtio_vm_ready,

	TP_PROTO(u64 handle),

	TP_ARGS(handle),

	TP_STRUCT__entry(
		__field(u64, handle)
	),

	TP_fast_assign(
		__entry->handle = handle;
	),

	TP_printk("handle=%llx", __entry->handle)
);

TRACE_EVENT(virtio_vm_cmd_int,

	TP_PROTO(u64 handle),

	TP_ARGS(handle),

	TP_STRUCT__entry(
		__field(u64, handle)
	),

	TP_fast_assign(
		__entry->handle = handle;
	),

	TP_printk("handle=%llx", __entry->handle)
);

TRACE_EVENT(virtio_vm_ioeventfd_add,

	TP_PROTO(u64 handle, u32 id),

	TP_ARGS(handle, id),

	TP_STRUCT__entry(
		__field(u64, handle)
		__field(u32, id)
	),

	TP_fast_assign(
		__entry->handle = handle;
		__entry->id = id;
	),

	TP_printk("handle=%llx id=%u", __entry->handle, __entry->id)
);

TRACE_EVENT(virtio_vm_ioeventfd_remove,

	TP_PROTO(u64 handle, u32 id),

	TP_ARGS(handle, id),

	TP_STRUCT__entry(
		__field(u64, handle)
		__field(u32, id)
	),

	TP_fast_assign(
		__entry->handle = handle;
		__entry->id = id;
	),

	TP_printk("handle=%llx id=%u", __entry->handle, __entry->id)
);

TRACE_EVENT(virtio_vm_ioeventfd_signal,

	TP_PROTO(u64 handle, u32 id),

	TP_ARGS(handle, id),

	TP_STRUCT__entry(
		__field(u64, handle)
		__field(u32, id)
	),

	TP_fast_assign(
		__entry->handle = handle;
		__entry->id = id;
	),

	TP_printk("handle=%llx id=%u", __entry->handle, __entry->id)
);

TRACE_EVENT(virtio_vm_vq_add,

	TP_PROTO(u64 handle, unsigned int operation, unsigned int oparg, unsigned long longarg),

	TP_ARGS(handle, operation, oparg, longarg),

	TP_STRUCT__entry(
		__field(u64, handle)
		__field(unsigned int, operation)
		__field(unsigned int, oparg)
		__field(unsigned long, longarg)
	),

	TP_fast_assign(
		__entry->handle = handle;
		__entry->operation = operation;
		__entry->oparg = oparg;
		__entry->longarg = longarg;
	),

	TP_printk("handle=%llx operation=%u oparg=%u longarg=%lx",
		  __entry->handle, __entry->operation, __entry->oparg, __entry->longarg)
);

TRACE_EVENT(virtio_vm_vq_remove,

	TP_PROTO(u64 handle, unsigned int operation, unsigned int oparg, unsigned long longarg, int status),

	TP_ARGS(handle, operation, oparg, longarg, status),

	TP_STRUCT__entry(
		__field(u64, handle)
		__field(unsigned int, operation)
		__field(unsigned int, oparg)
		__field(unsigned long, longarg)
		__field(int, status)
	),

	TP_fast_assign(
		__entry->handle = handle;
		__entry->operation = operation;
		__entry->oparg = oparg;
		__entry->longarg = longarg;
		__entry->status = status;
	),

	TP_printk("handle=%llx operation=%u oparg=%u longarg=%lx status=%d",
		  __entry->handle, __entry->operation, __entry->oparg, __entry->longarg, __entry->status)
);

TRACE_EVENT(virtio_vm_poll_start,

	TP_PROTO(bool empty),

	TP_ARGS(empty),

	TP_STRUCT__entry(
		__field(bool, empty)
	),

	TP_fast_assign(
		__entry->empty = empty;
	),

	TP_printk("empty=%d", __entry->empty)
);

TRACE_EVENT(virtio_vm_poll_stop,

	TP_PROTO(bool empty),

	TP_ARGS(empty),

	TP_STRUCT__entry(
		__field(bool, empty)
	),

	TP_fast_assign(
		__entry->empty = empty;
	),

	TP_printk("empty=%d", __entry->empty)
);

#endif /* __VIRTIO_VM_TRACE_H__ */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#include <trace/define_trace.h>
