#ifndef __TRAFFIC_MIRROR_DEBUG_H_
#define __TRAFFIC_MIRROR_DEBUG_H_

#include "common.h"
#include "context.h"

enum debug_event_type {
	// debug
	DEBUG_LEVEL              = 0x00,
	DEBUG_INET_ACCEPT_ENTRY  = 0x01,
	DEBUG_INET_ACCEPT_EXIT   = 0x02,
	DEBUG_INET_CONNECT_ENTRY = 0x03,
	DEBUG_INET_CONNECT_EXIT  = 0x04,
	DEBUG_SOCK_SENDMSG_ENTRY = 0x05,
	DEBUG_SOCK_SENDMSG_EXIT  = 0x06,
	DEBUG_SOCK_RECVMSG_ENTRY = 0x07,
	DEBUG_SOCK_RECVMSG_EXIT  = 0x08,
	DEBUG_FILP_CLOSE_ENTRY   = 0x09,
	DEBUG_FILP_CLOSE_EXIT    = 0x0A,
	DEBUG_GO_NEWPROC_ENTRY   = 0x0B,
	DEBUG_GO_NEWPROC_OFFSET  = 0x0C,
	DEBUG_GO_NEWPROC_EXIT    = 0x0D,
	DEBUG_SOCK_DATA_OUTPUT   = 0x0E,

	// info
	INFO_LEVEL = 0x40,
	INFO_STACK = 0x41,

	// warning
	WARN_LEVEL = 0x80,

	// error
	ERROR_LEVEL = 0xC0,
	// bpf_helpers
	ERROR_BPF_PERF_EVENT_OUTPUT = 0xC1,
	ERROR_BPF_PROBE_READ        = 0xC2,
	ERROR_BPF_MAP_LOOKUP_ELEM   = 0xC3,
	// others
	ERROR_LOGICAL            = 0xD1,
	ERROR_DATA_TRUNCATED     = 0xD2,
	ERROR_IOV_ITER_TYPE      = 0xD3,
	ERROR_COPY_FROM_IOV_ITER = 0xD4,
	ERROR_SAVE_CONTEXT       = 0xD5,
	ERROR_READ_CONTEXT       = 0xD6,
	ERROR_DELETE_CONTEXT     = 0xD7,
	ERROR_READ_SOCKET_INFO   = 0xD8,
	ERROR_UNKNOWN_GO_VERSION = 0xD9,
	ERROR_MSG_NAME_LEN       = 0xDA,
};

struct debug_event {
	__event_common;
	u64 data1;
	u64 data2;
	u64 data3;
};

static __always_inline
void debug_event_output(struct probe_ctx *ctx, u16 type,
				u64 arg1, u64 arg2, u64 arg3)
{
	struct debug_event event = {
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_DEBUG,
		.type = type,
		.tgid = ctx->tgid,
		.pid = ctx->pid,
		.rid = ctx->rid,
		.data1 = arg1,
		.data2 = arg2,
		.data3 = arg3,
	};
	int err = bpf_perf_event_output(ctx->bpf_ctx, &perf_events_map,
				BPF_F_CURRENT_CPU, &event, sizeof(event));
	if (err) {
		bpf_printk("debug_event_output error: %d\n", err);
	}
}

void report_stack(struct probe_ctx *ctx, int kern, int user) {
	u64 flags = BPF_F_FAST_STACK_CMP;
	long kernstack = 0;
	long userstack = 0;

	if (!kern && !user) {
		return;
	}

	if (kern) {
		kernstack = bpf_get_stackid(ctx->bpf_ctx, &stack_map, flags);
		if (kernstack < 0) {
			bpf_printk("bpf_get_stackid kern failed: %d\n", kernstack);
			return;
		}
	}

	if (user) {
		flags = BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP;
		userstack = bpf_get_stackid(ctx->bpf_ctx, &stack_map, flags);
		if (userstack < 0) {
			bpf_printk("bpf_get_stackid user failed: %d\n", userstack);
			return;
		}
	}

	debug_event_output(ctx, INFO_STACK, kernstack, userstack, 0);
}

static __always_inline
void trace_log(struct probe_ctx *ctx, u16 type, u64 arg1, u64 arg2, u64 arg3) {
#ifdef TRACE_BPF_LOG
	switch (type) {
	case DEBUG_INET_ACCEPT_ENTRY:
		bpf_printk("yarc: inet_accept entry, tgid %d\n", ctx->tgid);
		break;
	case DEBUG_INET_ACCEPT_EXIT:
		bpf_printk("yarc: inet_accept exit, tgid %d, retval %d\n", ctx->tgid, arg1);
		break;
	case DEBUG_INET_CONNECT_ENTRY:
		bpf_printk("yarc: inet_stream_connect entry, tgid %d\n", ctx->tgid);
		break;
	case DEBUG_INET_CONNECT_EXIT:
		bpf_printk("yarc: inet_stream_connect exit, tgid %d, retval %d\n", ctx->tgid, arg1);
		break;
	case DEBUG_SOCK_SENDMSG_ENTRY:
		bpf_printk("yarc: sock_sendmsg entry, tgid %d\n", ctx->tgid);
		break;
	case DEBUG_SOCK_SENDMSG_EXIT:
		bpf_printk("yarc: sock_sendmsg exit, tgid %d, retval %d\n", ctx->tgid, arg1);
		break;
	case DEBUG_SOCK_RECVMSG_ENTRY:
		bpf_printk("yarc: sock_recvmsg entry, tgid %d\n", ctx->tgid);
		break;
	case DEBUG_SOCK_RECVMSG_EXIT:
		bpf_printk("yarc: sock_recvmsg exit, tgid %d, retval %d\n", ctx->tgid, arg1);
		break;
	case DEBUG_FILP_CLOSE_ENTRY:
		bpf_printk("yarc: filp_close entry, tgid %d\n", ctx->tgid);
		break;
	case DEBUG_FILP_CLOSE_EXIT:
		bpf_printk("yarc: filp_close entry, tgid %d, retval %d\n", ctx->tgid, arg1);
		break;
	case DEBUG_GO_NEWPROC_ENTRY:
		bpf_printk("yarc: go runtime.newproc1 entry, tgid %d\n", ctx->tgid);
		break;
	case DEBUG_GO_NEWPROC_OFFSET:
		bpf_printk("yarc: go runtime.newproc1 offset, tgid %d\n", ctx->tgid);
		break;
	case DEBUG_GO_NEWPROC_EXIT:
		bpf_printk("yarc: go runtime.newproc1 exit, tgid %d\n", ctx->tgid);
		break;
	case DEBUG_SOCK_DATA_OUTPUT:
		bpf_printk("yarc: sock data output, tgid %d, offset %d, len %d\n", ctx->tgid, arg1, arg2);
		break;
	case ERROR_BPF_PERF_EVENT_OUTPUT:
		bpf_printk("yarc: bpf_perf_event_output failed, tgid %d, line %d, err %d\n", ctx->tgid, arg1, arg2);
		break;
	case ERROR_BPF_PROBE_READ:
		bpf_printk("yarc: bpf_probe_read failed, tgid %d, line %d, err %d\n", ctx->tgid, arg1, arg2);
		break;
	case ERROR_BPF_MAP_LOOKUP_ELEM:
		bpf_printk("yarc: bpf_map_lookup_elem failed, tgid %d, line %d\n", ctx->tgid, arg1);
		break;
	case ERROR_LOGICAL:
		bpf_printk("yarc: logical error, tgid %d, line %d, err %d\n", ctx->tgid, arg1, arg2);
		break;
	case ERROR_DATA_TRUNCATED:
		bpf_printk("yarc: data truncated, tgid %d, offset %d, remain %d\n", ctx->tgid, arg1, arg2);
		break;
	case ERROR_IOV_ITER_TYPE:
		bpf_printk("yarc: unkown iov_iter type %d, tgid %d, line %d\n", arg2, ctx->tgid, arg1);
		break;
	case ERROR_COPY_FROM_IOV_ITER:
		bpf_printk("yarc: copy from iov_iter failed, tgid %d, line %d, err %d\n", ctx->tgid, arg1, arg2);
		break;
	case ERROR_SAVE_CONTEXT:
		bpf_printk("yarc: save context failed, tgid %d, line %d\n", ctx->tgid, arg1);
		break;
	case ERROR_READ_CONTEXT:
		bpf_printk("yarc: read context failed, tgid %d, line %d\n", ctx->tgid, arg1);
		break;
	case ERROR_DELETE_CONTEXT:
		bpf_printk("yarc: delete context failed, tgid %d, line %d\n", ctx->tgid, arg1);
		break;
	case ERROR_READ_SOCKET_INFO:
		bpf_printk("yarc: read socket info failed, tgid %d, line %d\n", ctx->tgid, arg1);
		break;
	case ERROR_UNKNOWN_GO_VERSION:
		bpf_printk("yarc: unrecognized go version %d, tgid %d, line %d\n", arg2, ctx->tgid, arg1);
		break;
	case ERROR_MSG_NAME_LEN:
		bpf_printk("yarc: unrecognized msg_namelen, len %d, tgid %d, line %d\n", arg2, ctx->tgid, arg1);
		break;
	default:
		bpf_printk("yarc: unknown type %d, tgid %d\n", type, ctx->tgid);
		break;
	}
#endif // TRACE_BPF_LOG
}

static __always_inline __attribute__((unused))
void tm_err3(struct probe_ctx *ctx, u16 type, u64 arg1, u64 arg2, u64 arg3)
{
	trace_log(ctx, type, arg1, arg2, arg3);
	debug_event_output(ctx, type, arg1, arg2, arg3);
}

static __always_inline
void tm_err2(struct probe_ctx *ctx, u16 type, u64 arg1, u64 arg2)
{
	trace_log(ctx, type, arg1, arg2, 0);
	debug_event_output(ctx, type, arg1, arg2, 0);
}

static __always_inline
void tm_err(struct probe_ctx *ctx, u16 type, u64 arg1)
{
	trace_log(ctx, type, arg1, 0, 0);
	debug_event_output(ctx, type, arg1, 0, 0);
}

#ifdef DEBUG

static __always_inline __attribute__((unused))
void tm_dbg3(struct probe_ctx *ctx, u16 type, u64 arg1, u64 arg2, u64 arg3)
{
	trace_log(ctx, type, arg1, arg2, arg3);
	debug_event_output(ctx, type, arg1, arg2, arg3);
}

static __always_inline
void tm_dbg2(struct probe_ctx *ctx, u16 type, u64 arg1, u64 arg2)
{
	trace_log(ctx, type, arg1, arg2, 0);
	debug_event_output(ctx, type, arg1, arg2, 0);
}

static __always_inline
void tm_dbg(struct probe_ctx *ctx, u16 type, u64 arg1)
{
	trace_log(ctx, type, arg1, 0, 0);
	debug_event_output(ctx, type, arg1, 0, 0);
}

#else

static __always_inline
void tm_dbg(struct probe_ctx *ctx, u16 type, u64 arg1)
{
}

static __always_inline
void tm_dbg2(struct probe_ctx *ctx, u16 type, u64 arg1, u64 arg2)
{
}

static __always_inline __attribute__((unused))
void tm_dbg3(struct probe_ctx *ctx, u16 type, u64 arg1, u64 arg2, u64 arg3)
{
}

#endif // DEBUG

#endif // __TRAFFIC_MIRROR_DEBUG_H_
