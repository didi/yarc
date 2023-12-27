#ifndef __TRAFFIC_MIRROR_CONTEXT_H_
#define __TRAFFIC_MIRROR_CONTEXT_H_

#include "common.h"
#include "errno.h"

struct file;
struct socket;
struct msghdr;
struct iov_iter;

// context between probe and retprobe
struct probe_ctx {
	__event_common;

	union {
		// inet_accept
		struct {
			struct socket *sock;
			struct file *file;
			struct socket *newsock;
			struct file *newfile;
		} accept;

		// inet_stream_connect
		struct {
			struct socket *sock;
			struct sockaddr *addr;
		} connect;

		// inet_sendmsg/inet_recvmsg
		struct {
			struct socket *sock;
			struct socket_info sockinfo;
			struct iov_iter iter;
		} sr;

		// go: runtime/newproc
		struct {
			u32 gover;
		} goproc;
	};

	// verifer does not allow saving bpf ctx into map,
	// put it on the last and decrease the value_size of map
	void *bpf_ctx;
};

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wint-conversion"
const int CONTEXT_VALUE_SIZE = (&((struct probe_ctx*)0)->bpf_ctx);
#pragma clang diagnostic pop

// bpf map for saving probe_ctx
// key is thread id
// value is struct probe_ctx *
struct bpf_map_def SEC("maps") ctx_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = CONTEXT_VALUE_SIZE,
	.max_entries = 1024,
};

static __always_inline
int save_context(u32 pid, struct probe_ctx *ctx)
{
	int err = bpf_map_update_elem(&ctx_map, &pid, ctx, BPF_ANY);
	if (err < 0) {
		return -1;
	}
	return 0;
}

static __always_inline
int read_context(u32 pid, struct probe_ctx *ctx)
{
	int err;
	void *valp = bpf_map_lookup_elem(&ctx_map, &pid);
	if (!valp) {
		return -1;
	}

	err = bpf_probe_read(ctx, CONTEXT_VALUE_SIZE, valp);
	if (err < 0) {
		return -2;
	}
	return 0;
}

static __always_inline
int delete_context(u32 pid)
{
	int err = bpf_map_delete_elem(&ctx_map, &pid);
	if (err < 0) {
		return -1;
	}
	return 0;
}

#endif // __TRAFFIC_MIRROR_CONTEXT_H_
