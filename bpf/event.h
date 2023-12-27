#ifndef __TRAFFIC_MIRROR_EVENT_H_
#define __TRAFFIC_MIRROR_EVENT_H_

#include "common.h"

enum sock_event_type {
	EVENT_SOCK_SENDMSG = 1,
	EVENT_SOCK_RECVMSG = 2,
	EVENT_SOCK_CLOSE   = 3,
	EVENT_SOCK_ACCEPT  = 4,
	EVENT_SOCK_CONNECT = 5,
	EVENT_SOCK_INFO    = 6,
	EVENT_GO_NEWPROC   = 11,
};

enum sock_event_flags {
	FLAGS_SOCK_DATA_MORE      = 1 << 0,
	FLAGS_SOCK_DATA_TRUNCATED = 1 << 1,
	FLAGS_SOCK_DATA_RESERVED1 = 1 << 2,
	FLAGS_SOCK_DATA_RESERVED2 = 1 << 3,
};

struct sock_accept_event {
	__event_common;
	u64 sock;
	u64 newsock;
	u16 sock_family;
	u16 sock_type;
	u8 pad1[4];
	u8 sa_data[14];
	u8 pad2[2];
};

struct sock_connect_event {
	__event_common;
	u64 sock;
	u16 sock_family;
	u16 sock_type;
	u8 pad1[4];
	u8 sa_data[14];
	u8 pad2[2];
};

struct sock_send_recv_event {
	__event_common;
	u64 sock;
	u16 sock_family;
	u16 sock_type;
	u32 offset : 28,
		flags : 4;
	u32 len;
	u8 pad[4];
	// payload
};

struct sock_close_event {
	__event_common;
	u64 sock;
};

struct go_newproc_event {
	__event_common;
	u64 new_goid;
};

struct socket_info_event {
	__event_common;
	u64 sock;
	u16 sock_family;
	u16 sock_type;
	u8 pad1[4];
	u8 sa_data[14];
	u8 pad2[2];
};

#define EVENT_BUF_LEN 0x1FFF
#define EVENT_HDR_LEN sizeof(struct sock_send_recv_event)
#define EVENT_MAX_DATA_LEN (EVENT_BUF_LEN - EVENT_HDR_LEN)

/*
 * buffer for building socket send/recv event.
 * To pass the verifier's security checks,
 * value_size is larger than the actual required;
 * max_entries is set dynamically at program load.
 */
struct bpf_map_def SEC("maps") event_buffer = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = (EVENT_BUF_LEN * 2 + 64),
	.max_entries = 0,
};

static __always_inline
void *get_event_buffer()
{
	u32 key = 0;
	return bpf_map_lookup_elem(&event_buffer, &key);
}

#endif // __TRAFFIC_MIRROR_EVENT_H_
