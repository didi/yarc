#ifndef __TRAFFIC_MIRROR_COMMON_H_
#define __TRAFFIC_MIRROR_COMMON_H_

#include "vmlinux/vmlinux.h"

#include "bpf/bpf_common.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"

#define AF_INET	2	/* Internet IP Protocol */
#define	EINPROGRESS	115	/* Operation now in progress */
#define EINVAL	22	/* Invalid argument */

#define EVENT_VERSION 0x01

#define __event_common \
	u8 version; \
	u8 source; \
	u16 type; \
	u32 tgid; \
	u32 pid; \
	u32 reserved; \
	u64 id; \
	u64 rid

#define min(x, y) ((x) <= (y) ? (x) : (y))

enum event_source {
	EVENT_SOURCE_DEBUG  = 1,
	EVENT_SOURCE_SOCKET = 2,
};

// bpf map for communicating with user space
// key is index of cpu core
// value is fd of perf event
// max_entries is set at program load
struct bpf_map_def SEC("maps") perf_events_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 0,
};

struct proc_config {
	u64 seq;
	u64 go_version;
};

// offset of goid in struct g (go1.13.5 ~ go1.17.5)
#define GOID_OFFSET		152

#define PERF_MAX_STACK_DEPTH		127

struct bpf_map_def SEC("maps") stack_map = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(u32),
	.value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
	.max_entries= 10000,
};

// bpf map for saving configuration of every process
// key is the pid (tgid) of process
// value is struct config_item *
struct bpf_map_def SEC("maps") config_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct proc_config),
	.max_entries = 64,
};

struct socket_info {
	struct sock *sk;
	u16 sock_family;
	u16 sock_type;
	u8 pad[4];
};

static __always_inline __attribute__((unused))
u64 next_seq(u32 tgid)
{
	struct proc_config *valp = NULL;
	valp = bpf_map_lookup_elem(&config_map, &tgid);
	if (!valp) {
		return 0;
	}

	// add_and_fetch is not supported by ebpf of
	// kernel-4.18.0-193.6.3.el8_2.v1.2.x86_64
	return __sync_add_and_fetch(&valp->seq, 1);
}

static __always_inline
u32 get_go_version(u32 tgid)
{
	struct proc_config *valp = NULL;
	valp = bpf_map_lookup_elem(&config_map, &tgid);
	if (!valp) {
		return 0;
	}
	return valp->go_version;
}

static __always_inline
u64 get_rid(u32 tgid, u32 pid)
{
	if (get_go_version(tgid) == 0) {
		return pid;
	} else {
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		unsigned long fsbase = 0;
		void *g = NULL;
		u64 goid = 0;
		bpf_probe_read(&fsbase, sizeof(fsbase), &task->thread.fsbase);
		bpf_probe_read(&g, sizeof(g), (void*)fsbase-8);
		bpf_probe_read(&goid, sizeof(goid), (void*)g+GOID_OFFSET);
		return goid;
	}
}

#endif // __TRAFFIC_MIRROR_COMMON_H_
