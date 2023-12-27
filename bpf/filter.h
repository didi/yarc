#ifndef __TRAFFIC_MIRROR_FILTER_H_
#define __TRAFFIC_MIRROR_FILTER_H_

#include "common.h"
#include "context.h"

static __always_inline
int pid_filter(struct probe_ctx *ctx)
{
	u64 pid_tgid;
	u32 tgid;
	void *valp;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = pid_tgid >> 32;
	valp = bpf_map_lookup_elem(&config_map, &tgid);
	if (!valp) {
		return 1;
	}

	ctx->tgid = pid_tgid >> 32;
	ctx->pid = pid_tgid & 0xFFFFFFFF;
	return 0;
}

#endif // __TRAFFIC_MIRROR_FILTER_H_
