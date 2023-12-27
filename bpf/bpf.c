#include "linux/uio.h"

#include "common.h"
#include "context.h"
#include "debug.h"
#include "event.h"
#include "errno.h"
#include "filter.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline
int copy_from_iov_iter(struct probe_ctx *ctx, char *dst, size_t bytes,
				struct iov_iter *iter)
{
	const struct iovec *iovp;
	struct iovec iov;
	size_t skip;
	size_t left;
	size_t copied;
	int err;
	int cnt;

	if (bytes > iter->count) {
		bytes = iter->count;
	}
	if (bytes > EVENT_MAX_DATA_LEN) {
		bytes = EVENT_MAX_DATA_LEN;
	}

	iovp = iter->iov;
	err = bpf_probe_read(&iov, sizeof(iov), iovp);
	if (err) {
		tm_err2(ctx, ERROR_BPF_PROBE_READ, __LINE__, err);
		return -E_BPF_PROBE_READ_FAILED;
	}

	copied = 0;
	skip = iter->iov_offset;
	left = min(iov.iov_len - skip, bytes);
	if (left) {
		// makes verifier happy
		asm volatile("%0 &= 0x1FFF\n\t" : "=r"(left) : "0"(left) :);
		err = bpf_probe_read(dst, left, iov.iov_base + skip);
		if (err) {
			tm_err2(ctx, ERROR_BPF_PROBE_READ, __LINE__, err);
			return -E_BPF_PROBE_READ_FAILED;
		}

		copied += left;
		skip = iter->iov_offset + left;
	}

	cnt = 0;
	while (copied < bytes) {
		// avoid exceeding the verifer's max instruction number
		if (cnt++ >= 4) {
			return -E_SOCK_DATA_TRUNCATED;
		}

		iovp++;
		err = bpf_probe_read(&iov, sizeof(iov), iovp);
		if (err) {
			tm_err2(ctx, ERROR_BPF_PROBE_READ, __LINE__, err);
			return -E_BPF_PROBE_READ_FAILED;
		}

		left = min(iov.iov_len, bytes - copied);
		if (!left) {
			continue;
		}

		// makes verifier happy
		asm volatile(
			"%0 &= 0x1FFF\n\t"
			"%1 &= 0x1FFF\n\t"
			: "=r"(copied), "=r"(left)
			: "0"(copied), "1"(left)
			: /* no clobbers */
		);
		err = bpf_probe_read(dst + copied, left, iov.iov_base);
		if (err) {
			tm_err2(ctx, ERROR_BPF_PROBE_READ, __LINE__, err);
			return -E_BPF_PROBE_READ_FAILED;
		}

		skip = left;
		copied += left;
	}

	if (skip == iov.iov_len) {
		iovp++;
		skip = 0;
	}

	iter->count -= copied;
	iter->nr_segs -= iovp - iter->iov;
	iter->iov = iovp;
	iter->iov_offset = skip;
	return copied;
}

static __always_inline
int sock_data_output(struct probe_ctx *ctx, struct sock_send_recv_event *event,
				struct iov_iter *iter)
{
	void *valp;
	size_t bytes;
	int i;
	int err;
	int ret;

	if (!iter_is_iovec(iter)) {
		tm_err2(ctx, ERROR_IOV_ITER_TYPE, __LINE__, iov_iter_type(iter));
		return -E_IOV_ITER_TYPE_ERROR;
	}

	valp = get_event_buffer();
	if (!valp) {
		tm_err(ctx, ERROR_BPF_MAP_LOOKUP_ELEM, __LINE__);
		return -E_BPF_MAP_LOOKUP_ELEM_FAILED;
	}

	i = 0;
	bytes = iter->count;
	while (bytes) {
		// avoid exceeding the verifer's max instruction number
		if (i++ >= 256) {
			tm_err2(ctx, ERROR_DATA_TRUNCATED, event->offset, bytes);
			return -E_SOCK_DATA_TRUNCATED;
		}

		ret = copy_from_iov_iter(ctx, valp + EVENT_HDR_LEN, bytes, iter);
		if (ret <= 0) {
			tm_err2(ctx, ERROR_COPY_FROM_IOV_ITER, __LINE__, ret);
			return -E_BPF_PROBE_READ_FAILED;
		}

		if (ret < bytes) {
			event->flags |= FLAGS_SOCK_DATA_MORE;
		} else {
			event->flags &= ~FLAGS_SOCK_DATA_MORE;
		}

		bytes -= ret;
		event->len = ret;
		event->id = event->id + 1;
		err = bpf_probe_read(valp, sizeof(*event), event);
		if (err) {
			tm_err2(ctx, ERROR_BPF_PROBE_READ, __LINE__, err);
			return -E_BPF_PROBE_READ_FAILED;
		}

		ret = EVENT_HDR_LEN + event->len;
		if (ret > EVENT_BUF_LEN) {
			tm_err2(ctx, ERROR_LOGICAL, __LINE__, err);
			return -E_PERF_EVENT_TOO_LONG;
		}

		// makes verifier happy
		ret &= EVENT_BUF_LEN;
		err = bpf_perf_event_output(ctx->bpf_ctx, &perf_events_map,
			BPF_F_CURRENT_CPU, valp, ret);
		if (err) {
			tm_err2(ctx, ERROR_BPF_PERF_EVENT_OUTPUT, __LINE__, err);
			return err;
		}
		tm_dbg2(ctx, DEBUG_SOCK_DATA_OUTPUT, event->offset, event->len);
		event->offset += event->len;
	}

	return 0;
}

static __always_inline
int read_socket_peer(struct probe_ctx *ctx, struct sock *sk, u8 sa[14]) {
	int err;

	err = bpf_probe_read(sa, sizeof(sk->__sk_common.skc_dport),
		&sk->__sk_common.skc_dport);
	if (err) {
		tm_err2(ctx, ERROR_BPF_PROBE_READ, __LINE__, err);
		return -E_BPF_PROBE_READ_FAILED;
	}

	err = bpf_probe_read(sa+2, sizeof(sk->__sk_common.skc_daddr),
		&sk->__sk_common.skc_daddr);
	if (err) {
		tm_err2(ctx, ERROR_BPF_PROBE_READ, __LINE__, err);
		return -E_BPF_PROBE_READ_FAILED;
	}

	return 0;
}

static __always_inline
int read_socket_info(struct probe_ctx *ctx, struct socket_info *info,
				const struct socket *socket)
{
	int err;

	err = bpf_probe_read(&info->sock_type, sizeof(info->sock_type), &socket->type);
	if (err) {
		tm_err2(ctx, ERROR_BPF_PROBE_READ, __LINE__, err);
		return -E_BPF_PROBE_READ_FAILED;
	}

	err = bpf_probe_read(&info->sk, sizeof(info->sk), &socket->sk);
	if (err) {
		tm_err2(ctx, ERROR_BPF_PROBE_READ, __LINE__, err);
		return -E_BPF_PROBE_READ_FAILED;
	}

	err = bpf_probe_read(&info->sock_family, sizeof(info->sock_family),
		&info->sk->__sk_common.skc_family);
	if (err) {
		tm_err2(ctx, ERROR_BPF_PROBE_READ, __LINE__, err);
		return -E_BPF_PROBE_READ_FAILED;
	}

	return 0;
}


static __always_inline
int report_udp_peer(struct probe_ctx *yctx, struct msghdr *msg)
{
	struct socket_info_event event = {
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_SOCKET,
		.type = EVENT_SOCK_INFO,
		.tgid = yctx->tgid,
		.pid = yctx->pid,
		.rid = yctx->rid,
	};
	struct sockaddr *addr = NULL;
	int addrlen = 0;
	int err;

	err = bpf_probe_read(&addrlen, sizeof(addrlen), &msg->msg_namelen);
	if (err) {
		tm_err2(yctx, E_BPF_PROBE_READ_FAILED, __LINE__, err);
		return err;
	}

	// call send on a connected udp socket
	if (addrlen == 0) {
		err = read_socket_peer(yctx, yctx->sr.sockinfo.sk, event.sa_data);
		if (err) {
			tm_err2(yctx, ERROR_READ_SOCKET_INFO, __LINE__, err);
			return -1;
		}
	} else if (addrlen == 16) {
		err = bpf_probe_read(&addr, sizeof(addr), &msg->msg_name);
		if (err) {
			tm_err2(yctx, ERROR_BPF_PROBE_READ, __LINE__, err);
			return -1;
		}

		// udp4 sockaddr
		err = bpf_probe_read(event.sa_data, sizeof(event.sa_data), addr->sa_data);
		if (err) {
			tm_err2(yctx, ERROR_BPF_PROBE_READ, __LINE__, err);
			return -1;
		}
	} else {
		// only support udp4, struct sockaddr
		tm_err2(yctx, ERROR_MSG_NAME_LEN, __LINE__, addrlen);
		return -1;
	}

	event.sock = (u64)yctx->sr.sock;
	event.sock_family = yctx->sr.sockinfo.sock_family;
	event.sock_type = yctx->sr.sockinfo.sock_type;
	event.id = bpf_ktime_get_ns();
	err = bpf_perf_event_output(yctx->bpf_ctx, &perf_events_map,
		BPF_F_CURRENT_CPU, &event, sizeof(event));
	if (err) {
		tm_err2(yctx, ERROR_BPF_PERF_EVENT_OUTPUT, __LINE__, err);
		return -1;
	}
	return 0;
}

SEC("kprobe/inet_accept")
int BPF_KPROBE(inet_accept_entry, struct socket *sock, struct socket *newsock)
{
	struct probe_ctx yctx = {
		.bpf_ctx = ctx,
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_SOCKET,
		.type = EVENT_SOCK_ACCEPT,
	};
	int err;

	if (pid_filter(&yctx)) {
		return 0;
	}

	tm_dbg2(&yctx, DEBUG_INET_ACCEPT_ENTRY, (u64)sock, (u64)newsock);

	yctx.rid = get_rid(yctx.tgid, yctx.pid);
	yctx.accept.sock = sock;
	yctx.accept.newsock = newsock;
	yctx.id = bpf_ktime_get_ns();
	err = save_context(yctx.pid, &yctx);
	if (err) {
		tm_err2(&yctx, ERROR_SAVE_CONTEXT, __LINE__, err);
	}
	return 0;
}

SEC("kretprobe/inet_accept")
int BPF_KRETPROBE(inet_accept_exit, int retval)
{
	struct probe_ctx yctx = {
		.bpf_ctx = ctx,
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_SOCKET,
		.type = EVENT_SOCK_ACCEPT,
	};
	struct sock_accept_event event = {};
	struct socket_info sockinfo;
	int err;

	if (pid_filter(&yctx)) {
		return 0;
	}

	tm_dbg(&yctx, DEBUG_INET_ACCEPT_EXIT, (u64)retval);

	if (retval < 0) {
		goto out;
	}

	err = read_context(yctx.pid, &yctx);
	if (err) {
		tm_err2(&yctx, ERROR_READ_CONTEXT, __LINE__, err);
		goto out;
	}

	err = read_socket_info(&yctx, &sockinfo, yctx.accept.newsock);
	if (err) {
		tm_err2(&yctx, ERROR_READ_SOCKET_INFO, __LINE__, err);
		goto out;
	}

	err = read_socket_peer(&yctx, sockinfo.sk, event.sa_data);
	if (err) {
		tm_err2(&yctx, ERROR_READ_SOCKET_INFO, __LINE__, err);
		goto out;
	}

	event.sock = (u64)yctx.accept.sock;
	event.newsock = (u64)yctx.accept.newsock;
	event.sock_family = sockinfo.sock_family;
	event.sock_type = sockinfo.sock_type;
	event.version = yctx.version;
	event.source = yctx.source;
	event.type = yctx.type;
	event.tgid = yctx.tgid;
	event.pid = yctx.pid;
	event.rid = yctx.rid;
	event.id = yctx.id;
	err = bpf_perf_event_output(ctx, &perf_events_map,
			BPF_F_CURRENT_CPU, &event, sizeof(event));
	if (err) {
		tm_err2(&yctx, ERROR_BPF_PERF_EVENT_OUTPUT, __LINE__, err);
	}

out:
	err = delete_context(yctx.pid);
	if (err) {
		tm_err2(&yctx, ERROR_DELETE_CONTEXT, __LINE__, err);
	}
	return 0;
}


SEC("kprobe/inet_stream_connect")
int BPF_KPROBE(inet_stream_connect_entry, struct socket *sock,
	struct sockaddr *uaddr, int addr_len, int flags)
{
	struct probe_ctx yctx = {
		.bpf_ctx = ctx,
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_SOCKET,
		.type = EVENT_SOCK_CONNECT,
	};
	int err;

	if (pid_filter(&yctx)) {
		return 0;
	}

	tm_dbg(&yctx, DEBUG_INET_CONNECT_ENTRY, 0);

	yctx.rid = get_rid(yctx.tgid, yctx.pid);
	yctx.connect.sock = sock;
	yctx.connect.addr = uaddr;
	yctx.id = bpf_ktime_get_ns();
	err = save_context(yctx.pid, &yctx);
	if (err) {
		tm_err2(&yctx, ERROR_SAVE_CONTEXT, __LINE__, err);
	}
	return 0;
}

SEC("kretprobe/inet_stream_connect")
int BPF_KRETPROBE(inet_stream_connect_exit, int retval)
{
	struct probe_ctx yctx = {
		.bpf_ctx = ctx,
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_SOCKET,
		.type = EVENT_SOCK_CONNECT,
	};
	struct sock_connect_event event = {};
	struct socket_info sockinfo;
	struct sockaddr addr = {};
	int err;

	if (pid_filter(&yctx)) {
		return 0;
	}

	tm_dbg(&yctx, DEBUG_INET_CONNECT_EXIT, retval);

	// When EINPROGRESS was returned, it indicates that the connection
	// has not been successfully established, but we don't care, because
	// if the connect fails, the socket cannot be used to send or recv data.
	if (retval < 0 && retval != -EINPROGRESS) {
		goto out;
	}

	err = read_context(yctx.pid, &yctx);
	if (err) {
		tm_err2(&yctx, ERROR_READ_CONTEXT, __LINE__, err);
		goto out;
	}

	err = read_socket_info(&yctx, &sockinfo, yctx.connect.sock);
	if (err) {
		tm_err2(&yctx, ERROR_READ_SOCKET_INFO, __LINE__, err);
		goto out;
	}

	err = bpf_probe_read(event.sa_data, sizeof(addr.sa_data), yctx.connect.addr->sa_data);
	if (err) {
		tm_err2(&yctx, ERROR_BPF_PROBE_READ, __LINE__, err);
		goto out;
	}

	event.sock = (u64)yctx.connect.sock;
	event.sock_family = sockinfo.sock_family;
	event.sock_type = sockinfo.sock_type;
	event.version = yctx.version;
	event.source = yctx.source;
	event.type = yctx.type;
	event.tgid = yctx.tgid;
	event.pid = yctx.pid;
	event.rid = yctx.rid;
	event.id = yctx.id;
	err = bpf_perf_event_output(ctx, &perf_events_map,
			BPF_F_CURRENT_CPU, &event, sizeof(event));
	if (err) {
		tm_err2(&yctx, ERROR_BPF_PERF_EVENT_OUTPUT, __LINE__, err);
	}

out:
	err = delete_context(yctx.pid);
	if (err) {
		tm_err2(&yctx, ERROR_DELETE_CONTEXT, __LINE__, err);
	}
	return 0;
}


SEC("kprobe/inet_release")
int BPF_KPROBE(inet_release_entry, struct socket *sock)
{
	struct probe_ctx yctx = {
		.bpf_ctx = ctx,
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_SOCKET,
		.type = EVENT_SOCK_CLOSE,
	};
	struct sock_close_event event = {};
	int err;

	if (pid_filter(&yctx)) {
		return 0;
	}

	tm_dbg(&yctx, DEBUG_FILP_CLOSE_ENTRY, (u64)sock);

	event.sock = (u64)sock;
	event.version = yctx.version;
	event.source = yctx.source;
	event.type = yctx.type;
	event.tgid = yctx.tgid;
	event.pid = yctx.pid;
	event.id = bpf_ktime_get_ns();
	event.rid = get_rid(yctx.tgid, yctx.pid);
	err = bpf_perf_event_output(ctx, &perf_events_map,
			BPF_F_CURRENT_CPU, &event, sizeof(event));
	if (err) {
		tm_err2(&yctx, ERROR_BPF_PERF_EVENT_OUTPUT, __LINE__, err);
	}
	return 0;
}


SEC("kprobe/inet_sendmsg")
int BPF_KPROBE(inet_sendmsg_entry, struct socket *sock, struct msghdr *msg)
{
	struct probe_ctx yctx = {
		.bpf_ctx = ctx,
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_SOCKET,
		.type = EVENT_SOCK_SENDMSG,
		.sr.sock = sock,
	};
	int err;

	if (pid_filter(&yctx)) {
		return 0;
	}

	tm_dbg2(&yctx, DEBUG_SOCK_SENDMSG_ENTRY, (u64)sock, (u64)msg);

	err = read_socket_info(&yctx, &yctx.sr.sockinfo, sock);
	if (err) {
		tm_err2(&yctx, ERROR_READ_SOCKET_INFO, __LINE__, err);
		return 0;
	}

	// when sendto is called on an unconnected udp socket, we can't get the
	// peer address, so we need to get it from msghdr.
	if (yctx.sr.sockinfo.sock_family == AF_INET &&
		yctx.sr.sockinfo.sock_type == SOCK_DGRAM) {
		report_udp_peer(&yctx, msg);
	}

	err = bpf_probe_read(&yctx.sr.iter, sizeof(yctx.sr.iter), &msg->msg_iter);
	if (err) {
		tm_err2(&yctx, ERROR_BPF_PROBE_READ, __LINE__, err);
		return 0;
	}

	yctx.rid = get_rid(yctx.tgid, yctx.pid);
	yctx.id = bpf_ktime_get_ns();
	err = save_context(yctx.pid, &yctx);
	if (err) {
		tm_err2(&yctx, ERROR_SAVE_CONTEXT, __LINE__, err);
	}
	return 0;
}

SEC("kretprobe/inet_sendmsg")
int BPF_KRETPROBE(inet_sendmsg_exit, int retval)
{
	struct probe_ctx yctx = {
		.bpf_ctx = ctx,
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_SOCKET,
		.type = EVENT_SOCK_SENDMSG,
	};
	struct sock_send_recv_event event = {};
	int err;

	if (pid_filter(&yctx)) {
		return 0;
	}

	tm_dbg(&yctx, DEBUG_FILP_CLOSE_EXIT, retval);

	if (retval <= 0) {
		goto out;
	}

	err = read_context(yctx.pid, &yctx);
	if (err) {
		tm_err2(&yctx, ERROR_READ_CONTEXT, __LINE__, err);
		goto out;
	}

	event.sock_family = yctx.sr.sockinfo.sock_family;
	event.sock_type = yctx.sr.sockinfo.sock_type;
	event.sock = (u64)yctx.sr.sock;
	event.version = yctx.version;
	event.source = yctx.source;
	event.type = yctx.type;
	event.tgid = yctx.tgid;
	event.pid = yctx.pid;
	event.id = yctx.id;
	event.rid = yctx.rid;

	// iter.count is the length of data user wants to send,
	// it needs to be the length actual send.
	yctx.sr.iter.count = retval;
	sock_data_output(&yctx, &event, &yctx.sr.iter);

out:
	err = delete_context(yctx.pid);
	if (err) {
		tm_err2(&yctx, ERROR_DELETE_CONTEXT, __LINE__, err);
	}
	return 0;
}


SEC("kprobe/inet_recvmsg")
int BPF_KPROBE(inet_recvmsg_entry, struct socket *sock, struct msghdr *msg)
{
	struct probe_ctx yctx = {
		.bpf_ctx = ctx,
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_SOCKET,
		.type = EVENT_SOCK_RECVMSG,
		.sr.sock = sock,
	};
	int err;

	if (pid_filter(&yctx)) {
		return 0;
	}

	tm_dbg2(&yctx, DEBUG_SOCK_RECVMSG_ENTRY, (u64)sock, (u64)msg);

	err = read_socket_info(&yctx, &yctx.sr.sockinfo, yctx.sr.sock);
	if (err) {
		tm_err2(&yctx, ERROR_READ_SOCKET_INFO, __LINE__, err);
		return 0;
	}

	err = bpf_probe_read(&yctx.sr.iter, sizeof(yctx.sr.iter), &msg->msg_iter);
	if (err) {
		tm_err2(&yctx, ERROR_BPF_PROBE_READ, __LINE__, err);
		return 0;
	}

	yctx.rid = get_rid(yctx.tgid, yctx.pid);
	yctx.id = bpf_ktime_get_ns();
	err = save_context(yctx.pid, &yctx);
	if (err) {
		tm_err2(&yctx, ERROR_SAVE_CONTEXT, __LINE__, err);
	}
	return 0;
}

SEC("kretprobe/inet_recvmsg")
int BPF_KRETPROBE(inet_recvmsg_exit, int retval)
{
	struct probe_ctx yctx = {
		.bpf_ctx = ctx,
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_SOCKET,
		.type = EVENT_SOCK_RECVMSG,
	};
	struct sock_send_recv_event event = {};
	int ret;

	if (pid_filter(&yctx)) {
		return 0;
	}

	tm_dbg(&yctx, DEBUG_SOCK_RECVMSG_EXIT, retval);

	if (retval <= 0) {
		goto out;
	}

	ret = read_context(yctx.pid, &yctx);
	if (ret) {
		tm_err2(&yctx, ERROR_READ_CONTEXT, __LINE__, ret);
		goto out;
	}

	event.sock_family = yctx.sr.sockinfo.sock_family;
	event.sock_type = yctx.sr.sockinfo.sock_type;
	event.sock = (u64)yctx.sr.sock;
	event.version = yctx.version;
	event.source = yctx.source;
	event.type = yctx.type;
	event.tgid = yctx.tgid;
	event.pid = yctx.pid;
	event.id = yctx.id;
	event.rid = yctx.rid;

	// iter.count is the length of the provided buffer,
	// it needs to be the length actual recv.
	yctx.sr.iter.count = retval;
	sock_data_output(&yctx, &event, &yctx.sr.iter);

out:
	ret = delete_context(yctx.pid);
	if (ret) {
		tm_err2(&yctx, ERROR_DELETE_CONTEXT, __LINE__, ret);
	}
	return 0;
}


SEC("uprobe/go_newproc1")
int go_newproc1_entry(struct pt_regs *ctx) {
	struct probe_ctx yctx = {
		.bpf_ctx = ctx,
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_SOCKET,
		.type = EVENT_GO_NEWPROC,
	};
	void *g = NULL;
	u64 goid = 0;
	u32 gover = 0;
	int err;

	if (pid_filter(&yctx)) {
		return 0;
	}

	tm_dbg(&yctx, DEBUG_GO_NEWPROC_ENTRY, 0);

	gover = get_go_version(yctx.tgid);
	if (gover >= 118 && gover <= 120) {
		// go1.18 ~ go1.20
		g = (void*)ctx->bx;
	} else if (gover == 117) {
		// go1.17
		g = (void*)ctx->di;
	} else if (gover >= 115 && gover <= 116) {
		// go1.15 ~ go1.16
		err = bpf_probe_read(&g, sizeof(g), (void*)ctx->bp-24);
		if (err) {
			tm_err2(&yctx, ERROR_BPF_PROBE_READ, __LINE__, err);
			return 0;
		}
	} else if (gover >= 113 && gover <= 114) {
		// go1.13 ~ go1.14
		err = bpf_probe_read(&g, sizeof(g), (void*)ctx->bp-16);
		if (err) {
			tm_err2(&yctx, ERROR_BPF_PROBE_READ, __LINE__, err);
			return 0;
		}
	} else {
		// not support
		tm_err2(&yctx, ERROR_UNKNOWN_GO_VERSION, __LINE__, gover);
		return 0;
	}

	err = bpf_probe_read(&goid, sizeof(goid), (void*)g+GOID_OFFSET);
	if (err) {
		tm_err2(&yctx, ERROR_BPF_PROBE_READ, __LINE__, err);
		return 0;
	}

	yctx.rid = goid;
	yctx.goproc.gover = gover;
	yctx.id = bpf_ktime_get_ns();
	err = save_context(yctx.pid, &yctx);
	if (err) {
		tm_err2(&yctx, ERROR_SAVE_CONTEXT, __LINE__, err);
	}
	return 0;
}

SEC("uretprobe/go_newproc1")
int go_newproc1_exit(struct pt_regs *ctx) {
	struct probe_ctx yctx = {
		.bpf_ctx = ctx,
		.version = EVENT_VERSION,
		.source = EVENT_SOURCE_SOCKET,
		.type = EVENT_GO_NEWPROC,
	};
	struct go_newproc_event event = {};
	void *newg = NULL;
	u64 goid = 0;
	u32 gover = 0;
	int err;

	if (pid_filter(&yctx)) {
		return 0;
	}

	tm_dbg(&yctx, DEBUG_GO_NEWPROC_EXIT, 0);

	err = read_context(yctx.pid, &yctx);
	if (err) {
		tm_err2(&yctx, ERROR_READ_CONTEXT, __LINE__, err);
		return 0;
	}

	gover = yctx.goproc.gover;
	if (gover >= 117 && gover <= 120) {
		// go1.17 ~ go1.20
		// ax saves the memory address of the local variable `newg` in newproc1()
		newg = (void*)ctx->ax;
	} else if (gover >= 115 && gover <= 116) {
		// go1.15 ~ go1.16
		// bp-88 is the memory address of the local variable `newg` in newproc1()
		err = bpf_probe_read(&newg, sizeof(newg), (void*)ctx->bp-88);
		if (err) {
			tm_err2(&yctx, ERROR_BPF_PROBE_READ, __LINE__, err);
			goto out;
		}
	} else if (gover >= 113 && gover <= 114) {
		// go1.13 ~ go1.14
		// bp-80 is the memory address of the local variable `newg` in newproc1()
		// src/runtime/proc.go:3283
		err = bpf_probe_read(&newg, sizeof(newg), (void*)ctx->bp-80);
		if (err) {
			tm_err2(&yctx, ERROR_BPF_PROBE_READ, __LINE__, err);
			goto out;
		}
	} else {
		// not support
		tm_err2(&yctx, ERROR_UNKNOWN_GO_VERSION, __LINE__, gover);
		goto out;
	}

	err = bpf_probe_read(&goid, sizeof(goid), (void*)newg+GOID_OFFSET);
	if (err) {
		tm_err2(&yctx, ERROR_BPF_PROBE_READ, __LINE__, err);
		goto out;
	}

	event.new_goid = goid;
	event.version = yctx.version;
	event.source = yctx.source;
	event.type = yctx.type;
	event.tgid = yctx.tgid;
	event.pid = yctx.pid;
	event.id = yctx.id;
	event.rid = yctx.rid;
	err = bpf_perf_event_output(ctx, &perf_events_map,
			BPF_F_CURRENT_CPU, &event, sizeof(event));
	if (err) {
		tm_err2(&yctx, ERROR_BPF_PERF_EVENT_OUTPUT, __LINE__, err);
	}

out:
	err = delete_context(yctx.pid);
	if (err) {
		tm_err2(&yctx, ERROR_DELETE_CONTEXT, __LINE__, err);
	}
	return 0;
}
