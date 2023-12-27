package event

import "fmt"

// DebugEventType type of debug event
type DebugEventType uint16

const (
	// DebugInetAcceptEntry kprobe inet_accept
	DebugInetAcceptEntry DebugEventType = 0x01
	// DebugInetAcceptExit kretprobe inet_accept
	DebugInetAcceptExit DebugEventType = 0x02
	// DebugInetConnectEntry kprobe inet_stream_connect
	DebugInetConnectEntry DebugEventType = 0x03
	// DebugInetConnectExit kretprobe inet_stream_connect
	DebugInetConnectExit DebugEventType = 0x04
	// DebugSockSendMsgEntry kprobe sock_sendmsg
	DebugSockSendMsgEntry DebugEventType = 0x05
	// DebugSockSendMsgExit kretprobe sock_sendmsg
	DebugSockSendMsgExit DebugEventType = 0x06
	// DebugSockRecvMsgEntry kprobe sock_recvmsg
	DebugSockRecvMsgEntry DebugEventType = 0x07
	// DebugSockRecvMsgExit kretprobe sock_recvmsg
	DebugSockRecvMsgExit DebugEventType = 0x08
	// DebugFilpCloseEntry kprobe filp_close
	DebugFilpCloseEntry DebugEventType = 0x09
	// DebugFilpCloseExit kretprobe filp_close
	DebugFilpCloseExit DebugEventType = 0x0A
	// DebugGoNewProcEntry uprobe go runtime.newproc1
	DebugGoNewProcEntry DebugEventType = 0x0B
	// DebugGoNewProcOffset uprobe go runtime.newproc1+offset
	DebugGoNewProcOffset DebugEventType = 0x0C
	// DebugGoNewProcExit uretprobe go runtime.newproc1
	DebugGoNewProcExit DebugEventType = 0x0D
	// DebugSockDataOutput sock data output
	DebugSockDataOutput DebugEventType = 0x0E

	// DebugStack stackid
	DebugStack DebugEventType = 0x41

	// DebugBpfPerfEventOutputError bpf_perf_event_output failed
	DebugBpfPerfEventOutputError DebugEventType = 0xC1
	// DebugBpfProbeReadError bpf_probe_read failed
	DebugBpfProbeReadError DebugEventType = 0xC2
	// DebugBpfMapLookupElemError bpf_map_lookup_elem failed
	DebugBpfMapLookupElemError DebugEventType = 0xC3
	// DebugLogicalError logical error
	DebugLogicalError DebugEventType = 0xD1
	// DebugDataTruncated data truncated
	DebugDataTruncated DebugEventType = 0xD2
	// DebugIovIterTypeError iov_iter type error
	DebugIovIterTypeError DebugEventType = 0xD3
	// DebugCopyFromIovIterError copy_from_iov_iter failed
	DebugCopyFromIovIterError DebugEventType = 0xD4
	// DebugSaveContextError yarc_save_context failed
	DebugSaveContextError DebugEventType = 0xD5
	// DebugReadContextError yarc_read_context failed
	DebugReadContextError DebugEventType = 0xD6
	// DebugDeleteContextError yarc_delete_context failed
	DebugDeleteContextError DebugEventType = 0xD7
	//DebugReadSocketInfoError read_socket_info failed
	DebugReadSocketInfoError DebugEventType = 0xD8
	// DebugUnknownGoVersion unknown go version
	DebugUnknownGoVersion DebugEventType = 0xD9
	// DebugMsgNameLenError msg_namelen error
	DebugMsgNameLenError DebugEventType = 0xDA
)

// DebugEvent debug event
type DebugEvent struct {
	Data1 uint64 `json:"data1"`
	Data2 uint64 `json:"data2"`
	Data3 uint64 `json:"data3"`
}

// DebugInfo converts a debug event to a string
func DebugInfo(t DebugEventType, e DebugEvent) string {
	switch t {
	case DebugInetAcceptEntry:
		return "inet_accept entry"
	case DebugInetAcceptExit:
		return "inet_accept exit"
	case DebugInetConnectEntry:
		return "inet_connect entry"
	case DebugInetConnectExit:
		return "inet_connect exit"
	case DebugSockSendMsgEntry:
		return "sock_sendmsg entry"
	case DebugSockSendMsgExit:
		return "sock_sendmsg exit"
	case DebugSockRecvMsgEntry:
		return "sock_recvmsg entry"
	case DebugSockRecvMsgExit:
		return "sock_recvmsg exit"
	case DebugFilpCloseEntry:
		return "filp_close entry"
	case DebugFilpCloseExit:
		return "filp_close exit"
	case DebugGoNewProcEntry:
		return "go_newproc entry"
	case DebugGoNewProcOffset:
		return "go_newproc offset"
	case DebugGoNewProcExit:
		return "go_newproc exit"
	case DebugSockDataOutput:
		return fmt.Sprintf("sock_data_output: offset %d, len %d", e.Data1, e.Data2)
	case DebugStack:
		return fmt.Sprintf("kernstack %d, userstack %d", e.Data1, e.Data2)
	case DebugBpfPerfEventOutputError:
		return fmt.Sprintf("bpf_perf_event_output error: line %d, errno %d", e.Data1, int64(e.Data2))
	case DebugBpfProbeReadError:
		return fmt.Sprintf("bpf_probe_read error: line %d, errno %d", e.Data1, int64(e.Data2))
	case DebugBpfMapLookupElemError:
		return fmt.Sprintf("bpf_map_lookup_elem error: line %d, errno %d", e.Data1, int64(e.Data2))
	case DebugLogicalError:
		return fmt.Sprintf("logical error: line %d, data2 %d, data3 %d", e.Data1, e.Data2, e.Data3)
	case DebugDataTruncated:
		return fmt.Sprintf("data truncated error: offset %d, remain %d, data3 %d", e.Data1, e.Data2, e.Data3)
	case DebugIovIterTypeError:
		return fmt.Sprintf("logical error: line %d, iter_type %d", e.Data1, e.Data2)
	case DebugCopyFromIovIterError:
		return fmt.Sprintf("copy from iov_iter error: line %d, errno %d", e.Data1, int64(e.Data2))
	case DebugSaveContextError:
		return fmt.Sprintf("save context error: line %d, errno %d", e.Data1, int64(e.Data2))
	case DebugReadContextError:
		return fmt.Sprintf("read context error: line %d, errno %d", e.Data1, int64(e.Data2))
	case DebugDeleteContextError:
		return fmt.Sprintf("delete context error: line %d, errno %d", e.Data1, int64(e.Data2))
	case DebugReadSocketInfoError:
		return fmt.Sprintf("read socket info error: line %d, errno %d", e.Data1, int64(e.Data2))
	case DebugUnknownGoVersion:
		return fmt.Sprintf("unrecognized go version: line %d, version %d", e.Data1, e.Data2)
	case DebugMsgNameLenError:
		return fmt.Sprintf("unrecognized msg_namelen: line %d, len %d", e.Data1, e.Data2)
	default:
		return fmt.Sprintf("unknown debug event type: %d, data1 %d, data2 %d, data3 %d", t, e.Data1, e.Data2, e.Data3)
	}
}
