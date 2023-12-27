package event

// Header header of perf event
type Header struct {
	Version  uint8  `json:"version"`
	Source   uint8  `json:"source"`
	Type     uint16 `json:"type"`
	TGID     uint32 `json:"tgid"`
	PID      uint32 `json:"pid"`
	Reserved uint32 `json:"reserved"`
	ID       uint64 `json:"id"`
	GOID     uint64 `json:"goid"`
}

// SockAccept inet_accept event
type SockAccept struct {
	Sock         uint64   `json:"sock"`
	NewSock      uint64   `json:"new_sock"`
	SockFamily   uint16   `json:"sock_family"`
	SockType     uint16   `json:"sock_type"`
	Pad1         [4]byte  `json:"-"`
	SockAddrData [14]byte `json:"sock_addr_data"`
	Pad2         [2]byte  `json:"-"`
}

// SockConnect inet_stream_connect event
type SockConnect struct {
	Sock         uint64   `json:"sock"`
	SockFamily   uint16   `json:"sock_family"`
	SockType     uint16   `json:"sock_type"`
	Pad1         [4]byte  `json:"-"`
	SockAddrData [14]byte `json:"sock_addr_data"`
	Pad2         [2]byte  `json:"-"`
}

// SockSendRecv sock_sendmsg, sock_recvmsg event
type SockSendRecv struct {
	Sock       uint64  `json:"sock"`
	SockFamily uint16  `json:"sock_family"`
	SockType   uint16  `json:"sock_type"`
	Offset     uint32  `json:"offset"`
	Len        uint32  `json:"len"`
	Pad        [4]byte `json:"pad"`
}

// SocketInfo socket info event
type SocketInfo struct {
	Sock         uint64   `json:"sock"`
	SockFamily   uint16   `json:"sock_family"`
	SockType     uint16   `json:"sock_type"`
	Pad          [4]byte  `json:"-"`
	SockAddrData [14]byte `json:"sock_addr_data"`
}

// SockClose socket close event
type SockClose struct {
	Sock uint64 `json:"sock"`
}

// GoNewProc go newproc event
type GoNewProc struct {
	GOID uint64 `json:"goid"`
}

// Source event source
type Source uint8

// Type event type
type Type uint16

const (
	// yarcVersion version for perf event
	YarcVersion uint8 = 1

	MaxEventLen uint32 = 0x1FFF

	// EventHdrLen event header length
	EventHdrLen     uint32 = 32 // sizeof(Header)
	EventDataHdrLen uint32 = 24 // sizeof(SockSendRecv)
	// EventMaxDataLen max length of data for sock_sendmsg and sock_recvmsg
	EventMaxDataLen uint32 = MaxEventLen - EventHdrLen - EventDataHdrLen

	// EventSourceDebug debug event
	EventSourceDebug Source = 1
	// EventSourceSocket socket event
	EventSourceSocket Source = 2

	// EventSockSendmsg socket sendmsg
	EventSockSendmsg Type = 1
	// EventSockRecvmsg socket recvmsg
	EventSockRecvmsg Type = 2
	// EventSockClose socket close
	EventSockClose Type = 3
	// EventSockAccept socket accept
	EventSockAccept Type = 4
	// EventSockConnect socket connect
	EventSockConnect Type = 5
	// EventSockInfo socket info
	EventSockInfo Type = 6
	// EventGoNewProc go runtime.newproc1
	EventGoNewProc Type = 11

	// DataFlagMore more data
	DataFlagMore = 1 << 0
	// DataFlagTruncated data was truncated
	DataFlagTruncated = 1 << 1
	// DataFlagReserved1 reserved1
	DataFlagReserved1 = 1 << 2
	// DataFlagReserved2 reserved2
	DataFlagReserved2 = 1 << 3
)
