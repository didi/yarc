package model

import (
	"net"
	"time"
)

// AddressFamily address family
type AddressFamily uint16

// SockType socket type
type SockType uint16

const (
	// Unix AF_UNIX
	Unix AddressFamily = 1
	// Inet AF_INET
	Inet AddressFamily = 2
	// Inet6 AF_INET6
	Inet6 AddressFamily = 10
	// Netlink AF_NETLINK
	Netlink AddressFamily = 16

	// SockStream SOCK_STREAM
	SockStream SockType = 1
	// SockDgram SOCK_DGRAM
	SockDgram SockType = 2
)

type SockCreateBy uint8

const (
	Unknown SockCreateBy = iota
	Accept
	Connect
)

// Socket saves socket info
type Socket struct {
	ID         uint64
	CreateBy   SockCreateBy
	Reset      bool
	Family     AddressFamily
	Type       SockType
	LocalAddr  string
	PeerAddr   string
	PeerIPAddr net.IP
	PeerPort   int
	SendOffset uint32
	RecvOffset uint32
	LastAccess time.Time
	TraceID    string
}

// InetAddrString converts IP address represented by uint32 to net.IP and port.
func InetAddrString(ip uint32, port uint16) (net.IP, int) {
	a := (byte)(ip & 0xFF)
	b := (byte)((ip >> 8) & 0xFF)
	c := (byte)((ip >> 16) & 0xFF)
	d := (byte)((ip >> 24) & 0xFF)
	e := (int)((port >> 8) | (port << 8))
	return net.IPv4(a, b, c, d), e
}

// InetSockAddrString parses IP address and port from sockaddr.sa_data.
func InetSockAddrString(data [14]byte) (net.IP, int) {
	port := uint16(data[0])<<8 | uint16(data[1])
	ip := net.IPv4(data[2], data[3], data[4], data[5])
	return ip, int(port)
}
