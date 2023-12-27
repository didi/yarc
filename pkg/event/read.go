package event

import (
	"encoding/binary"
	"io"
)

var (
	byteOrder = binary.LittleEndian
)

func (h *Header) Read(r io.Reader) error {
	buf := [32]byte{}
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}

	h.Version = buf[0]
	h.Source = buf[1]
	h.Type = byteOrder.Uint16(buf[2:4])
	h.TGID = byteOrder.Uint32(buf[4:8])
	h.PID = byteOrder.Uint32(buf[8:12])
	h.Reserved = byteOrder.Uint32(buf[12:16])
	h.ID = byteOrder.Uint64(buf[16:24])
	h.GOID = byteOrder.Uint64(buf[24:32])
	return nil
}

func (p *SockAccept) Read(r io.Reader) error {
	buf := [40]byte{}
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}

	p.Sock = byteOrder.Uint64(buf[0:8])
	p.NewSock = byteOrder.Uint64(buf[8:16])
	p.SockFamily = byteOrder.Uint16(buf[16:18])
	p.SockType = byteOrder.Uint16(buf[18:20])
	// Pad1 buf[20:24]
	copy(p.SockAddrData[:], buf[24:38])
	// Pad2 buf[38:40]
	return nil
}

func (p *SockConnect) Read(r io.Reader) error {
	buf := [32]byte{}
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}

	p.Sock = byteOrder.Uint64(buf[0:8])
	p.SockFamily = byteOrder.Uint16(buf[8:10])
	p.SockType = byteOrder.Uint16(buf[10:12])
	// Pad1 buf[12:16]
	copy(p.SockAddrData[:], buf[16:30])
	// Pad2 buf[30:32]
	return nil
}

func (p *SockSendRecv) Read(r io.Reader) error {
	buf := [24]byte{}
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}

	p.Sock = byteOrder.Uint64(buf[0:8])
	p.SockFamily = byteOrder.Uint16(buf[8:10])
	p.SockType = byteOrder.Uint16(buf[10:12])
	p.Offset = byteOrder.Uint32(buf[12:16])
	p.Len = byteOrder.Uint32(buf[16:20])
	// Pad2 buf[20:24]
	return nil
}

func (p *SocketInfo) Read(r io.Reader) error {
	buf := [30]byte{}
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}

	p.Sock = byteOrder.Uint64(buf[0:8])
	p.SockFamily = byteOrder.Uint16(buf[8:10])
	p.SockType = byteOrder.Uint16(buf[10:12])
	// Pad2 buf[12:16]
	copy(p.SockAddrData[:], buf[16:30])
	return nil
}

func (p *SockClose) Read(r io.Reader) error {
	buf := [8]byte{}
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}

	p.Sock = byteOrder.Uint64(buf[0:8])
	return nil
}

func (p *GoNewProc) Read(r io.Reader) error {
	buf := [8]byte{}
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}

	p.GOID = byteOrder.Uint64(buf[0:8])
	return nil
}

func (p *DebugEvent) Read(r io.Reader) error {
	buf := [24]byte{}
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}

	p.Data1 = byteOrder.Uint64(buf[0:8])
	p.Data2 = byteOrder.Uint64(buf[8:16])
	p.Data3 = byteOrder.Uint64(buf[16:24])
	return nil
}
