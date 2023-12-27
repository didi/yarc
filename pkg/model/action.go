package model

import (
	"encoding/json"
	"math"
	"net"
)

// Action defines the interface for actions performanced during the processing of a request.
type Action interface {
	IsValid() bool
	GetActionIndex() int
	GetOccurredAt() uint64
	GetActionType() string
}

type action struct {
	ActionIndex int    `json:"ActionIndex"`
	OccurredAt  uint64 `json:"OccurredAt"`
	ActionType  string `json:"ActionType"`
	ThreadID    uint64 `json:"ThreadId"`
	SocketFD    uint64 `json:"SocketFD"`

	recvMore bool `json:"-"`
	sendMore bool `json:"-"`
}

// GetActionType returns action type.
func (act *action) GetActionType() string {
	return act.ActionType
}

// GetActionIndex returns action index.
func (act *action) GetActionIndex() int {
	return act.ActionIndex
}

// GetOccurredAt returns the time of action occurrence.
func (act *action) GetOccurredAt() uint64 {
	return act.OccurredAt
}

func (act *action) resetUint64Fields() {
	act.ThreadID &= math.MaxInt32
	act.SocketFD &= math.MaxInt32
}

// CallFromInbound represents a request of inbound.
type CallFromInbound struct {
	action
	Peer net.TCPAddr `json:"Peer"`
	//UnixAddr net.UnixAddr `json:"UnixAddr"`
	Request []byte `json:"Request"`
}

// IsValid returns whether this is valid action
func (in *CallFromInbound) IsValid() bool {
	if in.recvMore {
		return false
	}
	return len(in.Request) > 0
}

// MarshalJSON json encode
func (in *CallFromInbound) MarshalJSON() ([]byte, error) {
	wrapper := struct {
		CallFromInbound
		Request json.RawMessage `json:"Request"`
	}{
		CallFromInbound: *in,
		Request:         EncodeAnyByteArray(in.Request),
	}
	wrapper.action.resetUint64Fields()
	return json.Marshal(wrapper)
}

// ReturnInbound represents a response of inbound.
type ReturnInbound struct {
	action
	Response []byte `json:"Response"`
}

// IsValid returns whether this is valid action
func (in *ReturnInbound) IsValid() bool {
	if in.sendMore {
		return false
	}
	return len(in.Response) > 0
}

// MarshalJSON json encode
func (in *ReturnInbound) MarshalJSON() ([]byte, error) {
	wrapper := struct {
		ReturnInbound
		Response json.RawMessage `json:"Response"`
	}{
		ReturnInbound: *in,
		Response:      EncodeAnyByteArray(in.Response),
	}
	wrapper.action.resetUint64Fields()
	return json.Marshal(wrapper)
}

// CallOutbound represents a rpc call of outbound.
type CallOutbound struct {
	action
	Peer net.TCPAddr `json:"Peer"`
	//UnixAddr     net.UnixAddr `json:"UnixAddr"`
	Request      []byte `json:"Request"`
	Response     []byte `json:"Response"`
	ResponseTime uint64 `json:"ResponseTime"`
	CSpanID      []byte `json:"CSpanId"`

	Local string `json:"-"`
	Done  bool   `json:"-"`
}

// IsValid returns whether this is valid action
func (out *CallOutbound) IsValid() bool {
	if out.sendMore || out.recvMore {
		return false
	}
	return true
}

// MarshalJSON json encode
func (out *CallOutbound) MarshalJSON() ([]byte, error) {
	wrapper := struct {
		CallOutbound
		Request  json.RawMessage `json:"Request"`
		Response json.RawMessage `json:"Response"`
		CSpanID  json.RawMessage `json:"CSpanId"`
	}{
		CallOutbound: *out,
		Request:      EncodeAnyByteArray(out.Request),
		Response:     EncodeAnyByteArray(out.Response),
		CSpanID:      EncodeAnyByteArray(out.CSpanID),
	}
	wrapper.action.resetUint64Fields()
	return json.Marshal(wrapper)
}

// AppendFile represents a file append operation.
type AppendFile struct {
	action
	FileName string `json:"FileName"`
	Content  []byte `json:"Content"`
}

// IsValid returns whether this is valid action
func (af *AppendFile) IsValid() bool {
	if af.sendMore {
		return false
	}
	return len(af.FileName) > 0 && len(af.Content) > 0
}

// MarshalJSON json encode
func (af *AppendFile) MarshalJSON() ([]byte, error) {
	wrapper := struct {
		AppendFile
		Content json.RawMessage `json:"Content"`
	}{
		AppendFile: *af,
		Content:    EncodeAnyByteArray(af.Content),
	}
	wrapper.resetUint64Fields()
	return json.Marshal(wrapper)
}

// SendUDP represents a udp send operation.
type SendUDP struct {
	action
	Peer    net.UDPAddr `json:"Peer"`
	Content []byte      `json:"Content"`
}

// IsValid returns whether this is valid action
func (su *SendUDP) IsValid() bool {
	if su.sendMore {
		return false
	}
	return len(su.Content) > 0
}

// MarshalJSON json encode
func (su *SendUDP) MarshalJSON() ([]byte, error) {
	wrapper := struct {
		SendUDP
		Content json.RawMessage `json:"Content"`
	}{
		SendUDP: *su,
		Content: EncodeAnyByteArray(su.Content),
	}
	wrapper.resetUint64Fields()
	return json.Marshal(wrapper)
}

// ReadStorage read storage
type ReadStorage struct {
	action
	Content []byte `json:"Content"`
}

// IsValid returns whether this is valid action
func (rs *ReadStorage) IsValid() bool {
	if rs.sendMore {
		return false
	}
	return len(rs.Content) > 0
}

// MarshalJSON json encode
func (rs *ReadStorage) MarshalJSON() ([]byte, error) {
	wrapper := struct {
		ReadStorage
		Content json.RawMessage `json:"Content"`
	}{
		ReadStorage: *rs,
		Content:     EncodeAnyByteArray(rs.Content),
	}
	wrapper.resetUint64Fields()
	return json.Marshal(wrapper)
}
