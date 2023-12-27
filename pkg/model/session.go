package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/didi/yarc/pkg/buffer"
)

// Session contains all actions performanced during the processing of a request,
// including request, response and all rpc calls.
type Session struct {
	ServiceName     string           `json:"ServiceName"`
	Cluster         string           `json:"Cluster"`
	Context         string           `json:"Context"`
	ThreadID        uint64           `json:"ThreadId"`
	SessionID       string           `json:"SessionId"`
	SpanID          string           `json:"SpanId"`
	NextSessionID   string           `json:"NextSessionId"`
	InboundRequest  *CallFromInbound `json:"CallFromInbound"`
	InboundResponse *ReturnInbound   `json:"ReturnInbound"`
	Actions         []Action         `json:"Actions"`
	Status          string           `json:"Status"`
	Timestamp       uint64           `json:"timestamp"`

	LastAccess    time.Time       `json:"-"`
	DataLost      int             `json:"-"`
	UDPLost       int             `json:"-"`
	MaxActions    int             `json:"-"`
	callOutbounds []*CallOutbound `json:"-"`
}

var bufPool = buffer.NewPool()

// NewSession new session
func NewSession(service, cluster, ctx string, threadID uint64, maxActions int) *Session {
	return &Session{
		ServiceName: service,
		Cluster:     cluster,
		Context:     ctx,
		ThreadID:    threadID,
		SessionID:   fmt.Sprintf("%d-%d", time.Now().UnixNano(), threadID),
		MaxActions:  maxActions,
		LastAccess:  time.Now(),
	}
}

// Reset resets the session for reuse.
func (si *Session) Reset(nextSessionID string) {
	si.SessionID = nextSessionID
	si.SpanID = ""
	si.InboundRequest = nil
	si.InboundResponse = nil
	si.Actions = nil
	si.Status = ""
	si.DataLost = 0
	si.UDPLost = 0
	si.callOutbounds = nil
	si.LastAccess = time.Now()
}

// OnSockAccept is the callback for socket accept event.
func (si *Session) OnSockAccept() *Session {
	var dump *Session
	if si.hasResponded() {
		dump = si.Shutdown("next_accept")
	}
	si.Reset(si.nextSessionID())
	return dump
}

// OnSockSendMsg is the callback for socket send event.
func (si *Session) OnSockSendMsg(threadID uint64, socket *Socket, unixNano uint64, data []byte, more bool) {
	si.LastAccess = time.Now()
	if socket.CreateBy == Accept {
		si.sendtoInbound(threadID, socket, unixNano, data, more)
		return
	}
	if socket.Family == Inet && socket.Type == SockDgram {
		si.sendUDP(threadID, socket, unixNano, data, more)
	} else {
		si.sendtoOutbound(threadID, socket, unixNano, data, more)
	}
}

// OnSockRecvMsg is the callback for socket recv event.
func (si *Session) OnSockRecvMsg(threadID uint64, socket *Socket, unixNano uint64, data []byte, more bool) *Session {
	si.LastAccess = time.Now()
	if socket.CreateBy == Accept {
		return si.recvfromInbound(threadID, socket, unixNano, data, more)
	}
	si.recvFromOutbound(threadID, socket, unixNano, data, more)
	return nil
}

// OnSockClose is the callback for socket close event.
func (si *Session) OnSockClose(threadID uint64, socket *Socket) *Session {
	if socket.CreateBy == Accept {
		return si.Shutdown("closed")
	}
	return nil
}

// Shutdown finishes the session and returns a clone session.
func (si *Session) Shutdown(status string) *Session {
	si.Status = status

	for _, act := range si.Actions {
		if !act.IsValid() {
			si.DataLost++
		}
	}

	dump := &Session{
		ServiceName:     si.ServiceName,
		Cluster:         si.Cluster,
		Context:         si.Context,
		ThreadID:        si.ThreadID,
		SessionID:       si.SessionID,
		SpanID:          si.SpanID,
		NextSessionID:   si.NextSessionID,
		InboundRequest:  si.InboundRequest,
		InboundResponse: si.InboundResponse,
		Actions:         si.Actions,
		Status:          si.Status,
		DataLost:        si.DataLost,
		UDPLost:         si.UDPLost,
		LastAccess:      si.LastAccess,
	}
	si.Reset(si.nextSessionID())
	return dump
}

// Release frees the session and makes buffers reusable.
func (si *Session) Release() {
	if si.InboundRequest != nil && si.InboundRequest.Request != nil {
		buf := si.InboundRequest.Request
		si.InboundRequest.Request = nil
		bufPool.Put(buf)
	}

	if si.InboundResponse != nil && si.InboundResponse.Response != nil {
		buf := si.InboundResponse.Response
		si.InboundResponse.Response = nil
		bufPool.Put(buf)
	}

	for _, action := range si.Actions {
		if outbound, ok := action.(*CallOutbound); ok && outbound != nil {
			if outbound.Request != nil {
				buf := outbound.Request
				outbound.Request = nil
				bufPool.Put(buf)
			}
			if outbound.Response != nil {
				buf := outbound.Response
				outbound.Response = nil
				bufPool.Put(buf)
			}
		} else if sendUDP, ok := action.(*SendUDP); ok && sendUDP != nil {
			if sendUDP.Content != nil {
				buf := sendUDP.Content
				sendUDP.Content = nil
				bufPool.Put(buf)
			}
		}
	}
}

// MarshalJSON json encode
func (si *Session) MarshalJSON() ([]byte, error) {
	si.ThreadID &= math.MaxInt32
	return json.Marshal(*si)
}

func (si *Session) hasResponded() bool {
	return si.InboundResponse != nil && len(si.InboundResponse.Response) > 0
}

func (si *Session) nextSessionID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), si.ThreadID)
}

func (si *Session) newAction(actionType string, threadID, sockFD, unixNano uint64) action {
	return action{
		ActionIndex: len(si.Actions),
		OccurredAt:  unixNano,
		ActionType:  actionType,
		ThreadID:    threadID,
		SocketFD:    sockFD,
	}
}

func (si *Session) recvfromInbound(threadID uint64, socket *Socket, unixNano uint64, span []byte, more bool) *Session {
	// merge HTTP 100-continue
	if bytes.HasPrefix(span, []byte("POST ")) {
		span = bytes.Replace(span, []byte("Expect: 100-continue\r\n"), []byte{}, 1)
	}

	var dump *Session
	if si.hasResponded() || len(si.callOutbounds) > 0 {
		dump = si.Shutdown("pipeline")
	}

	if socket.Reset || si.InboundRequest == nil {
		socket.Reset = false
		si.InboundRequest = &CallFromInbound{
			action:  si.newAction("CallFromInbound", threadID, socket.ID, unixNano),
			Request: bufPool.Get(getBufSize(len(span), more)),
		}
	}
	if si.InboundRequest.Peer.Port == 0 {
		si.InboundRequest.Peer.IP = socket.PeerIPAddr
		si.InboundRequest.Peer.Port = socket.PeerPort
	}

	si.InboundRequest.Request = appendData(si.InboundRequest.Request, span)
	si.InboundRequest.recvMore = more
	return dump
}

func (si *Session) sendtoInbound(threadID uint64, socket *Socket, unixNano uint64, span []byte, more bool) {
	if si.InboundResponse == nil {
		si.InboundResponse = &ReturnInbound{
			action:   si.newAction("ReturnInbound", threadID, socket.ID, unixNano),
			Response: bufPool.Get(getBufSize(len(span), more)),
		}
	}

	// merge HTTP 100-continue
	if bytes.HasPrefix(span, []byte("HTTP/1.1 100 Continue\r\n\r\n")) {
		return
	}

	si.InboundResponse.Response = appendData(si.InboundResponse.Response, span)
	si.InboundResponse.sendMore = more
}

func (si *Session) sendtoOutbound(threadID uint64, socket *Socket, unixNano uint64, span []byte, more bool) {
	outbound := si.findOutboundForSend(socket)
	if outbound == nil {
		outbound = si.addCallOutbound(threadID, socket, unixNano)
	}
	if outbound.Request == nil {
		outbound.Request = bufPool.Get(getBufSize(len(span), more))
	}
	outbound.Request = appendData(outbound.Request, span)
	outbound.sendMore = more
}

func (si *Session) recvFromOutbound(threadID uint64, socket *Socket, unixNano uint64, span []byte, more bool) {
	outbound := si.findOutboundForRecv(socket)
	if outbound == nil {
		outbound = si.addCallOutbound(threadID, socket, unixNano)
	}
	if outbound.ResponseTime == 0 {
		outbound.ResponseTime = unixNano
	}
	if outbound.Response == nil {
		outbound.Response = bufPool.Get(getBufSize(len(span), more))
	}

	outbound.Response = appendData(outbound.Response, span)
	outbound.recvMore = more
}

func (si *Session) findOutboundForSend(socket *Socket) *CallOutbound {
	if socket.Reset {
		si.closeOutbounds(socket.ID)
		socket.Reset = false
		return nil
	}

	for _, out := range si.callOutbounds {
		if out.Done {
			continue
		}
		if out.SocketFD != socket.ID ||
			!out.Peer.IP.Equal(socket.PeerIPAddr) ||
			out.Peer.Port != socket.PeerPort {
			continue
		}
		if out.ResponseTime != 0 {
			// The outbound socket sends data again after receiving data,
			// which may be because the connection is reused. Therefore,
			// we mark the previous outbound action as completed and
			// create a new outbound action to save the data.
			out.Done = true
			continue
		}
		return out
	}
	return nil
}

func (si *Session) findOutboundForRecv(socket *Socket) *CallOutbound {
	if socket.Reset {
		si.closeOutbounds(socket.ID)
		socket.Reset = false
		return nil
	}

	for _, out := range si.callOutbounds {
		if out.Done {
			continue
		}
		if out.SocketFD != socket.ID ||
			!out.Peer.IP.Equal(socket.PeerIPAddr) ||
			out.Peer.Port != socket.PeerPort {
			continue
		}
		return out
	}
	return nil
}

func (si *Session) closeOutbounds(id uint64) {
	for _, out := range si.callOutbounds {
		if out.SocketFD == id {
			out.Done = true
		}
	}
}

func (si *Session) addCallOutbound(threadID uint64, socket *Socket, unixNano uint64) *CallOutbound {
	outbound := &CallOutbound{
		action: si.newAction("CallOutbound", threadID, socket.ID, unixNano),
		Peer: net.TCPAddr{
			IP:   socket.PeerIPAddr,
			Port: socket.PeerPort,
		},
		Local: socket.LocalAddr,
	}

	si.Actions = append(si.Actions, outbound)
	si.callOutbounds = append(si.callOutbounds, outbound)
	return outbound
}

func (si *Session) sendUDP(threadID uint64, socket *Socket, unixNano uint64, span []byte, more bool) {
	if len(si.Actions) > si.MaxActions {
		si.UDPLost++
		return
	}

	buf := bufPool.Get(len(span))
	action := &SendUDP{
		action: si.newAction("SendUDP", threadID, socket.ID, unixNano),
		Peer: net.UDPAddr{
			IP:   socket.PeerIPAddr,
			Port: socket.PeerPort,
		},
		Content: append(buf, span...),
	}
	// ingore udp's send more flag
	si.Actions = append(si.Actions, action)
}

func getBufSize(size int, more bool) int {
	if more {
		return size + size
	} else {
		return size
	}
}

func appendData(buf, data []byte) []byte {
	if (cap(buf)-len(buf)) >= len(data) || len(buf) > 32768 {
		return append(buf, data...)
	}

	newbuf := bufPool.Get(len(buf) + len(data))
	newbuf = append(newbuf, buf...)
	newbuf = append(newbuf, data...)
	bufPool.Put(buf)
	return newbuf
}
