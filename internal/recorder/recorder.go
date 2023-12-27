package recorder

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/didi/yarc/internal/log"
	"github.com/didi/yarc/pkg/event"
	"github.com/didi/yarc/pkg/model"
	"github.com/rs/zerolog"

	"golang.org/x/time/rate"
)

// SessionRecorder is responsible for recording the traffic of a single process.
type SessionRecorder struct {
	options     Options
	writer      SessionWriter
	stopWait    sync.WaitGroup
	stopChan    chan bool
	resetChan   chan uint64
	eventChan   chan *event.Item
	sessionChan chan *model.Session
	eventStat   EventStat
	lastEventID uint64
	eventBuf    event.SortIntf
	bufPool     *sync.Pool
	dataBuf     []byte
	limiter     *RateLimiter
	startDump   time.Time
	procTime    time.Time
	sessions    map[uint64]*model.Session
	threads     map[uint64]*model.Thread
	sockets     map[uint64]*model.Socket
}

// Status recorder status
type Status struct {
	PID       int     `json:"pid"`
	Hostname  string  `json:"hostname"`
	LogFile   string  `json:"log_file"`
	RateLimit float64 `json:"rate_limit"`
}

// EventStat perf event stat
type EventStat struct {
	SocketAcceptCnt  uint64
	SocketConnectCnt uint64
	SocketInfoCnt    uint64
	SocketSendMsgCnt uint64
	SocketRecvMsgCnt uint64
	SocketCloseCnt   uint64
	GoNewProcCnt     uint64
}

var (
	errEventChanIsFull = errors.New("perf event channel is full")
	errWaitStart       = errors.New("wait start")
	errInvalidThreadID = errors.New("invalid thread id")
	errInvalidInbound  = errors.New("invalid inbound")
	errEmptyInbound    = errors.New("empty inbound")
	errDataLost        = errors.New("data lost")
	errRateLimit       = errors.New("rate limit")
)

// NewSessionRecorder create a recorder
func NewSessionRecorder(opts *Options, pool *sync.Pool) RecorderIntf {
	limiter := NewRateLimiter(rate.Limit(opts.RateLimit), 3)
	for _, str := range opts.BlackList {
		limiter.NotAllow(str)
	}

	return &SessionRecorder{
		options:  *opts,
		writer:   opts.SessionWriter,
		limiter:  limiter,
		bufPool:  pool,
		dataBuf:  make([]byte, event.EventMaxDataLen),
		sessions: map[uint64]*model.Session{},
		threads:  map[uint64]*model.Thread{},
		sockets:  map[uint64]*model.Socket{},
	}
}

// Start sets the first sequence number of perf event, and starts recording.
func (rc *SessionRecorder) Start(seq uint64) error {
	rc.resetChan = make(chan uint64, 1)
	rc.eventChan = make(chan *event.Item, rc.options.EventBufSize)
	rc.eventBuf = event.NewMinHeap(rc.options.EventBufSize, rc.options.MinEventCount)
	rc.startDump = time.Now().Add(15 * time.Second)
	rc.sessionChan = make(chan *model.Session, rc.options.SessionBufSize)
	rc.stopChan = make(chan bool, 2)
	rc.stopWait.Add(2)
	go rc.processPerfEvents()
	go rc.dumpSessions()
	return nil
}

// Reset resets recording
func (rc *SessionRecorder) Reset(seq uint64) error {
	rc.startDump = time.Now().Add(15 * time.Second)
	rc.resetChan <- seq
	return nil
}

func (rc *SessionRecorder) reset(seq uint64) error {
	rc.eventBuf.Reset(seq)
	rc.sessions = map[uint64]*model.Session{}
	rc.threads = map[uint64]*model.Thread{}
	rc.sockets = map[uint64]*model.Socket{}
	return nil
}

// Stop stops recording
func (rc *SessionRecorder) Stop() {
	rc.stopChan <- true
	rc.stopChan <- true
	rc.stopWait.Wait()
	close(rc.stopChan)
	close(rc.eventChan)
	rc.stopChan = nil
	rc.eventChan = nil
	rc.eventBuf = nil
	close(rc.sessionChan)
	rc.sessionChan = nil
}

// Status returns the recorder status.
func (rc *SessionRecorder) Status() *Status {
	return &Status{
		Hostname:  rc.options.Hostname,
		RateLimit: rc.options.RateLimit,
	}
}

// GetSocket returns the Socket with the specified id.
func (rc *SessionRecorder) GetSocket(id uint64) model.Socket {
	sock, ok := rc.sockets[id]
	if ok && sock != nil {
		return *sock
	}
	return model.Socket{}
}

// GetThread returns the Thread with the specified id.
func (rc *SessionRecorder) GetThread(id uint64) model.Thread {
	thr, ok := rc.threads[id]
	if ok && thr != nil {
		return *thr
	}
	return model.Thread{}
}

// GetSesion returns the Sesion with the specified id.
func (rc *SessionRecorder) GetSesion(id uint64) model.Session {
	s, ok := rc.sessions[id]
	if ok && s != nil {
		return *s
	}
	return model.Session{}
}

// RecvPerfEvent is the callback for receiving perf event.
func (rc *SessionRecorder) RecvPerfEvent(item *event.Item) error {
	select {
	case rc.eventChan <- item:
	default:
		rc.bufPool.Put(item)
		return errEventChanIsFull
	}
	return nil
}

// SetDumpLimit updates session dump rate for the specified uri.
func (rc *SessionRecorder) SetDumpLimit(uri string, limit float64, burst int) {
	rc.limiter.Set(uri, limit, burst)
}

func (rc *SessionRecorder) processPerfEvents() {
	proc := func(item *event.Item) {
		err := rc.eventBuf.Push(item)
		if err != nil {
			log.Error().Err(err).Uint64("id", item.ID).Msg("push failed")
			return
		}

		for rc.eventBuf.Next() {
			item, ok := rc.eventBuf.Pop()
			if !ok {
				log.Error().Msg("pop failed")
				break
			}
			if item.ID != 0 && item.ID < rc.lastEventID {
				log.Error().Uint64("id", item.ID).
					Uint64("last", rc.lastEventID).Msg("event id wrap around")
			}
			rc.lastEventID = item.ID
			rc.processPerfEvent(item.Data, item.RecvTime)

			if rc.bufPool != nil {
				rc.bufPool.Put(item)
			}
		}
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case seq := <-rc.resetChan:
			log.Info().Uint64("seq", seq).Msg("reset")
			rc.reset(seq)
		case item := <-rc.eventChan:
			if item.Lost > 0 {
				log.Error().Uint64("lost", item.Lost).Msg("lost event")
			}
			proc(item)
		case <-ticker.C:
			log.Info().Uint64("SocketAccept", rc.eventStat.SocketAcceptCnt).
				Uint64("SocketConnect", rc.eventStat.SocketConnectCnt).
				Uint64("SocketInfo", rc.eventStat.SocketInfoCnt).
				Uint64("SocketSendMsg", rc.eventStat.SocketSendMsgCnt).
				Uint64("SocketRecvMsg", rc.eventStat.SocketRecvMsgCnt).
				Uint64("SocketClose", rc.eventStat.SocketCloseCnt).
				Uint64("GoNewProc", rc.eventStat.GoNewProcCnt).
				Msg("processPerfEvents: perf event stat")
			rc.eventStat = EventStat{}
			rc.cleanExpireData()
		case <-rc.stopChan:
			log.Info().Msg("processPerfEvents: recv stop msg")
			goto exit
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}

exit:
	log.Info().Msg("processPerfEvents: exit")
	rc.stopWait.Done()
}

func (rc *SessionRecorder) processPerfEvent(b []byte, ts uint64) {
	var hdr event.Header
	reader := bytes.NewReader(b)
	if err := hdr.Read(reader); err != nil {
		log.Error().Err(err).Msg("processPerfEvent: read event failed")
		return
	}

	if hdr.Version != event.YarcVersion {
		log.Error().Uint8("version", hdr.Version).Uint16("type", hdr.Type).
			Msg("processPerfEvent: unknown version")
		return
	}

	// 更新当前时间, 处理事件时使用
	rc.procTime = time.Now()

	switch event.Source(hdr.Source) {
	case event.EventSourceDebug:
		rc.processDebugEvent(&hdr, reader, ts)
	case event.EventSourceSocket:
		rc.processSockEvent(&hdr, reader, ts)
	default:
		log.Warn().Uint8("source", hdr.Source).
			Msg("processPerfEvent: unknown source")
	}
}

func (rc *SessionRecorder) sendSession(s *model.Session) {
	if s == nil {
		return
	}
	select {
	case rc.sessionChan <- s:
		log.Info().Msg("yarc.Session.Recording")
	default:
		log.Error().Msg("session channel is full")
	}
}

func (rc *SessionRecorder) dumpSessions() {
	count := 0
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case si := <-rc.sessionChan:
			if si == nil {
				continue
			}

			if err := rc.allowDump(si); err != nil {
				log.Debug().Str("session.ID", si.SessionID).
					Err(err).Msg("not allow to dump")
				si.Release()
				continue
			}

			log.Info().Str("session.ID", si.SessionID).
				Str("session.Status", si.Status).Msg("dump session")
			si.Timestamp = uint64(time.Now().UnixNano() / 1e6)
			rc.writer.Write(si)
			si.Release()
			count++
		case <-ticker.C:
			log.Info().Int("count", count).Int("queued", len(rc.sessionChan)).
				Msg("dumpSessions: tick")
			count = 0
		case <-rc.stopChan:
			log.Info().Msg("dumpSessions: recv stop msg")
			goto exit
		}
	}

exit:
	log.Info().Msg("dumpSessions: exit")
	rc.stopWait.Done()
}

func (rc *SessionRecorder) allowDump(s *model.Session) error {
	if s.LastAccess.Before(rc.startDump) {
		return errWaitStart
	}

	if s.ThreadID == 0 {
		return errInvalidThreadID
	}

	if s.InboundRequest == nil || len(s.InboundRequest.Request) <= 0 {
		return errInvalidInbound
	}

	if s.InboundResponse == nil || len(s.InboundResponse.Response) <= 0 {
		log.Warn().Str("session.ID", s.SessionID).
			Uint64("Thread", s.InboundRequest.ThreadID).
			Uint64("Socket", s.InboundRequest.SocketFD).
			Bytes("InboundRequest", s.InboundRequest.Request).
			Msg("InboundResponse is empty")
		return errEmptyInbound
	}

	if s.DataLost > 0 {
		log.Warn().Str("session.ID", s.SessionID).
			Uint64("Thread", s.InboundRequest.ThreadID).
			Int("DataLost", s.DataLost).Msg("data lost")
		return errDataLost
	}

	if s.UDPLost > 0 {
		// ignore udp lost
		log.Warn().Str("session.ID", s.SessionID).
			Uint64("Thread", s.InboundRequest.ThreadID).
			Int("DataLost", s.DataLost).Msg("udp lost")
		return errDataLost
	}

	_, allow := rc.limiter.Allow(s.InboundRequest.Request, rc.options.Protocol)
	if !allow {
		return errRateLimit
	}

	return nil
}

func (rc *SessionRecorder) cleanExpireData() {
	now := time.Now()
	activeSessionCount := 0
	activeSessions := make(map[uint64]*model.Session, len(rc.sessions))
	for id, session := range rc.sessions {
		if now.Sub(session.LastAccess) < rc.options.SessionExpire {
			activeSessions[id] = session
			activeSessionCount++
		} else {
			session = session.Shutdown("timeout")
			if session.DataLost == 0 {
				rc.sendSession(session)
			}
			log.Debug().Str("id", session.SessionID).
				Int("DataLost", session.DataLost).Msg("session expire")
		}
	}
	rc.sessions = activeSessions

	activeThreadCount := 0
	activeThreads := make(map[uint64]*model.Thread, len(rc.threads))
	for id, thread := range rc.threads {
		if now.Sub(thread.LastAccess) < rc.options.ThreadExpire {
			activeThreads[id] = thread
			activeThreadCount++
		} else {
			log.Debug().Uint64("id", id).Msg("thread expire")
		}
	}
	rc.threads = activeThreads

	activeSocketCount := 0
	activeSockets := make(map[uint64]*model.Socket, len(rc.sockets))
	for id, socket := range rc.sockets {
		if now.Sub(socket.LastAccess) < rc.options.SocketExpire {
			activeSockets[id] = socket
			activeSocketCount++
		} else {
			log.Debug().Uint64("id", id).Msg("socket expire")
		}
	}
	rc.sockets = activeSockets

	log.Info().Int("activeSessionCount", activeSessionCount).
		Int("activeThreadCount", activeThreadCount).
		Int("activeSocketCount", activeSocketCount).Msg("cleanExpireData")
}

func (rc *SessionRecorder) processDebugEvent(hdr *event.Header, reader io.Reader, ts uint64) {
	e := event.DebugEvent{}
	err := e.Read(reader)
	if err != nil {
		log.Warn().Err(err).Msg("binary read failed")
		return
	}

	info := event.DebugInfo(event.DebugEventType(hdr.Type), e)
	if hdr.Type >= uint16(event.DebugBpfPerfEventOutputError) {
		log.Error().Str("data", info).Msg("debug event")
	} else {
		log.Debug().Str("data", info).Msg("debug event")
	}

	rc.updateThreadAccess(hdr.GOID)
}

func (rc *SessionRecorder) processSockEvent(hdr *event.Header, reader io.Reader, ts uint64) {
	switch event.Type(hdr.Type) {
	case event.EventSockSendmsg:
		rc.processSockSendMsg(hdr, reader, ts)
		rc.eventStat.SocketSendMsgCnt++
	case event.EventSockRecvmsg:
		rc.processSockRecvMsg(hdr, reader, ts)
		rc.eventStat.SocketRecvMsgCnt++
	case event.EventSockClose:
		rc.processSockClose(hdr, reader)
		rc.eventStat.SocketCloseCnt++
	case event.EventSockAccept:
		rc.processSockAccept(hdr, reader)
		rc.eventStat.SocketAcceptCnt++
	case event.EventSockConnect:
		rc.processSockConnect(hdr, reader)
		rc.eventStat.SocketConnectCnt++
	case event.EventSockInfo:
		rc.processSocketInfo(hdr, reader)
		rc.eventStat.SocketInfoCnt++
	case event.EventGoNewProc:
		rc.processGoNewProc(hdr, reader)
		rc.eventStat.GoNewProcCnt++
	default:
		log.Error().Uint16("type", uint16(hdr.Type)).
			Msg("processSockEvent: unknown event type")
	}
}

func (rc *SessionRecorder) processSockAccept(hdr *event.Header, body io.Reader) {
	var event event.SockAccept
	err := event.Read(body)
	if err != nil {
		log.Error().Err(err).Msg("processSockAccept: read event failed")
		return
	}

	ip, port := model.InetSockAddrString(event.SockAddrData)

	log.Debug().Str("event", "accept").
		Uint16("type", uint16(hdr.Type)).
		Uint32("tgid", hdr.TGID).
		Uint32("pid", hdr.PID).
		Uint64("id", hdr.ID).
		Uint64("goid", hdr.GOID).
		Uint64("sock", event.Sock).
		Uint64("newsock", event.NewSock).
		Str("peer_ip", ip.String()).
		Int("peer_port", port).Msg("")

	socket := rc.sockets[event.NewSock]
	if socket == nil {
		socket = &model.Socket{
			ID: event.NewSock,
		}
		rc.sockets[event.NewSock] = socket
	}
	socket.CreateBy = model.Accept
	socket.Reset = true
	socket.Family = model.AddressFamily(event.SockFamily)
	socket.Type = model.SockType(event.SockType)
	socket.PeerIPAddr = ip
	socket.PeerPort = port
	socket.PeerAddr = fmt.Sprintf("%s:%d", ip.String(), port)
	socket.LastAccess = time.Now()

	si := rc.lookupSessionByThread(hdr.GOID)
	if si != nil {
		dump := si.OnSockAccept()
		rc.sendSession(dump)
	}
}

func (rc *SessionRecorder) processSockConnect(hdr *event.Header, body io.Reader) {
	var event event.SockConnect
	err := event.Read(body)
	if err != nil {
		log.Error().Err(err).Msg("processSockConnect: read event failed")
		return
	}

	if event.SockFamily != uint16(model.Inet) {
		log.Info().Uint16("sock_family", event.SockFamily).
			Msg("unsupport socket family")
		return
	}

	ip, port := model.InetSockAddrString(event.SockAddrData)

	log.Debug().Str("event", "connect").
		Uint16("type", uint16(hdr.Type)).
		Uint32("tgid", hdr.TGID).
		Uint32("pid", hdr.PID).
		Uint64("id", hdr.ID).
		Uint64("goid", hdr.GOID).
		Uint64("sock", event.Sock).
		Str("IP", ip.String()).
		Int("port", port).Msg("")

	socket := rc.sockets[event.Sock]
	if socket == nil {
		socket = &model.Socket{
			ID: event.Sock,
		}
		rc.sockets[event.Sock] = socket
	}
	socket.CreateBy = model.Connect
	socket.Reset = true
	socket.Family = model.AddressFamily(event.SockFamily)
	socket.Type = model.SockType(event.SockType)
	socket.PeerIPAddr = ip
	socket.PeerPort = port
	socket.PeerAddr = fmt.Sprintf("%s:%d", ip.String(), port)
	socket.LastAccess = time.Now()
}

func (rc *SessionRecorder) processSocketInfo(hdr *event.Header, body io.Reader) {
	var event event.SocketInfo
	err := event.Read(body)
	if err != nil {
		log.Error().Err(err).Msg("processSocketInfo: read event failed")
		return
	}

	if event.SockFamily != uint16(model.Inet) {
		log.Info().Uint16("sock_family", event.SockFamily).
			Msg("unsupport socket family")
		return
	}

	ip, port := model.InetSockAddrString(event.SockAddrData)

	log.Debug().Str("event", "socket_info").
		Uint16("type", uint16(hdr.Type)).
		Uint32("tgid", hdr.TGID).
		Uint32("pid", hdr.PID).
		Uint64("id", hdr.ID).
		Uint64("goid", hdr.GOID).
		Uint64("sock", event.Sock).
		Str("IP", ip.String()).
		Int("port", port).Msg("")

	socket := rc.sockets[event.Sock]
	if socket == nil {
		socket = &model.Socket{
			ID: event.Sock,
		}
		rc.sockets[event.Sock] = socket
	}
	socket.Family = model.AddressFamily(event.SockFamily)
	socket.Type = model.SockType(event.SockType)
	socket.PeerIPAddr = ip
	socket.PeerPort = port
	socket.PeerAddr = fmt.Sprintf("%s:%d", ip.String(), port)
	socket.LastAccess = time.Now()
}

func (rc *SessionRecorder) processSockSendMsg(hdr *event.Header, body io.Reader, ts uint64) {
	var e event.SockSendRecv
	err := e.Read(body)
	if err != nil {
		log.Error().Err(err).Msg("processSockSendMsg: read event failed")
		return
	}

	if e.Len > event.EventMaxDataLen {
		log.Error().Uint32("len", e.Len).Uint32("max", event.EventMaxDataLen).
			Msg("processSockSendMsg: exceed max data length")
		return
	}

	var lost int
	flag := uint8(e.Offset >> 28)
	more := flag&event.DataFlagMore > 0
	offset := e.Offset & 0x0FFFFFFF
	if flag&event.DataFlagTruncated > 0 {
		lost = 1
		log.Warn().Msg("processSockSendMsg: data was truncated")
	}

	data := rc.dataBuf[:e.Len]
	n, err := body.Read(data)
	if err != nil {
		log.Error().Err(err).Uint8("flag", flag).Uint32("offset", offset).
			Msg("processSockRecvMsg: body.Read failed")
		return
	}
	if n != int(e.Len) {
		log.Error().Int("read", n).Uint32("len", e.Len).
			Msg("processSockRecvMsg: read < len")
		return
	}

	logSize := rc.options.MaxLogDataLen
	if n < logSize {
		logSize = n
	}
	if log.G().GetLevel() == zerolog.DebugLevel {
		log.Debug().Str("event", "sock_sendmsg").
			Uint16("type", uint16(hdr.Type)).
			Uint32("tgid", hdr.TGID).
			Uint32("pid", hdr.PID).
			Uint64("id", hdr.ID).
			Uint64("goid", hdr.GOID).
			Uint64("sock", e.Sock).
			Uint8("flag", flag).
			Uint32("offset", offset).
			Int("len", len(data)).
			Bytes("data", data[0:logSize]).
			Msg("")
	}

	socket := rc.sockets[e.Sock]
	if socket == nil {
		socket = &model.Socket{
			ID:     e.Sock,
			Family: model.AddressFamily(e.SockFamily),
			Type:   model.SockType(e.SockType),
		}
		rc.sockets[e.Sock] = socket
	}
	socket.LastAccess = rc.procTime

	if socket.Family == model.Netlink {
		log.Warn().Msg("ignore socket family AF_NETLINK")
		return
	}

	if socket.SendOffset != offset {
		lost = 1
		log.Warn().Uint32("expect", socket.SendOffset).Uint32("actual", offset).
			Msg("unexpect send offset")
	}
	if more {
		socket.SendOffset = offset + e.Len
	} else {
		socket.SendOffset = 0
	}

	var si *model.Session
	if si == nil {
		si = rc.lookupSessionByThread(hdr.GOID)
	}
	if si == nil {
		log.Debug().Uint64("goid", hdr.GOID).
			Uint64("sock", e.Sock).Bytes("data", data[0:logSize]).
			Msg("processSockSendMsg: session not found")
		return
	}
	si.OnSockSendMsg(hdr.GOID, socket, ts, data[:n], more)
	si.DataLost += lost
}

func (rc *SessionRecorder) processSockRecvMsg(hdr *event.Header, body io.Reader, ts uint64) {
	var e event.SockSendRecv
	err := e.Read(body)
	if err != nil {
		log.Error().Err(err).Msg("processSockRecvMsg: read event failed")
		return
	}

	if e.Len > event.EventMaxDataLen {
		log.Error().Uint32("len", e.Len).Uint32("max", event.EventMaxDataLen).
			Msg("processSockSendMsg: exceed max data length")
		return
	}

	var lost int
	flag := uint8(e.Offset >> 28)
	more := flag&event.DataFlagMore > 0
	offset := e.Offset & 0x0FFFFFFF
	if flag&event.DataFlagTruncated > 0 {
		lost = 1
		log.Warn().Msg("processSockSendMsg: data was truncated")
	}

	data := rc.dataBuf[:e.Len]
	n, err := body.Read(data)
	if err != nil {
		log.Error().Err(err).Uint8("flag", flag).Uint32("offset", offset).
			Msg("processSockRecvMsg: body.Read failed")
		return
	}
	if n != int(e.Len) {
		log.Error().Int("read", n).Uint32("len", e.Len).
			Msg("processSockRecvMsg: read < len")
		return
	}

	logSize := rc.options.MaxLogDataLen
	if n < logSize {
		logSize = n
	}
	if log.G().GetLevel() == zerolog.DebugLevel {
		log.Debug().Str("event", "sock_recvmsg").
			Uint16("type", uint16(hdr.Type)).
			Uint32("tgid", hdr.TGID).
			Uint32("pid", hdr.PID).
			Uint64("id", hdr.ID).
			Uint64("goid", hdr.GOID).
			Uint64("sock", e.Sock).
			Uint8("flag", flag).
			Uint32("offset", offset).
			Int("len", len(data)).
			Bytes("data", data[0:logSize]).
			Msg("")
	}

	socket, ok := rc.sockets[e.Sock]
	if !ok {
		socket = &model.Socket{
			ID:     e.Sock,
			Family: model.AddressFamily(e.SockFamily),
			Type:   model.SockType(e.SockType),
		}
		rc.sockets[e.Sock] = socket
	}
	socket.LastAccess = rc.procTime

	if socket.Family == model.Netlink {
		log.Warn().Msg("ignore AF_NETLINK")
		return
	}

	if socket.RecvOffset != offset {
		lost = 1
		log.Warn().Uint32("expect", socket.RecvOffset).Uint32("actual", offset).Msg("unexpect recv offset")
	}
	if more {
		socket.RecvOffset = offset + e.Len
	} else {
		socket.RecvOffset = 0
	}

	if socket.CreateBy == model.Unknown && matchHttpLine(data) {
		socket.CreateBy = model.Accept
	}

	var si *model.Session
	if socket.CreateBy == model.Accept {
		si = rc.lookupSessionByThread(hdr.GOID)
		if si == nil {
			si = rc.createSession(hdr.GOID)
			// make the thread as a root thread
			rc.saveThread(hdr.GOID, 0)
		}
	} else {
		if si == nil {
			si = rc.lookupSessionByThread(hdr.GOID)
		}
		if si == nil {
			log.Debug().Uint64("goid", hdr.GOID).
				Uint64("sock", e.Sock).Bytes("data", data[0:logSize]).
				Msg("processSockRecvMsg: session not found")
			return
		}
	}

	dump := si.OnSockRecvMsg(hdr.GOID, socket, ts, data[:n], more)
	if dump != nil {
		rc.sendSession(dump)
	}

	si.DataLost += lost
}

func (rc *SessionRecorder) processSockClose(hdr *event.Header, body io.Reader) {
	var event event.SockClose
	err := event.Read(body)
	if err != nil {
		log.Error().Err(err).Msg("processSockClose: read event failed")
		return
	}

	log.Debug().Str("event", "sock_close").
		Uint8("type", uint8(hdr.Type)).
		Uint32("tgid", hdr.TGID).
		Uint32("pid", hdr.PID).
		Uint64("id", hdr.ID).
		Uint64("goid", hdr.GOID).
		Uint64("sock", event.Sock).Msg("")

	socket, ok := rc.sockets[event.Sock]
	if ok {
		delete(rc.sockets, event.Sock)
	} else {
		socket = &model.Socket{ID: event.Sock}
	}

	si := rc.lookupSessionByThread(hdr.GOID)
	if si == nil {
		log.Debug().Uint64("goid", hdr.GOID).
			Uint64("sock", event.Sock).Msg("processSockClose: session not found")
		return
	}
	dump := si.OnSockClose(hdr.GOID, socket)
	rc.sendSession(dump)
}

func (rc *SessionRecorder) processGoNewProc(hdr *event.Header, body io.Reader) {
	var event event.GoNewProc
	err := event.Read(body)
	if err != nil {
		log.Error().Err(err).Msg("processGoNewProc: read event failed")
		return
	}

	log.Debug().Str("event", "go_newproc").
		Uint8("type", uint8(hdr.Type)).
		Uint32("tgid", hdr.TGID).
		Uint32("pid", hdr.PID).
		Uint64("id", hdr.ID).
		Uint64("goid", hdr.GOID).
		Uint64("newgoid", event.GOID).Msg("")

	if event.GOID == 0 || hdr.GOID == event.GOID {
		log.Error().Uint64("hdr.GOID", hdr.GOID).
			Uint64("event.GOID", event.GOID).Msg("invalid NewProc GOID")
		return
	}

	root := rc.findRootThreadID(hdr.GOID)
	rc.saveThread(event.GOID, root)
}

func (rc *SessionRecorder) createSession(threadID uint64) *model.Session {
	si := model.NewSession(rc.options.ServiceName, rc.options.ClusterName,
		rc.options.Hostname, threadID, rc.options.MaxActions)
	rc.sessions[threadID] = si
	return si
}

func (rc *SessionRecorder) lookupSessionByThread(threadID uint64) *model.Session {
	si := rc.sessions[threadID]
	if si != nil {
		return si
	}

	pt := rc.threads[threadID]
	if pt != nil {
		pt.LastAccess = rc.procTime
		si := rc.sessions[pt.ParentID]
		if si != nil {
			// 避免返回已经结束的session
			if si.InboundRequest != nil {
				return si
			}
		}
	}
	return nil
}

func (rc *SessionRecorder) updateThreadAccess(id uint64) {
	if thread := rc.threads[id]; thread != nil {
		thread.LastAccess = rc.procTime
	}
}

func (rc *SessionRecorder) findRootThreadID(id uint64) uint64 {
	for {
		pt := rc.threads[id]
		if pt == nil || pt.ParentID == 0 {
			break
		}
		id = pt.ParentID
	}
	return id
}

func (rc *SessionRecorder) saveThread(id, parent uint64) *model.Thread {
	thread := rc.threads[id]
	if thread == nil {
		thread = &model.Thread{ID: id}
		rc.threads[id] = thread
	}
	thread.ParentID = parent
	thread.LastAccess = rc.procTime
	return thread
}

func matchHttpLine(data []byte) bool {
	if !matchHTTPMethod(data) {
		return false
	}
	index := bytes.Index(data, []byte("\r\n"))
	if index < 0 {
		return false
	}
	return bytes.Contains(data[:index], []byte("HTTP/1."))
}

var httpMethods = [][]byte{
	[]byte(http.MethodGet),
	[]byte(http.MethodPost),
	[]byte(http.MethodPut),
	[]byte(http.MethodDelete),
	[]byte(http.MethodHead),
	[]byte(http.MethodPatch),
	[]byte(http.MethodConnect),
	[]byte(http.MethodOptions),
	[]byte(http.MethodTrace),
}

func matchHTTPMethod(data []byte) bool {
	for _, method := range httpMethods {
		if bytes.HasPrefix(data, method) {
			return true
		}
	}
	return false
}
