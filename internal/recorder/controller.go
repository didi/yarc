package recorder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/didi/yarc/internal/log"
	"github.com/didi/yarc/pkg/elf"
	"github.com/didi/yarc/pkg/event"
	"github.com/didi/yarc/pkg/kallsyms"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// Controller maintains all processes being recorded.
type Controller struct {
	mu           sync.RWMutex
	stopChan     chan bool
	procExitChan chan int
	waitStop     sync.WaitGroup
	logSize      int
	bpfObjects   TrafficMirrorObjects
	perfReader   *perf.Reader
	eventBufPool sync.Pool
	links        []link.Link
	kprobes      []*linkConfig
	uprobes      []*linkConfig
	recorders    map[int]*recorderWrapper
}

type RecorderIntf interface {
	Start(seq uint64) error
	Reset(seq uint64) error
	Stop()
	Status() *Status
	RecvPerfEvent(e *event.Item) error
}

type recorderWrapper struct {
	recorder      RecorderIntf
	links         []link.Link
	lastKeepalive time.Time
}

type configItem struct {
	Seq       uint64
	GoVersion uint64
}

type linkConfig struct {
	FuncName     string
	SymbolOffset uint64
	EntryProgram *ebpf.Program
	ExitProgram  *ebpf.Program
}

var (
	errAlreadyStarted  = errors.New("already started")
	errProcessNotFound = errors.New("process not found")
)

// NewController create a controller
func NewController(logSize int) *Controller {
	return &Controller{
		logSize: logSize,
		eventBufPool: sync.Pool{
			New: func() interface{} {
				return &event.Item{
					Data: make([]byte, 0x1FFF),
				}
			},
		},
		recorders: map[int]*recorderWrapper{},
	}
}

// Start loads bpf objects and starts the read loop of perf event.
func (ctl *Controller) Start() error {
	err := ctl.loadBpfObjects()
	if err != nil {
		log.Error().Err(err).Msg("loadBpfObjects failed")
		return err
	}

	ctl.initLinkConfigs()
	err = ctl.linkKernelPrograms()
	if err != nil {
		log.Error().Err(err).Msg("linkKernelPrograms failed")
		return err
	}

	ctl.procExitChan = make(chan int, 1024)
	ctl.stopChan = make(chan bool, 1)
	ctl.waitStop.Add(1)
	go ctl.readPerfEvents()
	log.Info().Msg("controller started...")
	return nil
}

// Stop stops read loop and all recorders, unloads bpf objects.
func (ctl *Controller) Stop() {
	for _, link := range ctl.links {
		link.Close()
	}
	ctl.links = nil

	ctl.mu.Lock()
	for pid, wrapper := range ctl.recorders {
		ctl.unlinkUserPrograms(wrapper)
		log.Info().Int("pid", pid).Msg("stop record ...")
		wrapper.recorder.Stop()
		log.Info().Int("pid", pid).Msg("stop record done")
	}
	ctl.recorders = map[int]*recorderWrapper{}
	ctl.mu.Unlock()

	ctl.stopChan <- true
	ctl.perfReader.Close()
	ctl.waitStop.Wait()
	ctl.perfReader = nil
	ctl.bpfObjects.Close()
	log.Info().Msg("TrafficMirror: stopped")
}

// GetPerfEventMap returns the perf event map for reading data from kernel.
func (ctl *Controller) GetPerfEventMap() *ebpf.Map {
	return ctl.bpfObjects.PerfEventsMap
}

// StartRecord starts recording the specified process.
func (ctl *Controller) StartRecord(pid int, options ...Option) error {
	log.Info().Int("pid", pid).Msg("start record")

	opts := NewDefaultOptions()
	for _, opt := range options {
		opt(opts)
	}

	log.Info().Int("gover", opts.GoVersion).Msg("")

	ctl.mu.Lock()
	defer ctl.mu.Unlock()

	_, ok := ctl.recorders[pid]
	if ok {
		return errAlreadyStarted
	}

	recorder := opts.NewRecorder(opts, &ctl.eventBufPool)
	wrapper := &recorderWrapper{
		recorder:      recorder,
		lastKeepalive: time.Now(),
	}

	seq := uint64(time.Now().UnixNano() / 1e6)
	err := recorder.Start(seq + 1)
	if err != nil {
		return err
	}

	err = ctl.loadProcessConfig(pid, seq, opts.GoVersion)
	if err != nil {
		recorder.Stop()
		return err
	}

	if opts.GoVersion > 0 {
		err = ctl.linkUserPrograms(pid, wrapper)
		if err != nil {
			ctl.unlinkUserPrograms(wrapper)
			ctl.deleteProcessConfig(pid)
			recorder.Stop()
			return err
		}
	}

	ctl.recorders[pid] = wrapper
	return nil
}

// StopRecord stops recording the specified process.
func (ctl *Controller) StopRecord(pid int) error {
	log.Info().Int("pid", pid).Msg("stop record")

	ctl.mu.Lock()
	defer ctl.mu.Unlock()
	return ctl.stopRecordUnsafe(pid)
}

func (ctl *Controller) stopRecordUnsafe(pid int) error {
	wrapper, ok := ctl.recorders[pid]
	if !ok {
		return errProcessNotFound
	}

	ctl.deleteProcessConfig(pid)
	delete(ctl.recorders, pid)
	ctl.unlinkUserPrograms(wrapper)
	go wrapper.recorder.Stop()
	return nil
}

func (ctl *Controller) loadBpfObjects() error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	spec, err := LoadTrafficMirror()
	if err != nil {
		log.Error().Err(err).Msg("loadTrafficMirror failed")
		return err
	}

	// Different hosts may have different number of cpu cores,
	// so we need to set the max_entries of the map at runtime.
	// Maps of type BPF_MAP_TYPE_PERF_EVENT_ARRAY are handled in
	// cilium/ebpf, maps of type BPF_MAP_TYPE_PERCPU_ARRAY need
	// to be set manually.
	spec.Maps["event_buffer"].MaxEntries = uint32(runtime.NumCPU())

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{},
		Programs: ebpf.ProgramOptions{
			LogSize: ctl.logSize,
		},
	}
	err = spec.LoadAndAssign(&ctl.bpfObjects, &opts)
	if err != nil {
		log.Error().Err(err).Msg("spec.LoadAndAssign failed")
		return err
	}

	ctl.perfReader, err = perf.NewReader(ctl.bpfObjects.PerfEventsMap, os.Getpagesize()*1024*16)
	if err != nil {
		log.Fatal().Err(err).Msg("readPerfEvents: perf.NewReader failed")
		return err
	}

	return nil
}

// Status returns status of the specified process, or all status if pid = 0.
func (ctl *Controller) Status(pid int) []*Status {
	ctl.mu.RLock()
	defer ctl.mu.RUnlock()

	result := []*Status{}
	if pid != 0 {
		if wrapper, ok := ctl.recorders[pid]; ok {
			status := wrapper.recorder.Status()
			result = append(result, status)
		}
		return result
	}

	for pid, wrapper := range ctl.recorders {
		status := wrapper.recorder.Status()
		status.PID = pid
		result = append(result, status)
	}
	return result
}

func (ctl *Controller) loadProcessConfig(pid int, seq uint64, ver int) error {
	key := uint32(pid)
	val := configItem{
		Seq:       seq,
		GoVersion: uint64(ver),
	}
	if err := ctl.bpfObjects.ConfigMap.Update(key, val, ebpf.UpdateAny); err != nil {
		return err
	}
	return nil
}

func (ctl *Controller) deleteProcessConfig(pid int) {
	key := uint32(pid)
	if err := ctl.bpfObjects.ConfigMap.Delete(key); err != nil {
		log.Error().Err(err).Msg("loadProcessConfig: update config map pid")
		return
	}
	log.Info().Int("pid", pid).Msg("delete process config ok")
}

func (ctl *Controller) initLinkConfigs() {
	ctl.kprobes = []*linkConfig{
		{
			FuncName:     "inet_accept",
			EntryProgram: ctl.bpfObjects.InetAcceptEntry,
			ExitProgram:  ctl.bpfObjects.InetAcceptExit,
		},
		{
			FuncName:     "inet_stream_connect",
			EntryProgram: ctl.bpfObjects.InetStreamConnectEntry,
			ExitProgram:  ctl.bpfObjects.InetStreamConnectExit,
		},
		{
			FuncName:     "inet_release",
			EntryProgram: ctl.bpfObjects.InetReleaseEntry,
		},
		{
			FuncName:     "inet_sendmsg",
			EntryProgram: ctl.bpfObjects.InetSendmsgEntry,
			ExitProgram:  ctl.bpfObjects.InetSendmsgExit,
		},
		{
			FuncName:     "inet_recvmsg",
			EntryProgram: ctl.bpfObjects.InetRecvmsgEntry,
			ExitProgram:  ctl.bpfObjects.InetRecvmsgExit,
		},
	}

	ctl.uprobes = []*linkConfig{
		{
			FuncName:     "runtime.newproc1",
			EntryProgram: ctl.bpfObjects.GoNewproc1Entry,
			ExitProgram:  ctl.bpfObjects.GoNewproc1Exit,
		},
	}
}

func (ctl *Controller) linkKernelPrograms() error {
	for _, config := range ctl.kprobes {
		if config.EntryProgram != nil {
			link, err := link.Kprobe(config.FuncName, config.EntryProgram, nil)
			if err != nil {
				return err
			}
			ctl.links = append(ctl.links, link)
		}
		if config.ExitProgram != nil {
			opts := link.KprobeOptions{RetprobeMaxActive: 4096}
			link, err := link.Kretprobe(config.FuncName, config.ExitProgram, &opts)
			if err != nil {
				return err
			}
			ctl.links = append(ctl.links, link)
		}
	}
	return nil
}

func (ctl *Controller) linkUserPrograms(pid int, wrapper *recorderWrapper) error {
	filePath := fmt.Sprintf("/proc/%d/exe", pid)
	ex, err := link.OpenExecutable(filePath)
	if err != nil {
		return err
	}

	for _, config := range ctl.uprobes {
		opts := link.UprobeOptions{
			PID:    pid,
			Offset: 0,
		}

		if config.EntryProgram != nil {
			if config.SymbolOffset > 0 {
				opts.Offset, err = elf.SymbolOffset(filePath, config.FuncName)
				if err != nil || opts.Offset == 0 {
					return fmt.Errorf("get symbol offset failed, %v", err)
				}
				opts.Offset += config.SymbolOffset
			}
			link, err := ex.Uprobe(config.FuncName, config.EntryProgram, &opts)
			if err != nil {
				return err
			}
			wrapper.links = append(wrapper.links, link)
		}
		if config.ExitProgram != nil {
			link, err := ex.Uretprobe(config.FuncName, config.ExitProgram, nil)
			if err != nil {
				return err
			}
			wrapper.links = append(wrapper.links, link)
		}
	}

	return nil
}

func (ctl *Controller) unlinkUserPrograms(wrapper *recorderWrapper) {
	for _, link := range wrapper.links {
		link.Close()
	}
	wrapper.links = nil
}

func (ctl *Controller) readPerfEvents() {
	var hdr event.Header
	reader := bytes.NewReader(nil)
	for {
		record, err := ctl.perfReader.Read()
		if err != nil {
			log.Error().Err(err).Msg("readPerfEvents: read perf event failed")
			break
		}

		if record.LostSamples > 0 {
			log.Error().Err(err).Uint64("lostSamples", record.LostSamples).
				Msg("readPerfEvents: lost samples")
		}

		reader.Reset(record.RawSample)
		if err := hdr.Read(reader); err != nil {
			log.Error().Err(err).Msg("readPerfEvents: read event header failed")
			continue
		}

		log.Debug().
			Uint8("version", hdr.Version).
			Uint8("source", hdr.Source).
			Uint16("type", hdr.Type).
			Uint32("tgid", hdr.TGID).
			Uint32("pid", hdr.PID).
			Uint64("id", hdr.ID).
			Uint64("goid", hdr.GOID).
			Msg("perf event")

		err = ctl.sendToRecorder(hdr.TGID, hdr.ID, record.RawSample)
		if err != nil {
			log.Warn().Err(err).Msg("send to recorder failed")
		}
	}
	log.Info().Msg("readPerfEvents: exit")
	ctl.waitStop.Done()
}

// ProcessPerfEvents parses the tgid from the perf event data
// and sends the event to the recorder.
func (ctl *Controller) ProcessPerfEvents(data []byte) error {
	var hdr event.Header
	reader := bytes.NewReader(data)
	if err := hdr.Read(reader); err != nil {
		return err
	}
	return ctl.sendToRecorder(hdr.TGID, hdr.ID, data)
}

func (ctl *Controller) sendToRecorder(tgid uint32, id uint64, data []byte) error {
	ctl.mu.RLock()
	defer ctl.mu.RUnlock()

	wrapper, ok := ctl.recorders[int(tgid)]
	if !ok {
		return errProcessNotFound
	}

	item := &event.Item{
		ID:       id,
		RecvTime: uint64(time.Now().UnixNano()),
		Data:     data,
	}
	return wrapper.recorder.RecvPerfEvent(item)
}

func (ctl *Controller) processDebugEvent(hdr *event.Header, body io.Reader) {
	var e event.DebugEvent
	err := e.Read(body)
	if err != nil {
		log.Error().Err(err).Msg("processDebugEvent: read event failed")
		return
	}

	log.Debug().Str("event", "debug").
		Uint8("source", hdr.Source).
		Uint16("type", hdr.Type).
		Uint32("tgid", hdr.TGID).
		Uint32("pid", hdr.PID).
		Msg(event.DebugInfo(event.DebugEventType(hdr.Type), e))
}

// ParseKernStack parse kernel stack from the specified stackid.
func (ctl *Controller) ParseKernStack(stackid uint64) ([]*StackFrame, error) {
	id := uint32(stackid)
	stack := make([]byte, 128*8)
	err := ctl.bpfObjects.StackMap.Lookup(id, &stack)
	if err != nil {
		return nil, err
	}

	result := []*StackFrame{}
	reader := bytes.NewReader(stack)
	for i := 0; ; i++ {
		var addr uint64
		err := binary.Read(reader, binary.LittleEndian, &addr)
		if err != nil || addr == 0 {
			break
		}

		frame := &StackFrame{
			Frame: i,
			Addr:  addr,
		}
		if sym := kallsyms.Lookup(frame.Addr); sym != nil {
			frame.Func = sym.Name
		}
		result = append(result, frame)
	}
	return result, nil
}

// ParseUserStack parse user stack from the specified stackid.
func (ctl *Controller) ParseUserStack(stackid uint64) ([]*StackFrame, error) {
	id := uint32(stackid)
	stack := make([]byte, 128*8)
	err := ctl.bpfObjects.StackMap.Lookup(id, &stack)
	if err != nil {
		return nil, err
	}

	result := []*StackFrame{}
	reader := bytes.NewReader(stack)
	for i := 0; ; i++ {
		var addr uint64
		err := binary.Read(reader, binary.LittleEndian, &addr)
		if err != nil || addr == 0 {
			break
		}
		frame := &StackFrame{
			Frame: i,
			Addr:  addr,
		}
		result = append(result, frame)
	}
	return result, nil
}
