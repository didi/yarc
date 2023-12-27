package event

import (
	"errors"
	"time"
)

// Item represents the data to be sorted
type Item struct {
	ID       uint64
	Data     []byte
	RecvTime uint64 // unix nano
	Lost     uint64
}

// SortIntf represents the interface of sort buffer.
type SortIntf interface {
	Push(item *Item) error
	Pop() (*Item, bool)
	Next() bool
	Reset(seq uint64)
}

// SeqBuffer sorts data by the sequence numbers.
// Data will be saved in a fixed size buffer, and only
// data with consecutive sequence numbers can be Pop.
type SeqBuffer struct {
	buf     []*Item
	size    int
	nextIdx uint64
	nextSeq uint64
}

var (
	errOutOfBound = errors.New("out of bound")
	errRepeatData = errors.New("repeat data")
)

// NewSeqBuffer creates a SeqBuffer
func NewSeqBuffer(size int, seq uint64) *SeqBuffer {
	if size <= 0 {
		size = 4096
	}

	return &SeqBuffer{
		buf:     make([]*Item, size),
		size:    size,
		nextSeq: seq,
	}
}

// Push writes data into the buffer in order.
// If the seq is out of range, it will return an error.
func (s *SeqBuffer) Push(item *Item) error {
	offset := item.ID - s.nextSeq
	if offset > 0x7FFFFFFF {
		return errOutOfBound
	}

	if offset >= uint64(s.size) {
		item.Lost = offset
		s.buf[0] = item
		s.nextSeq = item.ID
		s.nextIdx = 0
	} else {
		idx := (s.nextIdx + offset) % uint64(s.size)
		if s.buf[idx] != nil {
			return errRepeatData
		}
		s.buf[idx] = item
	}
	return nil
}

// Pop returns and removes data with the next sequence number.
// If the data does not exist, it returns a default Item and false.
func (s *SeqBuffer) Pop() (*Item, bool) {
	item := s.buf[s.nextIdx]
	if item == nil {
		return nil, false
	}

	s.buf[s.nextIdx] = nil
	s.nextIdx = (s.nextIdx + 1) % uint64(s.size)
	s.nextSeq++
	return item, true
}

// Next check whether the data of next sequence number is received.
func (s *SeqBuffer) Next() bool {
	return s.buf[s.nextIdx] != nil
}

// Reset clear buffer and set the next sequence number to seq.
func (s *SeqBuffer) Reset(seq uint64) {
	for i := range s.buf {
		s.buf[i] = nil
	}
	s.nextIdx = 0
	s.nextSeq = seq
}

// MinHeap is min heap with threshold.
// Data can only be Pop if the number is greater than threshold.
type MinHeap struct {
	capacity  int
	threshold int
	size      int
	buf       []*Item
}

// NewMinHeap creates a MinHeap
func NewMinHeap(capacity, threshold int) *MinHeap {
	if capacity == 0 {
		capacity = 64
	}
	if threshold == 0 {
		threshold = 1
	}
	return &MinHeap{
		capacity:  capacity,
		threshold: threshold,
		buf:       make([]*Item, capacity),
	}
}

// Push writes data into the buffer, and sorts by seq.
// If the buffer is full, it will grow dynamically.
func (h *MinHeap) Push(item *Item) error {
	if h.size >= h.capacity {
		h.grow()
	}

	idx := h.size
	h.buf[idx] = item
	h.size++
	h.shiftup(idx)
	return nil
}

// Pop reads and remove data from heap.
// If the buffer size is less than the threshold,
// it will return a default Item and false.
func (h *MinHeap) Pop() (*Item, bool) {
	if h.size <= 0 {
		return nil, false
	}

	res := h.buf[0]
	h.buf[0] = nil
	h.swap(0, h.size-1)
	h.size--
	h.shiftdown(0, h.size)
	return res, true
}

// Next checks if there are enough data in the buffer.
func (h *MinHeap) Next() bool {
	if h.size >= h.threshold {
		return true
	}

	if h.size > 0 {
		now := time.Now().UnixNano()
		if uint64(now)-h.buf[0].RecvTime > 10*1e9 {
			return true
		}
	}

	return false
}

func (h *MinHeap) Reset(seq uint64) {
	h.size = 0
}

// Size returns the buffer size.
func (h *MinHeap) Size() int {
	return h.size
}

func (h *MinHeap) swap(i, j int) {
	if i == j {
		return
	}

	temp := h.buf[i]
	h.buf[i] = h.buf[j]
	h.buf[j] = temp
}

func (h *MinHeap) shiftup(j int) {
	for j > 0 {
		i := (j - 1) / 2
		if h.buf[i].ID <= h.buf[j].ID {
			break
		}
		h.swap(i, j)
		j = i
	}
}

func (h *MinHeap) shiftdown(i, n int) {
	for {
		j := i*2 + 1
		if j >= n || j < 0 {
			break
		}
		if k := j + 1; k < n && h.buf[k].ID < h.buf[j].ID {
			j = k
		}
		if h.buf[i].ID <= h.buf[j].ID {
			break
		}
		h.swap(i, j)
		i = j
	}
}

func (h *MinHeap) grow() {
	if h.capacity < 1024 {
		h.capacity *= 2
	} else {
		h.capacity += h.capacity / 4
	}
	buf := make([]*Item, h.capacity)
	copy(buf, h.buf)
	h.buf = buf
}
