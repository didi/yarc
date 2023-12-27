package buffer

import (
	"sort"
	"sync"
)

type Pool struct {
	count   int
	maxSize int
	items   []item
}

type item struct {
	size int
	pool *sync.Pool
}

func NewPool(sizes ...int) *Pool {
	if len(sizes) <= 0 {
		sizes = []int{1024, 4096, 8192, 32768}
	}

	sort.Ints(sizes)

	count := len(sizes)
	p := &Pool{count: count, maxSize: sizes[count-1]}
	p.items = make([]item, len(sizes))
	for i, size := range sizes {
		p.items[i].size = size
		p.items[i].pool = makePool(size)
	}
	return p
}

func (p *Pool) Get(size int) []byte {
	for i := 0; i < p.count; i++ {
		if p.items[i].size >= size {
			buf := p.items[i].pool.Get().([]byte)
			return buf[:0]
		}
	}
	return make([]byte, 0, size)
}

func (p *Pool) Put(b []byte) {
	size := cap(b)
	if size > p.maxSize {
		return
	}
	for i := p.count - 1; i >= 0; i-- {
		if size >= p.items[i].size {
			p.items[i].pool.Put(b)
			break
		}
	}
}

func makePool(cap int) *sync.Pool {
	return &sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, cap)
		},
	}
}
