package mem

import (
	"sync"
)

type Pool struct {
	pool *sync.Pool
}

func NewPool(size int) *Pool {
	return &Pool{
		pool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
	}
}

func (p *Pool) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *Pool) Put(b []byte) {
	p.pool.Put(b)
}
