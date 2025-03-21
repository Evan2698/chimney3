package mem

import (
	"sync"
)

type bufferHolder struct {
	smallbuffer *Pool
	largebuffer *Pool
}

type Buffer interface {
	GetLarge() []byte
	PutLarge([]byte)
	GetSmall() []byte
	PutSmall([]byte)
}

var (
	instance          *bufferHolder
	once              sync.Once
	LARGE_BUFFER_SIZE = 4096
	SMALL_BUFFER_SIZE = 512
)

func NewApplicationBuffer() Buffer {
	once.Do(func() {
		instance = &bufferHolder{
			smallbuffer: NewPool(SMALL_BUFFER_SIZE),
			largebuffer: NewPool(LARGE_BUFFER_SIZE),
		}
	})
	return instance
}

func (b *bufferHolder) GetLarge() []byte {
	return b.largebuffer.Get()
}

func (b *bufferHolder) PutLarge(t []byte) {

	b.largebuffer.Put(t)
}

func (b *bufferHolder) GetSmall() []byte {

	return b.smallbuffer.Get()
}

func (b *bufferHolder) PutSmall(t []byte) {
	b.smallbuffer.Put(t)
}
