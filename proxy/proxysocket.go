package proxy

import (
	"chimney3/core"
	"chimney3/mem"
	"chimney3/privacy"
	"chimney3/utils"
	"errors"
	"log"
	"net"
	"time"
)

type ProxySocket interface {
	net.Conn
}

type Psocket struct {
	Con net.Conn
	I   privacy.EncryptThings
	Key []byte
}

func NewProxySocket(raw net.Conn, II privacy.EncryptThings, k []byte) ProxySocket {
	return &Psocket{
		Con: raw,
		I:   II,
		Key: k,
	}
}

func (p *Psocket) Read(b []byte) (n int, err error) {

	tmpBuffer := mem.NewApplicationBuffer().GetLarge()
	defer func() {
		mem.NewApplicationBuffer().PutLarge(tmpBuffer)
	}()

	buffer, err := core.ReadXBytes(4, tmpBuffer[:4], p.Con)
	if err != nil {
		log.Println("read raw content failed", err)
		return 0, err
	}

	rLen := len(buffer)
	if rLen > mem.LARGE_BUFFER_SIZE {
		return 0, errors.New("out of out buffer")
	}
	outBuffer := mem.NewApplicationBuffer().GetLarge()
	defer func() {
		mem.NewApplicationBuffer().PutLarge(outBuffer)
	}()

	n, err = p.I.Uncompress(buffer, p.Key, outBuffer)
	if err != nil {
		log.Print("uncompress failed: ", err)
		return 0, err
	}

	if len(b) < n {
		return 0, errors.New("buffer size too small")
	}

	copy(b, outBuffer[:n])

	return n, nil
}

func (p *Psocket) Write(b []byte) (int, error) {
	outlen := len(b)
	if outlen == 0 || outlen > mem.LARGE_BUFFER_SIZE {
		return 0, errors.New("input buffer size is zero or buffer is too large")
	}

	outBuffer := mem.NewApplicationBuffer().GetLarge()
	defer func() {
		mem.NewApplicationBuffer().PutLarge(outBuffer)
	}()

	n, err := p.I.Compress(b, p.Key, outBuffer)
	if err != nil {
		log.Print("compress failed", err)
		return 0, err
	}
	vLenBuffer := utils.Int2Bytes(uint32(n))
	_, err = core.WriteXBytes(vLenBuffer, p.Con)
	if err != nil {
		log.Println("write length of content failed: ", err)
		return 0, err
	}

	_, err = core.WriteXBytes(outBuffer[:n], p.Con)
	if err != nil {
		log.Println("write content failed: ", err)
		return 0, err
	}

	return n, nil
}

func (p *Psocket) Close() error {
	return p.Con.Close()
}

func (p *Psocket) LocalAddr() net.Addr {
	return p.Con.LocalAddr()
}

func (p *Psocket) RemoteAddr() net.Addr {
	return p.Con.RemoteAddr()
}

func (p *Psocket) SetDeadline(t time.Time) error {
	return p.Con.SetDeadline(t)
}

func (p *Psocket) SetReadDeadline(t time.Time) error {
	return p.Con.SetReadDeadline(t)
}

func (p *Psocket) SetWriteDeadline(t time.Time) error {
	return p.Con.SetWriteDeadline(t)
}
