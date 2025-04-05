package core

import (
	"chimney3/mem"
	"chimney3/privacy"
	"chimney3/utils"
	"errors"
	"log"
	"net"
	"time"
)

type SocksStream interface {
	net.Conn
	GetSourceSocks5Address() *Socks5Address
	GetDstSocks5Address() *Socks5Address
}

type Socks5Socket struct {
	RawConnection net.Conn
	Address       *Socks5Address
	I             privacy.EncryptThings
	Key           []byte
	Dst           *Socks5Address
}

func NewSocks5Socket(conn net.Conn, i privacy.EncryptThings, key []byte, addr, dst *Socks5Address) SocksStream {
	return &Socks5Socket{
		RawConnection: conn,
		I:             i,
		Key:           key,
		Address:       addr,
		Dst:           dst,
	}
}

func (sock *Socks5Socket) GetDstSocks5Address() *Socks5Address {
	return sock.Dst
}

func (sock *Socks5Socket) GetSourceSocks5Address() *Socks5Address {
	return sock.Address
}

func (sock *Socks5Socket) Read(b []byte) (int, error) {

	tmpBuffer := mem.NewApplicationBuffer().GetLarge()
	defer func() {
		mem.NewApplicationBuffer().PutLarge(tmpBuffer)
	}()

	buffer, err := ReadXBytes(4, tmpBuffer[:4], sock.RawConnection)
	if err != nil {
		log.Println("read raw content failed", err)
		return 0, err
	}

	vLen := utils.Bytes2Int(buffer)

	if (vLen > uint32(mem.LARGE_BUFFER_SIZE)) || (vLen <= 0) {
		log.Println("read raw content failed, invalid length", vLen)
		return 0, errors.New("invalid length")
	}

	buffer, err = ReadXBytes(vLen, tmpBuffer[:vLen], sock.RawConnection)
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

	n, err := sock.I.Uncompress(buffer, sock.Key, outBuffer)
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

func (sock *Socks5Socket) Write(b []byte) (int, error) {
	outlen := len(b)
	if outlen == 0 || outlen > mem.LARGE_BUFFER_SIZE {
		return 0, errors.New("input buffer size is zero or buffer is too large")
	}

	outBuffer := mem.NewApplicationBuffer().GetLarge()
	defer func() {
		mem.NewApplicationBuffer().PutLarge(outBuffer)
	}()

	n, err := sock.I.Compress(b, sock.Key, outBuffer)
	if err != nil {
		log.Print("compress failed", err)
		return 0, err
	}
	vLenBuffer := utils.Int2Bytes(uint32(n))
	_, err = WriteXBytes(vLenBuffer, sock.RawConnection)
	if err != nil {
		log.Println("write length of content failed: ", err)
		return 0, err
	}

	_, err = WriteXBytes(outBuffer[:n], sock.RawConnection)
	if err != nil {
		log.Println("write content failed: ", err)
		return 0, err
	}

	return n, nil
}

func (sock *Socks5Socket) Close() error {
	return sock.RawConnection.Close()
}

func (sock *Socks5Socket) LocalAddr() net.Addr  { return sock.RawConnection.LocalAddr() }
func (sock *Socks5Socket) RemoteAddr() net.Addr { return sock.RawConnection.RemoteAddr() }

func (sock *Socks5Socket) SetDeadline(t time.Time) error {
	return sock.RawConnection.SetDeadline(t)
}

func (sock *Socks5Socket) SetReadDeadline(t time.Time) error {
	return sock.RawConnection.SetReadDeadline(t)
}

func (sock *Socks5Socket) SetWriteDeadline(t time.Time) error {
	return sock.RawConnection.SetWriteDeadline(t)
}
