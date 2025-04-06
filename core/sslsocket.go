package core

import (
	"bytes"
	"chimney3/mem"
	"chimney3/privacy"
	"chimney3/utils"
	"errors"
	"log"
	"net"
	"time"
)

type MySSLSocket interface {
	net.Conn
}

type SSLSocketImpl struct {
	RawConnection net.Conn
	II            privacy.EncryptThings
	Key           []byte
}

func NewMySSLSocket(conn net.Conn, encryptor privacy.EncryptThings, key []byte) *SSLSocketImpl {
	return &SSLSocketImpl{
		RawConnection: conn,
		II:            encryptor,
		Key:           key,
	}
}

func (sock *SSLSocketImpl) IsOk() bool {

	if sock.RawConnection == nil {
		return false
	}
	if sock.II == nil {
		return false
	}
	if sock.Key == nil {
		return false
	}
	return true
}

func (sock *SSLSocketImpl) HandshakeClient() error {

	buffer := mem.NewApplicationBuffer().GetSmall()
	defer func() {
		mem.NewApplicationBuffer().PutSmall(buffer)
	}()

	// Step 1: say hello
	sock.RawConnection.Write([]byte{0x5, 0x0})

	// Step 2: receive EncryptThings from the server
	n, err := sock.RawConnection.Read(buffer[:])
	if err != nil {
		log.Println("read failed ", err)
		return err
	}
	if n < 2 {
		log.Println("handshake failed ")
		return errors.New("handshake failed")
	}
	if !bytes.Equal(buffer[:2], []byte{0x5, 0x0}) {
		log.Println("protocol is incorrect")
		return errors.New("protocol is incorrect")
	}
	ebytes := buffer[3:n]
	if len(ebytes) != int(buffer[2]) {
		log.Println("handshake failed ")
		return errors.New("handshake length is incorrect")
	}

	i, err := privacy.FromBytes(ebytes)
	if err != nil {
		log.Println("handshake failed ", err)
		return err
	}
	sock.II = i

	// step 3: send ok
	_, err = sock.RawConnection.Write([]byte{0x5, 0x1, 0x0})
	if err != nil {
		log.Println("write failed ", err)
		return err
	}

	return nil
}

func (sock *SSLSocketImpl) HandshakeServer() error {
	buffer := mem.NewApplicationBuffer().GetSmall()
	defer func() {
		mem.NewApplicationBuffer().PutSmall(buffer)
	}()

	n, err := sock.RawConnection.Read(buffer[:])
	if err != nil {
		log.Println("read failed ", err)
		return err
	}
	if n < 2 {
		log.Println("handshake failed ")
		return errors.New("handshake failed")
	}
	if !bytes.Equal(buffer[:2], []byte{0x5, 0x0}) {
		log.Println("protocol is incorrect")
		return errors.New("protocol is incorrect")
	}
	// Step 2: send EncryptThings to the client
	I := sock.II.ToBytes()
	var memoryBuffer bytes.Buffer
	memoryBuffer.WriteByte(0x5)
	memoryBuffer.WriteByte(0x0)
	memoryBuffer.WriteByte(byte(len(I)))
	memoryBuffer.Write(I)
	_, err = sock.RawConnection.Write(memoryBuffer.Bytes())
	if err != nil {
		log.Println("write failed ", err)
		return err
	}
	// Step 3: receive ok
	n, err = sock.RawConnection.Read(buffer[:])
	if err != nil {
		log.Println("read failed ", err)
		return err
	}
	if n < 2 {
		log.Println("handshake failed ")
		return errors.New("handshake failed")
	}
	if !bytes.Equal(buffer[:3], []byte{0x5, 0x1, 0x0}) {
		log.Println("protocol is incorrect")
		return errors.New("protocol is incorrect")
	}
	return nil
}

func (sock *SSLSocketImpl) Read(b []byte) (int, error) {

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

	n, err := sock.II.Uncompress(buffer, sock.Key, outBuffer)
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

func (sock *SSLSocketImpl) Write(b []byte) (int, error) {
	outlen := len(b)
	if outlen == 0 || outlen > mem.LARGE_BUFFER_SIZE {
		return 0, errors.New("input buffer size is zero or buffer is too large")
	}

	outBuffer := mem.NewApplicationBuffer().GetLarge()
	defer func() {
		mem.NewApplicationBuffer().PutLarge(outBuffer)
	}()

	n, err := sock.II.Compress(b, sock.Key, outBuffer)
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

func (sock *SSLSocketImpl) Close() error {
	return sock.RawConnection.Close()
}
func (sock *SSLSocketImpl) LocalAddr() net.Addr {
	return sock.RawConnection.LocalAddr()
}
func (sock *SSLSocketImpl) RemoteAddr() net.Addr {
	return sock.RawConnection.RemoteAddr()
}
func (sock *SSLSocketImpl) SetDeadline(t time.Time) error {
	return sock.RawConnection.SetDeadline(t)
}
func (sock *SSLSocketImpl) SetReadDeadline(t time.Time) error {
	return sock.RawConnection.SetReadDeadline(t)
}

func (sock *SSLSocketImpl) SetWriteDeadline(t time.Time) error {

	return sock.RawConnection.SetWriteDeadline(t)
}
