package proxy

import (
	"bytes"
	"chimney3/mem"
	"chimney3/privacy"
	"log"
	"net"
)

type ProxyListener interface {
	net.Listener
}

type proxyListener struct {
	Listener net.Listener
	ConnChan chan net.Conn
	Exit     bool
	Password string
	Which    string
}

func NewProxyListener(address string, password, which string) (ProxyListener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}

	abc := &proxyListener{
		Listener: listener,
		ConnChan: make(chan net.Conn),
		Password: password,
		Which:    which,
	}

	go abc.acceptRoutine()

	return abc, nil
}

func (pl *proxyListener) acceptRoutine() {
	for {
		conn, err := pl.Listener.Accept()
		if err != nil {
			log.Println("accept failed ", err)
			if pl.Exit {
				log.Println("listener closed")
				break
			}
			break
		}

		go pl.dohandshake(conn)
	}
}

func (pl *proxyListener) dohandshake(conn net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on handshake: ", err)
		}
	}()

	tmpbuffer := mem.NewApplicationBuffer().GetSmall()
	defer func() {
		mem.NewApplicationBuffer().PutSmall(tmpbuffer)
	}()

	n, err := conn.Read(tmpbuffer[:])
	if err != nil {
		log.Println("read failed ", err)
		conn.Close()
		return
	}
	if !bytes.Equal(tmpbuffer[:n], []byte{0x5, 0x1, 0x0}) {
		log.Println("handshake failed, client is chimney")
		conn.Close()
		return
	}

	II := privacy.NewMethodWithName(pl.Which)
	sI := II.ToBytes()
	var byteBuffer bytes.Buffer
	byteBuffer.WriteByte(byte(len(sI)))
	byteBuffer.Write(sI)
	_, err = conn.Write(byteBuffer.Bytes())
	if err != nil {
		log.Println("handshake failed ", err)
		conn.Close()
		return
	}

	n, err = conn.Read(tmpbuffer[:])
	if err != nil {
		log.Println("read failed ", err)
		conn.Close()
		return
	}

	if !bytes.Equal(tmpbuffer[:n], []byte{0x5, 0x0}) {
		log.Println("handshake failed, client is chimney")
		conn.Close()
		return
	}

	pt := NewProxySocket(conn, II, privacy.MakeCompressKey(pl.Password))

	if !pl.Exit {
		pl.ConnChan <- pt
	}

	log.Println("handshake success")

}

func (pl *proxyListener) Accept() (net.Conn, error) {
	if pl.Exit {
		return nil, net.ErrClosed
	}

	conn := <-pl.ConnChan
	return conn, nil
}

func (pl *proxyListener) Addr() net.Addr {
	return pl.Listener.Addr()
}

func (pl *proxyListener) Close() error {
	pl.Exit = true
	pl.Listener.Close()
	close(pl.ConnChan)
	return nil
}
