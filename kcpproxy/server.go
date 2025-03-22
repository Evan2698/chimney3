package kcpproxy

import (
	"bytes"
	"chimney3/core"
	"chimney3/mem"
	"chimney3/privacy"
	"crypto/sha1"
	"errors"
	"log"
	"net"
	"sync"

	"golang.org/x/crypto/pbkdf2"

	"github.com/xtaci/kcp-go/v5"
)

func RunkcpServer(s *KCPSetting) error {
	key := pbkdf2.Key(privacy.MakeCompressKey(s.Password), []byte(s.User), 1024, 32, sha1.New)
	block, _ := kcp.NewSalsa20BlockCrypt(key)
	listener, err := kcp.ListenWithOptions(s.ListenAddress, block, 10, 3)
	if err != nil {
		log.Println("kcp listen error", err)
		return err
	}

	defer listener.Close()

	for {
		s, err := listener.AcceptKCP()
		if err != nil {
			log.Println("accept kcp error", err)
			break
		}
		session := &kcpSession{S: s}
		go serverOn(session)
	}

	return nil
}

func serverOn(s *kcpSession) {

	defer func(c *kcpSession) {
		c.S.Close()
	}(s)

	dst, err := echoSocks5Hello(s.S)
	if err != nil {
		log.Println("handle socks5 failed", err)
		return
	}

	defer func() {
		dst.Close()
	}()
	wg := sync.WaitGroup{}
	wg.Add(2)
	go copy2(s.S, dst, &wg)
	go copy2_(s.S, dst, &wg)
	wg.Wait()

}

func copy2_(d *kcp.UDPSession, s net.Conn, wg *sync.WaitGroup) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on proxy: ", err)
		}
	}()

	tmpBuffer := mem.NewApplicationBuffer().GetLarge()
	defer func() {
		mem.NewApplicationBuffer().PutLarge(tmpBuffer)
	}()
	for {
		n, err := s.Read(tmpBuffer)
		if err != nil {
			break
		}
		_, err = d.Write(tmpBuffer[:n])
		if err != nil {
			break
		}
	}

	wg.Done()
}

func copy2(s *kcp.UDPSession, d net.Conn, wg *sync.WaitGroup) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on proxy: ", err)
		}
	}()

	tmpBuffer := mem.NewApplicationBuffer().GetLarge()
	defer func() {
		mem.NewApplicationBuffer().PutLarge(tmpBuffer)
	}()
	for {
		n, err := s.Read(tmpBuffer)
		if err != nil {
			break
		}
		_, err = d.Write(tmpBuffer[:n])
		if err != nil {
			break
		}
	}

	wg.Done()
}

func echoSocks5Hello(s *kcp.UDPSession) (net.Conn, error) {
	tmpBuffer := mem.NewApplicationBuffer().GetSmall()
	defer func(t []byte) {
		mem.NewApplicationBuffer().PutSmall(t)
	}(tmpBuffer)

	n, err := s.Read(tmpBuffer)
	if err != nil {
		return nil, err
	}

	if n < 3 {
		return nil, errors.New("length is incorrect")
	}

	if tmpBuffer[0] != 0x5 || tmpBuffer[1] != 0 {
		return nil, errors.New("protocol is incorrect")
	}
	_, err = s.Write([]byte{0x5, 0x0})
	if err != nil {
		return nil, err
	}

	//2. parse the connect command
	n, err = s.Read(tmpBuffer)
	if err != nil {
		s.Write([]byte{0x05, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("read connect command failed", err)
		return nil, err
	}

	cmd := tmpBuffer[:n]
	if len(cmd) < 4 {
		s.Write([]byte{0x05, 0x0B, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("cmd length is too short!!")
		return nil, errors.New("cmd length is too short")
	}
	if cmd[0] != 0x5 {
		s.Write([]byte{0x05, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("cmd protocol is incorrect")
		return nil, errors.New("cmd protocol is incorrect")
	}

	if cmd[1] != 0x1 {
		s.Write([]byte{0x05, 0x0D, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("does not support other command")
		return nil, errors.New("does not support other command")
	}
	adr := core.NewSocks5Address()
	err = adr.Parse(cmd[3:])
	if err != nil {
		s.Write([]byte{0x05, 0x0E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("parse cmd address failed", err)
		return nil, err
	}

	remote, err := net.Dial("tcp", adr.String())
	if err != nil {
		s.Write([]byte{0x05, 0x0F, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("connect remote failed", err)
		return nil, err
	}

	rAddress, err := core.ParseTargetAddress(remote.RemoteAddr().String())
	if err != nil {
		s.Write([]byte{0x05, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("remote address parse error", err)
		remote.Close()
		return nil, err
	}

	var op bytes.Buffer
	op.Write([]byte{0x5, 0x00, 0x00})
	op.Write(rAddress.Bytes())
	_, err = s.Write(op.Bytes())
	if err != nil {
		s.Write([]byte{0x05, 0x11, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("write remote failed", err)
		remote.Close()
		return nil, err
	}

	return remote, nil
}
