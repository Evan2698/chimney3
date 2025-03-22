package kcpproxy

import (
	"chimney3/privacy"
	"crypto/sha1"
	"io"
	"log"
	"net"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

func RunkcpClient(s *KCPSetting) {
	key := pbkdf2.Key(privacy.MakeCompressKey(s.Password), []byte(s.User), 1024, 32, sha1.New)
	block, _ := kcp.NewSalsa20BlockCrypt(key)

	l, err := net.Listen("tcp", s.ListenAddress)
	if err != nil {
		return
	}

	defer func() {
		l.Close()
	}()

	for {
		con, err := l.Accept()
		if err != nil {
			log.Println(" accept failed ", err)
			break
		}

		go onclientOn(con, block, s.ProxyAddress)
	}
}

func onclientOn(con net.Conn, block kcp.BlockCrypt, host string) {
	s, err := kcp.DialWithOptions(host, block, 10, 3)
	if err != nil {
		return
	}

	defer func() {
		s.Close()
		con.Close()
	}()

	go io.Copy(s, con)
	io.Copy(con, s)
}
