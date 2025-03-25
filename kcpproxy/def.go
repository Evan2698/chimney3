package kcpproxy

import (
	"chimney3/mem"
	"io"
	"log"
	"sync"

	"github.com/xtaci/kcp-go/v5"
)

type KCPSetting struct {
	User          string
	Password      string
	ListenAddress string
	ProxyAddress  string
}

type kcpSession struct {
	S *kcp.UDPSession
}

func copy(s, d io.ReadWriter, wg *sync.WaitGroup) {
	tmpBuffer := mem.NewApplicationBuffer().GetLarge()
	defer func(b []byte) {
		mem.NewApplicationBuffer().PutLarge(b)
	}(tmpBuffer)

	for {
		n, err := s.Read(tmpBuffer)
		if err != nil {
			log.Println("error ", err)
			break
		}

		_, err = d.Write(tmpBuffer[:n])
		if err != nil {
			log.Println(err)
			break
		}
	}
	wg.Done()
}
