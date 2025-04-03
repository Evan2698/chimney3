package kcpproxy

import (
	"chimney3/mem"
	"chimney3/settings"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

func SetSocketTimeout(con net.Conn, tm uint32) {
	if con != nil && tm != 0 {
		readTimeout := time.Duration(tm) * time.Second
		v := time.Now().Add(readTimeout)
		con.SetReadDeadline(v)
		con.SetWriteDeadline(v)
		con.SetDeadline(v)
	}
}

func copyConnection(src, dst net.Conn, wg *sync.WaitGroup) {
	tmpBuffer := mem.NewApplicationBuffer().GetLarge()
	defer func() {
		mem.NewApplicationBuffer().PutLarge(tmpBuffer)
	}()

	for {
		n, err := src.Read(tmpBuffer)
		if err != nil {
			log.Println("read failed", err)
			break
		}

		_, err = dst.Write(tmpBuffer[:n])
		if err != nil {
			log.Println("write failed", err)
			break
		}
	}

	wg.Done()
}

func RunKCP(s *settings.Settings, isServer bool) {
	if isServer {
		runKcpServer(s)
	} else {
		runKcpClient(s)
	}
}

func runKcpClient(s *settings.Settings) {

	client := NewKcpClient(s.Client.User, s.Client.Password,
		net.JoinHostPort(s.Server.IP, strconv.Itoa(s.Server.Port)),
		net.JoinHostPort(s.Client.IP, strconv.Itoa(s.Client.Port)))

	client.Serve()
}

func runKcpServer(s *settings.Settings) {

	server := NewKcpServer(s.Server.User, s.Server.Password,
		net.JoinHostPort(s.Server.IP, strconv.Itoa(s.Server.Port)))
	server.Serve()

}
