package socks5

import (
	"chimney3/settings"
	"log"
	"net"
	"strconv"
)

func RunServer(s *settings.Settings, isServer bool) error {
	if isServer {
		runSocks5Server(s)
	} else {
		runSocks5Client(s)
	}
	return nil
}

func runSocks5Server(s *settings.Settings) {
	ss := &Socks5ServerSettings{
		ListenAddress: net.JoinHostPort(s.Server.IP, strconv.Itoa(s.Server.Port)),
		User:          s.Server.User,
		PassWord:      s.Server.Password,
		ProxyAddress:  net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Server.Port)),
		Method:        s.Server.Method,
	}
	log.Println("This is server!!")
	server := NewSocks5Server(ss, nil)
	server.Serve()
}

func runSocks5Client(s *settings.Settings) {
	ss := &Socks5ServerSettings{
		ListenAddress: net.JoinHostPort(s.Client.IP, strconv.Itoa(s.Client.Port)),
		User:          s.Client.User,
		PassWord:      s.Client.Password,
		ProxyAddress:  net.JoinHostPort(s.Server.IP, strconv.Itoa(s.Server.Port)),
		Method:        s.Server.Method,
	}
	log.Println("This is client!!")
	server := NewSocks5Server(ss, nil)
	server.Serve()
}
