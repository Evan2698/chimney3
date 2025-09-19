package socks5

import (
	"chimney3/settings"
	"log"
	"net"
	"strconv"
)

// RunServer 启动 SOCKS5 服务器或客户端，依据 isServer 参数。
func RunServer(s *settings.Settings, isServer bool) error {
	if isServer {
		return startSocks5Server(s)
	}
	return startSocks5Client(s)
}

// startSocks5Server 构建并启动 SOCKS5 服务器。
func startSocks5Server(s *settings.Settings) error {
	ss := &Socks5ServerSettings{
		ListenAddress: net.JoinHostPort(s.Server.IP, strconv.Itoa(s.Server.Port)),
		User:          s.Server.User,
		PassWord:      s.Server.Password,
		ProxyAddress:  net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Server.Port)),
		Method:        s.Server.Method,
	}
	log.Println("SOCKS5 server starting...")
	server := NewSocks5Server(ss, nil)
	return server.Serve()
}

// startSocks5Client 构建并启动 SOCKS5 客户端。
func startSocks5Client(s *settings.Settings) error {
	ss := &Socks5ServerSettings{
		ListenAddress: net.JoinHostPort(s.Client.IP, strconv.Itoa(s.Client.Port)),
		User:          s.Client.User,
		PassWord:      s.Client.Password,
		ProxyAddress:  net.JoinHostPort(s.Server.IP, strconv.Itoa(s.Server.Port)),
		Method:        s.Server.Method,
	}
	log.Println("SOCKS5 client starting...")
	server := NewSocks5Server(ss, nil)
	go Run2HTTP(s)
	return server.Serve()
}
