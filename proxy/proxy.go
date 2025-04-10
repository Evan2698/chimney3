package proxy

import (
	"chimney3/settings"
	"net"
	"strconv"
)

func RunServer(s *settings.Settings, isServer bool) {

	if isServer {
		runserver(s)

	} else {
		runclient(s)
	}
}

func runclient(s *settings.Settings) {
	pc := &proxyClient{
		Password:     s.Client.Password,
		LocalHost:    net.JoinHostPort(s.Client.IP, strconv.Itoa(s.Client.Port)),
		ProxyAddress: net.JoinHostPort(s.Server.IP, strconv.Itoa(s.Server.Port)),
		Exit:         false,
	}
	pc.Serve()
}

func runserver(s *settings.Settings) {
	ps := &proxyServer{
		Host:     net.JoinHostPort(s.Server.IP, strconv.Itoa(s.Server.Port)),
		Password: s.Server.Password,
		Which:    s.Server.Method,
		Exit:     false,
	}
	ps.Serve()
}
