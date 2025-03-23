package kcpproxy

import (
	"chimney3/settings"
	"net"
	"strconv"
)

func runKCPClient(s *settings.Settings) {
	c := &KCPSetting{
		User:          s.Client.User,
		Password:      s.Client.Password,
		ListenAddress: net.JoinHostPort(s.Client.IP, strconv.Itoa(s.Client.Port)),
		ProxyAddress:  net.JoinHostPort(s.Server.IP, strconv.Itoa(s.Server.Port)),
	}
	runkcpClientImp(c)
}

func runKCPServer(s *settings.Settings) {
	c := &KCPSetting{
		User:          s.Server.User,
		Password:      s.Server.Password,
		ListenAddress: net.JoinHostPort(s.Server.IP, strconv.Itoa(s.Server.Port)),
		ProxyAddress:  "",
	}
	runkcpServerImp(c)
}

func RunServer(isServer bool, s *settings.Settings) {
	if isServer {
		runKCPServer(s)
	} else {
		runKCPClient(s)
	}
}
