package all

import (
	"chimney3/proxy"
	"chimney3/settings"
	"chimney3/socks5"
)

var (
	PROXY  = "proxy"
	SOCKS5 = "socks5"
)

func Reactor(s *settings.Settings, isServer bool) {
	if s.Which == SOCKS5 {
		socks5.RunServer(s, isServer)
	} else if s.Which == PROXY {
		proxy.RunServer(s, isServer)
	}
}
