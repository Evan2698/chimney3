package all

import (
	"chimney3/kcpproxy"
	"chimney3/settings"
	"chimney3/socks5"
)

var (
	KCP    = "kcp"
	SOCKS5 = "socks5"
)

func Reactor(s *settings.Settings, isServer bool) {
	if s.Which == KCP {
		kcpproxy.RunServer(isServer, s)
	} else if s.Which == SOCKS5 {
		socks5.RunServer(s, isServer)
	}
}
