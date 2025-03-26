package all

import (
	"chimney3/settings"
	"chimney3/socks5"
)

var (
	KCP    = "kcp"
	SOCKS5 = "socks5"
)

func Reactor(s *settings.Settings, isServer bool) {
	if s.Which == SOCKS5 {
		socks5.RunServer(s, isServer)
	}
}
