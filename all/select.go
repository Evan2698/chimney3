package all

import (
	"chimney3-go/kcpproxy"
	"chimney3-go/proxy"
	"chimney3-go/settings"
	"chimney3-go/socks5"
)

var (
	PROXY  = "proxy"
	SOCKS5 = "socks5"
	KCP    = "kcp"
)

func Reactor(s *settings.Settings, isServer bool) {
	switch s.Which {
	case SOCKS5:
		socks5.RunServer(s, isServer)
	case PROXY:
		proxy.RunServer(s, isServer)
	case KCP:
		_ = kcpproxy.RunKCPRoutine(s, isServer)
	}
}
