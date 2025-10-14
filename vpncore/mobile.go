package vpncore

import (
	"chimney3/mobile"
	"chimney3/socks5"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Chimney struct {
	Fd          int
	Pfun        mobile.ProtectSocket
	User        string
	Pass        string
	TcpProxyUrl string
	MTU         uint32
	UdpProxyUrl string
}

var (
	client   socks5.Socks5Server
	netstack *stack.Stack
)

func StartChimney(c *Chimney) error {

	var err error
	client = buildVpnClient("127.0.0.1:1080", c.TcpProxyUrl, c.User, c.Pass, c.Pfun)
	netstack, err = buildNetstackVpnClient(c.Fd, c.MTU, "127.0.0.1:1080", c.UdpProxyUrl)
	if err != nil {
		return err
	}

	return nil
}

func StopChimney() {

	if netstack != nil {
		netstack.Close()
		netstack = nil
	}

	if client != nil {
		client.Stop()
		client = nil
	}
}
