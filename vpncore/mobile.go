package vpncore

import (
	"chimney3-go/mobile"
	"chimney3-go/socks5"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Protect interface {
	mobile.ProtectSocket
}

type Chimney struct {
	Fd          int
	Pfun        Protect
	User        string
	Pass        string
	TcpProxyUrl string
	MTU         int
	UdpProxyUrl string
}

var (
	client   socks5.Socks5Server
	netstack *stack.Stack
)

func StartChimney(c *Chimney) error {

	var err error
	client = buildVpnClient("127.0.0.1:1080", c.TcpProxyUrl, c.User, c.Pass, c.Pfun)
	netstack, err = buildNetstackVpnClient(c.Fd, (uint32)(c.MTU), "127.0.0.1:1080", c.UdpProxyUrl)
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
