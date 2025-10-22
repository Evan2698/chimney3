package vpncore

import (
	"chimney3-go/socks5"
	"fmt"
	"log"
	"tun2proxylib/gvisorcore"
	"tun2proxylib/gvisorcore/proxy"
	"tun2proxylib/mobile"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func buildVpnClient(localListenUrl, proxyUrl string, user, pass string, p mobile.ProtectSocket) socks5.Socks5Server {

	ss := &socks5.Socks5ServerSettings{
		ListenAddress: localListenUrl,
		User:          user,
		PassWord:      pass,
		ProxyAddress:  proxyUrl,
		Method:        "socks5",
	}
	log.Println("SOCKS5 client starting...")
	server := socks5.NewSocks5Server(ss, p)

	socks5Url := fmt.Sprintf("socks5://%s", localListenUrl)
	log.Printf("Starting HTTP to SOCKS5 proxy on %s forwarding to %s", localListenUrl, socks5Url)

	go server.Serve()

	return server
}

func stopVpnClient(s socks5.Socks5Server) {
	s.Stop()
}

func buildNetstackVpnClient(fd int, mtu uint32, tcpUrl string, udpUrl string) (*stack.Stack, error) {
	linker, err := gvisorcore.CreateLinkEndpoint(fd, mtu)
	if err != nil {
		log.Printf("Failed to create link endpoint: %v", err)
		return nil, err
	}
	handler := proxy.NewDefaultProxy(tcpUrl, udpUrl)
	options := gvisorcore.StackOptions{
		TransportHandler: handler,
		LinkEndpoint:     linker,
	}

	s, err := gvisorcore.CreateStack(options)
	if err != nil {
		log.Printf("Failed to create stack: %v", err)
		return nil, err
	}

	return s, nil

}

func stopNetstackVpnClient(s *stack.Stack) {
	s.Close()
}
