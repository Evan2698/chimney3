package kcpproxy

import "github.com/xtaci/kcp-go/v5"

type KCPSetting struct {
	User          string
	Password      string
	ListenAddress string
	ProxyAddress  string
}

type kcpSession struct {
	S *kcp.UDPSession
}
