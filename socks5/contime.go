package socks5

import (
	"chimney3-go/core"
	"net"
)

func SetSocketTimeout(con net.Conn, tm uint32) {
	core.SetConnectTimeout(con, tm)
}
