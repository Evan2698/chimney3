package socks5

const (
	socks5Version          uint8 = 0x5
	socks5NoAuth           uint8 = 0x0
	socks5AuthWithUserPass uint8 = 0x2
)
const (
	socks5CMDConnect uint8 = 0x1
	socks5CMDBind    uint8 = 0x2
	socks5CMDUDP     uint8 = 0x3
)

const (
	MAX_TIME_OUT uint32 = 600
)
