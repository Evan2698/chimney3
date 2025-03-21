package core

import (
	"bytes"
	"net"
	"strconv"
)

var (
	ADDRESSTYPE_IPV4   byte = 0x01
	ADDRESSTYPE_DOMAIN byte = 0x03
	ADDRESSTYPE_IPV6   byte = 0x04
)

type Socks5Address struct {
	Type  byte
	Host  string
	Port  uint16
	IP    []byte
	IPV6  []byte
	Valid bool
}

func NewSocks5Address() *Socks5Address {
	return &Socks5Address{
		Valid: false,
	}
}

func (addr *Socks5Address) GetAddress() string {
	if addr.Type == ADDRESSTYPE_DOMAIN {
		return addr.Host
	}
	if addr.Type == ADDRESSTYPE_IPV4 {
		return net.IP(addr.IP).String()
	}
	if addr.Type == ADDRESSTYPE_IPV6 {
		return net.IP(addr.IPV6).String()
	}
	return ""
}

func (addr *Socks5Address) GetPort() uint16 {
	return addr.Port
}

func (addr *Socks5Address) String() string {
	return net.JoinHostPort(addr.GetAddress(), strconv.Itoa(int(addr.GetPort())))
}

func (addr *Socks5Address) SetDomainAddress(host string, port uint16) {
	addr.Host = host
	addr.Port = port
	addr.Type = ADDRESSTYPE_DOMAIN
	addr.Valid = true
}

func (addr *Socks5Address) SetIPv4Address(ip []byte, port uint16) {
	addr.IP = ip
	addr.Port = port
	addr.Type = ADDRESSTYPE_IPV4
	addr.Valid = true
}

func (addr *Socks5Address) SetIPv6Address(ip []byte, port uint16) {
	addr.IPV6 = ip
	addr.Port = port
	addr.Type = ADDRESSTYPE_IPV6
	addr.Valid = true
}

func (addr *Socks5Address) Bytes() []byte {
	var hello bytes.Buffer
	hello.WriteByte(addr.Type)
	if addr.Type == ADDRESSTYPE_DOMAIN {
		hello.WriteByte(byte(len(addr.Host)))
		hello.WriteString(addr.Host)
	} else if addr.Type == ADDRESSTYPE_IPV4 {
		hello.Write(addr.IP)
	} else if addr.Type == ADDRESSTYPE_IPV6 {
		hello.Write(addr.IPV6)
	}
	hello.WriteByte(byte(addr.Port >> 8))
	hello.WriteByte(byte(addr.Port & 0xff))
	return hello.Bytes()
}

func (addr *Socks5Address) Parse(data []byte) error {
	if len(data) < 7 {
		addr.Valid = false
		return nil
	}
	addr.Type = data[0]
	if addr.Type == ADDRESSTYPE_DOMAIN {
		addr.Host = string(data[2 : 2+data[1]])
		addr.Port = uint16(data[len(data)-2])<<8 | uint16(data[len(data)-1])
	} else if addr.Type == ADDRESSTYPE_IPV4 {
		addr.IP = data[1:5]
		addr.Port = uint16(data[len(data)-2])<<8 | uint16(data[len(data)-1])
	} else if addr.Type == ADDRESSTYPE_IPV6 {
		addr.IPV6 = data[1:17]
		addr.Port = uint16(data[len(data)-2])<<8 | uint16(data[len(data)-1])
	} else {
		addr.Valid = false
		return nil
	}
	addr.Valid = true
	return nil
}
