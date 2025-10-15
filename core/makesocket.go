package core

import (
	"chimney3-go/mobile"
	"errors"
	"log"
	"net"
	"os"
	"strconv"
	"syscall"
)

var (
	TCP_SOCKET = 0x1
	UDP_SOCKET = 0x2
)

func AessembleSocketAddress(ip net.IP, port uint16) (sa syscall.Sockaddr, err error) {

	if ip == nil {
		return nil, errors.New("none address")
	}

	if ip.To4() == nil {
		ipa := ip.To16()
		sa = &syscall.SockaddrInet6{
			Port: int(port),
			Addr: [16]byte{ipa[0], ipa[1], ipa[2], ipa[3],
				ipa[4], ipa[5], ipa[6],
				ipa[7], ipa[8], ipa[9],
				ipa[10], ipa[11], ipa[12],
				ipa[13], ipa[14], ipa[15]},
		}
	} else {
		ipa := ip.To4()
		sa = &syscall.SockaddrInet4{
			Port: int(port),
			Addr: [4]byte{ipa[0], ipa[1], ipa[2], ipa[3]},
		}
	}

	return sa, err
}

func ParseIPAddress(host string) (ip net.IP, port uint16, err error) {
	host, portStr, err := net.SplitHostPort(host)
	if err != nil {
		return nil, 0, err
	}

	ip = net.ParseIP(host)
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, err
	}
	port = uint16(portInt)
	return ip, port, nil
}

func CreateSocket(host string, which int, protect mobile.ProtectSocket) (con net.Conn, err error) {

	ip, port, err := ParseIPAddress(host)
	if err != nil {
		return nil, err
	}
	sa, err := AessembleSocketAddress(ip, port)
	if err != nil {
		return nil, err
	}

	socketType := syscall.SOCK_STREAM
	protocol := syscall.IPPROTO_TCP

	if which == UDP_SOCKET {
		socketType = syscall.SOCK_DGRAM
		protocol = syscall.IPPROTO_UDP
	}

	fd, err := syscall.Socket(syscall.AF_INET, socketType, protocol)
	if err != nil {
		return nil, err
	}

	defer func() {
		syscall.Close(fd)
	}()

	if protect != nil {
		r := protect.Protect(fd)
		log.Println("protect socket value: ", r)
	}
	if which == TCP_SOCKET {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, 128)
		if err != nil {
			log.Println("setsockopt failed!!!!", err)
			return nil, err
		}
	}

	err = syscall.Connect(fd, sa)
	if err != nil {
		log.Println("connect remote end failed!!!!", err)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "")
	defer file.Close()

	outcon, err := net.FileConn(file)

	return outcon, err
}
