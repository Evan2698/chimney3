package kcpproxy

import (
	"chimney3/settings"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/xtaci/kcp-go/v5"
)

func runKCPClient(s settings.Settings) error {
	listenAddress := net.JoinHostPort(s.Client.IP, strconv.Itoa(s.Client.Port))

	l, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatalf("Error listening on %s: %v", listenAddress, err)
		return err
	}
	defer l.Close()
	log.Printf("KCP client listening on %s", listenAddress)

	key := deriveKey(s.Client.User)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		log.Printf("Error creating block cipher: %v", err)
		return err
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			break
		}
		go handleKCPConnection(conn, s, block)
	}

	return nil
}

func handleKCPConnection(conn net.Conn, s settings.Settings, block kcp.BlockCrypt) {

	defer conn.Close()
	proxyAddr := net.JoinHostPort(s.Server.IP, strconv.Itoa(s.Server.Port))
	log.Printf("Connecting to KCP server at %s", proxyAddr)

	sess, err := kcp.DialWithOptions(proxyAddr, block, 10, 3)
	if err != nil {
		log.Printf("Error dialing KCP server: %v", err)
		return
	}
	defer sess.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go clientRoutine(conn, sess, &wg)
	go clientRoutine(sess, conn, &wg)
	wg.Wait()
}

func clientRoutine(src, dest net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(dest, src)
}

func runKCPServer(s settings.Settings) error {
	listenAddress := net.JoinHostPort(s.Server.IP, strconv.Itoa(s.Server.Port))

	key := deriveKey(s.Server.User)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		log.Printf("Error creating block cipher: %v", err)
		return err
	}

	l, err := kcp.ListenWithOptions(listenAddress, block, 10, 3)
	if err != nil {
		log.Fatalf("Error listening on %s: %v", listenAddress, err)
		return err
	}
	defer l.Close()
	log.Printf("KCP server listening on %s", listenAddress)

	for {
		sess, err := l.AcceptKCP()
		if err != nil {
			log.Printf("Error accepting KCP connection: %v", err)
			break
		}
		go handleKCPServerSession(sess)
	}

	return nil
}

// handleKCPServerSession handles an incoming KCP session by echoing data back to the client.
func handleKCPServerSession(conn *kcp.UDPSession) {
	defer conn.Close()
	// 1. 握手阶段
	buf := make([]byte, 258)
	_, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		return
	}
	// 检查 SOCKS5 版本
	if buf[0] != 0x05 {
		return
	}
	// 不认证
	conn.Write([]byte{0x05, 0x00})

	// 2. 请求阶段
	_, err = io.ReadAtLeast(conn, buf, 5)
	if err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 { // 只支持 CONNECT
		return
	}
	var addr string
	switch buf[3] {
	case 0x01: // IPv4
		addr = net.IP(buf[4:8]).String()
		port := binary.BigEndian.Uint16(buf[8:10])
		addr = net.JoinHostPort(addr, fmt.Sprint(int(port)))
	case 0x03: // 域名
		domainLen := int(buf[4])
		addr = string(buf[5 : 5+domainLen])
		port := binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])
		addr = net.JoinHostPort(addr, fmt.Sprint(int(port)))
	case 0x04: // IPv6
		addr = net.IP(buf[4:20]).String()
		port := binary.BigEndian.Uint16(buf[20:22])
		addr = net.JoinHostPort(addr, fmt.Sprint(int(port)))
	default:
		return
	}

	// 3. 连接目标服务器
	target, err := net.Dial("tcp", addr)
	if err != nil {
		// 连接失败
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	// 连接成功
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	var wg sync.WaitGroup
	wg.Add(2)
	go clientRoutine(conn, target, &wg)
	go clientRoutine(target, conn, &wg)
	wg.Wait()
}

func RunKCPRoutine(s *settings.Settings, isServer bool) error {
	if isServer {
		return runKCPServer(*s)
	} else {
		return runKCPClient(*s)
	}
}
