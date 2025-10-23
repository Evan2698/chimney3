package udpserver

import (
	"log"
	"net"
	"time"
	"tun2proxylib/gvisorcore/buffer"
	"tun2proxylib/udppackage"
)

var (
	stop = false
)

func RunUdpServer(udpURl string) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on udp server: ", err)
		}
	}()
	if udpURl == "" {
		udpURl = "0.0.0.0:5353"
	}

	udpAddr, err := net.ResolveUDPAddr("udp", udpURl)
	if err != nil {
		return
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return
	}
	defer conn.Close()

	buf := buffer.Get()
	defer buffer.Put(buf)
	for {

		if stop {
			break
		}

		conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		// Handle received data in buf[:n] from addr
		target, src, payload, err := udppackage.UnpackUDPData(buf[:n])
		if err != nil {
			continue
		}
		go captureRemote(target, addr, src, payload, conn)

	}

}

func captureRemote(target, local, src *net.UDPAddr, payload []byte, conn *net.UDPConn) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on udp server: ", err)
		}
	}()

	remoteConn, err := net.DialUDP("udp", nil, target)
	if err != nil {
		log.Println("Error dialing UDP:", err)
		return
	}
	defer remoteConn.Close()

	remoteConn.SetWriteDeadline(time.Now().Add(20 * time.Second))
	remoteConn.Write(payload)

	buf := buffer.Get()
	defer buffer.Put(buf)

	remoteConn.SetReadDeadline(time.Now().Add(20 * time.Second))

	n, _, err := remoteConn.ReadFromUDP(buf)
	if err != nil {
		log.Println("remote failed", err)
		return
	}

	packet, err := udppackage.PackUDPData(src, target, buf[:n])
	if err != nil {
		log.Println("pack udp failed", err)
		return
	}

	conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
	conn.WriteToUDP(packet, local)
}

func Stop() {
	stop = true
}
