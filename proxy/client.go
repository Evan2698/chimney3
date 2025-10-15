package proxy

import (
	"chimney3-go/core"
	"chimney3-go/mem"
	"chimney3-go/privacy"
	"log"
	"net"
	"sync"
)

type proxyClient struct {
	Password     string
	I            privacy.EncryptThings
	LocalHost    string
	ProxyAddress string
	Exit         bool
}

type ProxyClient interface {
	Serve()
	Close()
}

func (c *proxyClient) Serve() {
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on serveOn: ", err)
		}
	}()

	l, err := net.Listen("tcp", c.LocalHost)
	if err != nil {
		log.Println("listen failed ", err)
		return
	}

	defer l.Close()

	for {
		con, err := l.Accept()
		if err != nil {
			log.Println(" accept failed ", err)
			break
		}
		if c.Exit {
			log.Println(" accept failed ", err)
			break
		}
		go c.serveOn(con)
	}
}

func (c *proxyClient) Close() {
	c.Exit = true
}

func (c *proxyClient) serveOn(con net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on serveOn: ", err)
		}
	}()

	defer con.Close()

	//do handshake
	key := privacy.MakeCompressKey(c.Password)
	dstIm, err := net.Dial("tcp", c.ProxyAddress)
	if err != nil {
		log.Println("handshake failed ", err)
		return
	}

	dst := core.NewMySSLSocket(dstIm, nil, key)
	err = dst.HandshakeClient()
	if err != nil {
		dst.Close()
		log.Println("handshake failed ", err)
		return
	}
	if !dst.IsOk() {
		dst.Close()
		log.Println("check dst status failed! ", err)
		return
	}

	defer dst.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go transfer(dst, con, &wg)
	go transfer(con, dst, &wg)
	wg.Wait()

}

// func (c *proxyClient) handshake(host string, con net.Conn) (net.Conn, error) {
// 	// handshake
// 	// 1. send username and password
// 	// 2. receive username and password
// 	// 3. send ok or not
// 	// 4. receive ok or not

// 	dst, err := net.Dial("tcp", host)
// 	if err != nil {
// 		log.Println("dial failed ", err)
// 		return nil, err
// 	}

// 	// send username and password
// 	_, err = dst.Write([]byte{0x5, 0x1, 0x0})
// 	if err != nil {
// 		log.Println("write failed ", err)
// 		dst.Close()
// 		return nil, err
// 	}

// 	buffer := mem.NewApplicationBuffer().GetSmall()
// 	defer func() {
// 		mem.NewApplicationBuffer().PutSmall(buffer)
// 	}()
// 	n, err := dst.Read(buffer)
// 	if err != nil {
// 		log.Println("read failed ", err)
// 		dst.Close()
// 		return nil, err
// 	}

// 	if int(buffer[0]) != n-1 {
// 		log.Println("handshake failed ", err)
// 		dst.Close()
// 		return nil, err
// 	}
// 	pBuffer := buffer[1:n]
// 	II, err := privacy.FromBytes(pBuffer)
// 	if err != nil {
// 		log.Println("handshake failed ", err)
// 		dst.Close()
// 		return nil, err
// 	}
// 	// send ok
// 	c.I = II
// 	dst.Write([]byte{0x5, 0x0})
// 	// receive ok
// 	key := privacy.MakeCompressKey(c.Password)
// 	return NewProxySocket(dst, c.I, key), nil
// }

func transfer(src, dst net.Conn, wg *sync.WaitGroup) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on Transfer: ", err)
		}
	}()

	defer wg.Done()

	buf := mem.NewApplicationBuffer().GetLarge()
	defer func() {
		mem.NewApplicationBuffer().PutLarge(buf)
	}()
	for {
		n, err := src.Read(buf)
		if err != nil {
			log.Println("read failed ", err)
			break
		}

		_, err = dst.Write(buf[:n])
		if err != nil {
			log.Println("write failed ", err)
			break
		}
	}
}
