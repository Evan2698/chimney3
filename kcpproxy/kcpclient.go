package kcpproxy

import (
	"chimney3/privacy"
	"crypto/sha1"
	"sync"

	"log"
	"net"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

type kcpClient struct {
	User      string
	PassWord  string
	Proxy     string
	LocalHost string
	Exit      bool
}

type KCPClient interface {
	Serve()
	Close()
}

func NewKcpClient(User, Pass, Proxy, Host string) KCPClient {
	return &kcpClient{
		User:      User,
		PassWord:  Pass,
		Proxy:     Proxy,
		LocalHost: Host,
	}
}

func (c *kcpClient) Serve() {
	l, err := net.Listen("tcp", c.LocalHost)
	if err != nil {
		log.Println("listen tcp failed", err)
		return
	}

	ks := privacy.MakeCompressKey(c.PassWord)
	salt := privacy.BuildMacHash(ks, c.User)

	key := pbkdf2.Key(ks, salt, 4096, 32, sha1.New)
	block, _ := kcp.NewSalsa20BlockCrypt(key)

	for {
		con, err := l.Accept()
		if err != nil {
			log.Println(" accept failed ", err)
			break
		}
		if c.Exit {
			log.Println("EXIT TCP")
			break
		}
		go c.serveOn(con, block)
	}

}

func (c *kcpClient) serveOn(con net.Conn, block kcp.BlockCrypt) {
	defer func(l net.Conn) {
		l.Close()
	}(con)

	// kSession, err := kcp.DialWithOptions(c.Proxy, block, 10, 3)
	kSession, err := net.Dial("tcp", c.Proxy)
	if err != nil {
		log.Println("session failed", err)
		return
	}

	defer func(k net.Conn) {
		k.Close()
	}(kSession)

	SetSocketTimeout(kSession, 600)
	SetSocketTimeout(con, 600)

	wg := sync.WaitGroup{}
	wg.Add(2)
	go copyConnection(con, kSession, &wg)
	go copyConnection(kSession, con, &wg)
	wg.Wait()
}

func (c *kcpClient) Close() {
	c.Exit = false
}
