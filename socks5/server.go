package socks5

import (
	"bytes"
	"chimney3/core"
	"chimney3/mem"
	"chimney3/mobile"
	"chimney3/privacy"
	"chimney3/utils"
	"errors"
	"log"
	"net"
	"strconv"
	"sync"
)

type Socks5Server interface {
	Serve() error
	Stop()
}

type Socks5ServerSettings struct {
	Server     string
	ServerPort int
	IsLocal    bool
	PassWord   string
	Which      string
	Local      string
	LocalPort  int
	User       string
}

type Socks5S struct {
	Key      []byte
	I        privacy.EncryptThings
	Settings *Socks5ServerSettings
	Exit     bool
	Protect  mobile.ProtectSocket
}

type socks5session struct {
	Conn             net.Conn
	AuthenticateUser bool
}

func (session *socks5session) Close() {
	session.Conn.Close()
	session.AuthenticateUser = false
}

func (s *Socks5S) Serve() error {

	host := net.JoinHostPort(s.Settings.Server, strconv.Itoa(s.Settings.ServerPort))
	// to TCP
	log.Println("server run on " + host + " with tcp protocol.")
	l, err := net.Listen("tcp", host)
	if err != nil {
		log.Println("listen failed ", err)
		return err
	}

	defer l.Close()

	for {
		con, err := l.Accept()
		if err != nil {
			log.Println(" accept failed ", err)
			break
		}
		if s.Exit {
			log.Println("EXIT TCP")
			break
		}
		session := &socks5session{
			Conn:             con,
			AuthenticateUser: false,
		}

		go s.serveOn(session)
	}

	return err
}

func (s *Socks5S) serveOn(session *socks5session) {
	// Implement the serveOn method here
	defer session.Close()
	// Add your handling code here

	defer utils.Trace("serveOn")()
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on proxyWrite: ", err)
		}
	}()
	SetSocketTimeout(session.Conn, MAX_TIME_OUT)

	err := s.echoHello(session)
	if err != nil {
		log.Println("echo error", err)
		return
	}

	dstConn, err := s.doCommandConnect(session)
	if err != nil {
		log.Println("create dst socket faile", err)
		return
	}

	defer func() {
		dstConn.Close()
	}()

	wg := sync.WaitGroup{}
	wg.Add(2)
	go copyConnect2Connect(session.Conn, dstConn, &wg)
	go copyConnect2Connect(dstConn, session.Conn, &wg)
	wg.Wait()

}

func copyConnect2Connect(src, dst net.Conn, wg *sync.WaitGroup) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on proxy: ", err)
		}
	}()

	tmpBuffer := mem.NewApplicationBuffer().GetLarge()
	defer func() {
		mem.NewApplicationBuffer().PutLarge(tmpBuffer)
	}()

	for {
		n, err := src.Read(tmpBuffer[:mem.LARGE_BUFFER_SIZE-BUFFER_OFFSET])
		if err != nil {
			log.Println("read src failed ", err)
			break
		}
		_, err = dst.Write(tmpBuffer[:n])
		if err != nil {
			log.Println("write dst failed ", err)
			break
		}
	}

	wg.Done()

}

func (s *Socks5S) echoHello(session *socks5session) error {
	con := session.Conn
	tmpBuffer := mem.NewApplicationBuffer().GetSmall()
	defer func() {
		mem.NewApplicationBuffer().PutSmall(tmpBuffer)
	}()
	n, err := con.Read(tmpBuffer)
	if err != nil {
		return err
	}
	res := []byte{socks5Version, 0xff}
	if n < 3 || tmpBuffer[0] != socks5Version {
		con.Write(res)
		log.Println("client hello message: ", tmpBuffer[:n])
		return errors.New("client hello message error")
	}
	if tmpBuffer[1] < 1 {
		con.Write(res)
		log.Println("length of method : ", tmpBuffer[:n])
		return errors.New("length of method format error")
	}
	if tmpBuffer[2] == socks5NoAuth {
		res = []byte{socks5Version, socks5NoAuth}
		_, err = con.Write(res)
		if err != nil {
			log.Println("write hello failed (NoAuth)", err)
			return err
		}

		return nil
	}

	if tmpBuffer[2] == socks5AuthWithUserPass {
		session.AuthenticateUser = true
		var out bytes.Buffer
		out.Write([]byte{socks5Version, socks5AuthWithUserPass})
		ii := s.I.ToBytes()
		out.WriteByte(byte(len(ii)))
		out.Write(ii)
		_, err = con.Write(out.Bytes())
		if err != nil {
			log.Println("write hello failed(U&P) ", err)
			return err
		}

		err = s.authUser(con)
		if err != nil {
			log.Println("verify user failed", err)
			return err
		}

		return nil
	}

	con.Write(res)
	return errors.New("not implement for other method")
}

func (s *Socks5S) authUser(con net.Conn) error {
	tmpBuffer := mem.NewApplicationBuffer().GetSmall()
	defer func() {
		mem.NewApplicationBuffer().PutSmall(tmpBuffer)
	}()
	res := []byte{socks5Version, 0xff}
	n, err := con.Read(tmpBuffer)
	if err != nil {
		con.Write(res)
		return err
	}

	if n < 10 {
		return errors.New("user and password is incorrect")
	}

	if tmpBuffer[0] != socks5Version || tmpBuffer[1] != socks5AuthWithUserPass {
		return errors.New("verify user failed")
	}
	userLen := tmpBuffer[2]
	usr := tmpBuffer[3 : 3+userLen]
	userName := string(usr)

	pass := tmpBuffer[3+userLen+1 : n]
	sha1 := privacy.BuildMacHash(s.Key, userName)
	tmpOutBuffer := mem.NewApplicationBuffer().GetSmall()
	defer func() {
		mem.NewApplicationBuffer().PutSmall(tmpOutBuffer)
	}()
	n, err = s.I.Uncompress(pass, s.Key, tmpOutBuffer)
	if err != nil {
		log.Println("uncompress user name failed", err)
		return err
	}
	if bytes.Equal(sha1, tmpOutBuffer[:n]) {
		con.Write([]byte{socks5Version, 0x00})
		log.Println("verify success!")
		return nil
	}

	con.Write([]byte{socks5Version, 0xff})

	return errors.New("other error")
}

func (s *Socks5S) doCommandConnect(session *socks5session) (remote net.Conn, err error) {
	conn := session.Conn
	tmpBuffer := mem.NewApplicationBuffer().GetSmall()
	defer func() {
		mem.NewApplicationBuffer().PutSmall(tmpBuffer)
	}()

	n, err := conn.Read(tmpBuffer)
	if err != nil {
		conn.Write([]byte{0x05, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("read connect command failed", err)
		return nil, err
	}

	cmd := tmpBuffer[:n]
	log.Println("connect: ", tmpBuffer[:n])
	if len(cmd) < 4 {
		conn.Write([]byte{0x05, 0x0F, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("cmd length is too short!!")
		return nil, errors.New("cmd length is too short")
	}
	if cmd[0] != socks5Version {
		conn.Write([]byte{0x05, 0x0E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("cmd protocol is incorrect")
		return nil, errors.New("cmd protocol is incorrect")
	}

	if socks5CMDConnect != cmd[1] {
		conn.Write([]byte{0x05, 0x0B, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Println("command is not connection command")
		return nil, errors.New("command is not connection command")
	}

	if session.AuthenticateUser {
		text := cmd[5:]
		if int(cmd[4]) != len(text) {
			conn.Write([]byte{0x05, 0x1B, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			log.Println("address not is incorrect")
			return nil, errors.New("address length is incorrect")
		}

		n, err = s.I.Uncompress(text, s.Key, tmpBuffer)
		if err != nil {
			conn.Write([]byte{0x05, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			log.Println("command is not connection command")
			return nil, err
		}
		addr := core.NewSocks5Address()
		err = addr.Parse(tmpBuffer[:n])
		if err != nil {
			conn.Write([]byte{0x05, 0x0B, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			log.Println("command is not connection command")
			return nil, err
		}

		remote, err = buildTcpSocket(addr)
		if err != nil {
			conn.Write([]byte{0x05, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			log.Println("build tcp failed", err)
			return nil, err
		}

		ra, _ := core.ParseTargetAddress(remote.RemoteAddr().String())
		n, err = s.I.Compress(ra.Bytes(), s.Key, tmpBuffer)
		if err != nil {
			conn.Write([]byte{0x05, 0x11, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			log.Println("remote address compress failed", err)
			remote.Close()
			return nil, err
		}
		var op bytes.Buffer
		op.Write([]byte{socks5Version, socks5ReplySuccess, 0x00, ra.Type})
		op.WriteByte(byte(n))
		op.Write(tmpBuffer[:n])
		_, err = conn.Write(op.Bytes())
		if err != nil {
			remote.Close()
			log.Print("write response failed ", err)
			return nil, err
		}
		return remote, nil

	} else {
		address := core.NewSocks5Address()
		err = address.Parse(cmd[4:])
		if err != nil {
			conn.Write([]byte{0x05, 0x11, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			log.Println("parse socks5 connect address failed", err)
			return nil, err
		}
		remoteAddress, err := s.buildTcpSocketWithSocks5Address(address)
		if err != nil {
			conn.Write([]byte{0x05, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			log.Println("parse socks5 connect address failed", err)
			return nil, err
		}

		ra := remoteAddress.GetDstSocks5Address()

		var op bytes.Buffer
		op.Write([]byte{socks5Version, socks5ReplySuccess, 0x00})
		op.Write(ra.Bytes())
		conn.Write(op.Bytes())

		return remoteAddress, nil
	}

}

func (s *Socks5S) buildTcpSocketWithSocks5Address(addr *core.Socks5Address) (conn core.SocksStream, err error) {
	cc := &ClientSettings{
		Server:     s.Settings.Server,
		ServerPort: s.Settings.ServerPort,
		Local:      s.Settings.Local,
		LocalPort:  s.Settings.LocalPort,
		User:       s.Settings.User,
		PassWord:   s.Settings.PassWord,
	}
	client := NewSocks5Client(cc, s.Protect)
	conn, err = client.Dial(addr)
	return conn, err
}

func buildTcpSocket(addr *core.Socks5Address) (net.Conn, error) {

	host := addr.String()
	log.Println("connect the host: ", host)
	return net.Dial("tcp", host)
}
