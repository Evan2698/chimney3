package socks5

import (
	"bytes"
	"chimney3/mem"
	"chimney3/privacy"
	"chimney3/utils"
	"errors"
	"log"
	"net"
	"strconv"
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
}

type Socks5S struct {
	Key      []byte
	I        privacy.EncryptThings
	Settings *Socks5ServerSettings
	Exit     bool
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

		go s.serveOn(con)
	}

	return err
}

func (s *Socks5S) serveOn(con net.Conn) {
	// Implement the serveOn method here
	defer con.Close()
	// Add your handling code here

	defer utils.Trace("serveOn")()
	defer func() {
		if err := recover(); err != nil {
			log.Println(" fatal error on proxyWrite: ", err)
		}
	}()
	SetSocketTimeout(con, MAX_TIME_OUT)

	s.echoHello(con)

}
func (s *Socks5S) echoHello(con net.Conn) error {
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
