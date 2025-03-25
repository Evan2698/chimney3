package socks5

import (
	"bytes"
	"chimney3/core"
	"chimney3/mem"
	"chimney3/mobile"
	"chimney3/privacy"
	"errors"
	"io"
	"log"
	"net"
)

type ClientSettings struct {
	ProxyAddress string
	User         string
	PassWord     string
}

type Socks5 struct {
	Settings *ClientSettings
	I        privacy.EncryptThings
	Protect  mobile.ProtectSocket
}

type Socks5Client interface {
	Dial(addr *core.Socks5Address) (core.SocksStream, error)
	Close()
}

func NewSocks5Client(c *ClientSettings, f mobile.ProtectSocket) Socks5Client {

	return &Socks5{
		Settings: c,
		Protect:  f,
	}
}

func (c *Socks5) Dial(addr *core.Socks5Address) (core.SocksStream, error) {

	// 1. create socket
	success := false
	rawSocket, err := c.buildClientSocket()
	if err != nil {
		log.Print("create client socket failed:", err)
		return nil, err
	}
	defer func() {
		if !success {
			rawSocket.Close()
		}
	}()

	// 2. say hello
	err = c.sayHello(rawSocket)
	if err != nil {
		return nil, err
	}

	// 3. do authetication
	key := privacy.MakeCompressKey(c.Settings.PassWord)
	if err = c.authenticateUser(rawSocket, key); err != nil {
		log.Println("authenticate failed! ", err)
		return nil, err
	}

	dstAddr, err := c.connectTarget(rawSocket, addr, key)
	if err != nil {
		log.Println("connect target failed:", err)
		return nil, err
	}

	success = true

	return core.NewSocks5Socket(rawSocket, c.I, key, addr, dstAddr), nil
}

func (c *Socks5) Close() {

}

func (c *Socks5) sayHello(writer io.ReadWriteCloser) error {
	welcome := []byte{socks5Version, 1, socks5AuthWithUserPass}
	if _, err := writer.Write(welcome); err != nil {
		log.Println("hello message failed: ", err)
		return err
	}
	return nil
}

func (c *Socks5) authenticateUser(con io.ReadWriteCloser, key []byte) error {

	tmpBuffer := mem.NewApplicationBuffer().GetSmall()
	defer func() {
		mem.NewApplicationBuffer().PutSmall(tmpBuffer)
	}()

	n, err := con.Read(tmpBuffer)
	if err != nil {
		log.Println("hello response read failed: ", err)
		return err
	}
	if n < 3 || (!bytes.Equal([]byte{socks5Version, socks5AuthWithUserPass}, tmpBuffer[:2])) {
		log.Println("custom protocol is incorrect!! ", tmpBuffer[:n])
		return errors.New("custom protocol is incorrect")
	}

	aLen := int(tmpBuffer[2])
	aCon := tmpBuffer[3:n]
	if aLen != len(aCon) {
		log.Println("encrypt bytes format is incorrect!!  ", tmpBuffer[:n])
		return errors.New("encrypt bytes format is incorrect")
	}

	i, err := privacy.FromBytes(aCon)
	if err != nil {
		log.Println("parse I failed  ", err, aCon)
		return err
	}
	c.I = i

	usrsha1 := privacy.BuildMacHash(key, c.Settings.User)

	tmpOutBuffer := mem.NewApplicationBuffer().GetSmall()
	defer func() {
		mem.NewApplicationBuffer().PutSmall(tmpOutBuffer)
	}()

	n, err = c.I.Compress(usrsha1, key, tmpOutBuffer)
	if err != nil {
		log.Println("compress password failed ", err)
		return err
	}

	usr := []byte(c.Settings.User)
	userLen := len(usr)

	var out bytes.Buffer
	out.WriteByte(socks5Version)
	out.WriteByte(socks5AuthWithUserPass)
	out.WriteByte(byte(userLen))
	out.Write(usr)
	out.WriteByte(byte(n))
	out.Write(tmpOutBuffer[:n])
	log.Println("sha1 ", usrsha1, "enc=", tmpOutBuffer[:n])

	// log.Println("I=", c.I.ToBytes())
	// log.Println("user len=(C)", userLen, " username byte: ", usr, "username=", c.Settings.User)
	// log.Println("key= ", key)
	// log.Print("pass origin=", usrsha1, "unpress=", tmpOutBuffer[:n])

	if _, err = con.Write(out.Bytes()); err != nil {
		log.Println("send user and pass failed! ", err)
		return err
	}

	n, err = con.Read(tmpBuffer)
	if err != nil {
		log.Println("read authentication response failed! ", err)
		return err
	}
	if n != 2 {
		log.Println("authentication result format is incorrect ! ", tmpBuffer[:n])
		return errors.New("authentication result format is incorrect")
	}
	if !bytes.Equal([]byte{socks5Version, 0x00}, tmpBuffer[:n]) {
		log.Println("authentication result is incorrect ! ", tmpBuffer[:n])
		return errors.New("authentication result is incorrect")
	}
	return nil
}

func (c *Socks5) connectTarget(con net.Conn, addr *core.Socks5Address, key []byte) (dst *core.Socks5Address, err error) {

	log.Println("socks5 address: ", addr.String(), addr.Bytes())
	var op bytes.Buffer
	op.Write([]byte{socks5Version, socks5CMDConnect, 0x00, addr.Type})
	tmpBuffer := mem.NewApplicationBuffer().GetSmall()
	defer func() {
		mem.NewApplicationBuffer().PutSmall(tmpBuffer)
	}()
	n, err := c.I.Compress(addr.Bytes(), key, tmpBuffer)
	if err != nil {
		log.Println("compress address failed", err)
		return nil, err
	}
	op.WriteByte(byte(n))
	op.Write(tmpBuffer[:n])

	if _, err = con.Write(op.Bytes()); err != nil {
		log.Println("send request failed ", err)
		return nil, err
	}

	n, err = con.Read(tmpBuffer[:])
	if err != nil {
		log.Println("request response read failed ", err)
		return nil, err
	}

	if n < 10 || !bytes.Equal(tmpBuffer[:3], []byte{socks5Version, 0x00, 00}) {
		log.Println("there is a format error in response ", tmpBuffer[:n])
		return nil, err
	}

	response := tmpBuffer[5:n]
	log.Println("compress", tmpBuffer[:n], response)
	tmpOutBuffer := mem.NewApplicationBuffer().GetSmall()
	defer func() {
		mem.NewApplicationBuffer().PutSmall(tmpOutBuffer)
	}()
	n, err = c.I.Uncompress(response, key, tmpOutBuffer)
	if err != nil || n < 1 {
		log.Println("dst address parse failed: ", err)
		return nil, err
	}

	socks5Address := core.NewSocks5Address()
	err = socks5Address.Parse(tmpOutBuffer[:n])
	if err != nil {
		log.Println("dst address parse failed: ", err)
		return nil, err
	}

	//log.Println("client--->", socks5Address.String())

	return socks5Address, nil
}

func (c *Socks5) buildClientSocket() (con net.Conn, err error) {
	host := c.Settings.ProxyAddress
	if c.Protect != nil {
		con, err = core.CreateSocket(host, core.TCP_SOCKET, c.Protect)
	} else {
		con, err = net.Dial("tcp", host)
	}

	return con, err
}
