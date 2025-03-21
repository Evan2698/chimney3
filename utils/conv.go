package utils

import (
	"bytes"
	"encoding/binary"
	"strings"
)

//Int2Bytes ...
func Int2Bytes(n uint32) []byte {
	u := uint32(n)
	var hello bytes.Buffer
	binary.Write(&hello, binary.BigEndian, u)
	return hello.Bytes()
}

//Bytes2Int ...
func Bytes2Int(b []byte) uint32 {
	bytesBuffer := bytes.NewBuffer(b)
	var tmp uint32
	binary.Read(bytesBuffer, binary.BigEndian, &tmp)
	return tmp
}

// Bytes2Uint16 ...
func Bytes2Uint16(b []byte) uint16 {
	bytesBuffer := bytes.NewBuffer(b)
	var tmp uint16
	binary.Read(bytesBuffer, binary.BigEndian, &tmp)
	return tmp
}

// Uint162Bytes ...
func Uint162Bytes(b uint16) []byte {
	var hello bytes.Buffer
	binary.Write(&hello, binary.BigEndian, b)
	return hello.Bytes()
}

// Port2Bytes ..
func Port2Bytes(port uint16) []byte {
	return Uint162Bytes(port)
}

// FormatProtocol ..
func FormatProtocol(p string) string {
	p = strings.ToLower(p)
	p = strings.Trim(p, " ")
	r := "tcp"
	if strings.Contains("quic", p) {
		r = "quic"
	}
	return r
}
