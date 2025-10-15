package privacy

import (
	"bytes"
	"chimney3-go/utils"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/salsa20"
)

type salsa_20 struct {
	iv []byte
}

const (
	salsaName = "SALSA20-I"
	salsaCode = 0x1238
)

func (g *salsa_20) Compress(src []byte, key []byte, out []byte) (int, error) {
	n := len(src)
	if n == 0 {
		return 0, errors.New("compressed failed")
	}

	if len(out) < n {
		return 0, errors.New("out of buffer")
	}

	if len(key) != 32 {
		return 0, errors.New("key length must be 32 bytes")
	}
	if len(g.iv) != 24 {
		return 0, errors.New("IV length must be 24 bytes")
	}
	var keyArr [32]byte

	copy(keyArr[:], key)

	salsa20.XORKeyStream(out, src, g.iv[:], &keyArr)

	return n, nil
}

func (g *salsa_20) Uncompress(src []byte, key []byte, out []byte) (int, error) {

	return g.Compress(src, key, out)
}

func (g *salsa_20) MakeSalt() []byte {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil
	}
	return nonce
}

func (g *salsa_20) GetIV() []byte {
	return g.iv[:]
}

func (g *salsa_20) SetIV(iv []byte) {
	g.iv = make([]byte, len(iv))
	copy(g.iv, iv)
}

func (g *salsa_20) GetSize() int {
	return 2 + 1 + len(g.iv)
}

func (g *salsa_20) ToBytes() []byte {
	var op bytes.Buffer
	mask := utils.Uint162Bytes(gcmCode)
	op.Write(mask)
	lv := (byte)(len(g.iv))
	op.WriteByte(lv)
	if lv > 0 {
		op.Write(g.iv)
	}
	return op.Bytes()
}

// From bytes
func (g *salsa_20) FromBytes(v []byte) error {
	op := bytes.NewBuffer(v)
	lvl := op.Next(1)
	if len(lvl) < 1 {
		return errors.New("out of length")
	}

	value := int(lvl[0])
	if value > 0 {
		iv := op.Next(value)
		g.SetIV(iv)
	}
	return nil
}

func init() {
	register(salsaName, salsaCode, &salsa_20{})
}
