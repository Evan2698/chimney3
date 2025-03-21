package privacy

import (
	"bytes"
	"chimney3/utils"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/salsa20"
)

type saLsa20 struct {
	iv []byte
}

const (
	salsa20name = "salsa-20"
	salsa20Code = 0x1236
)

func (salsa *saLsa20) Compress(src []byte, key []byte, out []byte) (int, error) {
	if len(key) != 32 || len(src) == 0 {
		return 0, errors.New("parameter is invalid")
	}

	salsa20.XORKeyStream(out, src, salsa.iv, (*[32]byte)(key))

	return len(src), nil
}

func (salsa *saLsa20) Uncompress(src []byte, key []byte, out []byte) (int, error) {
	return salsa.Compress(src, key, out)
}

func (salsa *saLsa20) GetIV() []byte {
	return salsa.iv
}

// salt
func (salsa *saLsa20) MakeSalt() []byte {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil
	}
	return nonce

}

// SetIV
func (salsa *saLsa20) SetIV(iv []byte) {
	salsa.iv = make([]byte, len(iv))
	copy(salsa.iv, iv)
}

// GetSize
func (salsa *saLsa20) GetSize() int {

	return 2 + 1 + len(salsa.iv)
}

// bytes
func (salsa *saLsa20) ToBytes() []byte {

	var op bytes.Buffer
	mask := utils.Uint162Bytes(chacha20Code)
	op.Write(mask)
	lv := (byte)(len(salsa.iv))
	op.WriteByte(lv)
	if lv > 0 {
		op.Write(salsa.iv)
	}
	return op.Bytes()
}

// From bytes
func (salsa *saLsa20) FromBytes(v []byte) error {

	op := bytes.NewBuffer(v)
	lvl := op.Next(1)
	if len(lvl) < 1 {
		return errors.New("out of length")
	}

	value := int(lvl[0])
	if value > 0 {
		iv := op.Next(value)
		salsa.SetIV(iv)
	}
	return nil
}

func init() {
	register(salsa20name, salsa20Code, &saLsa20{})
}
