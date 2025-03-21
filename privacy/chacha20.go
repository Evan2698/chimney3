package privacy

import (
	"bytes"
	"chimney3/privacy/chacha20"
	"chimney3/utils"
	"crypto/rand"
	"errors"
	"io"
)

type cha20 struct {
	iv []byte
}

const (
	chacha20Name = "CHACHA-20"
	chacha20Code = 0x1235
)

func (chacha *cha20) Compress(src []byte, key []byte, out []byte) (int, error) {

	if len(key) != 32 || len(src) == 0 {
		return 0, errors.New("parameter is invalid")
	}

	a, err := chacha20.NewXChaCha(key, chacha.iv)
	if err != nil {
		return 0, err
	}

	a.XORKeyStream(out, src)

	return len(src), nil

}

func (chacha *cha20) Uncompress(src []byte, key []byte, out []byte) (int, error) {
	return chacha.Compress(src, key, out)
}

func (chacha *cha20) MakeSalt() []byte {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil
	}
	return nonce
}

func (chacha *cha20) GetIV() []byte {
	return chacha.iv
}

func (chacha *cha20) SetIV(iv []byte) {
	chacha.iv = make([]byte, len(iv))
	copy(chacha.iv, iv)
}

func (chacha *cha20) GetSize() int {
	return 2 + 1 + len(chacha.iv)
}

func (chacha *cha20) ToBytes() []byte {
	var op bytes.Buffer
	mask := utils.Uint162Bytes(chacha20Code)
	op.Write(mask)
	lv := (byte)(len(chacha.iv))
	op.WriteByte(lv)
	if lv > 0 {
		op.Write(chacha.iv)
	}
	return op.Bytes()
}

// From bytes
func (chacha *cha20) FromBytes(v []byte) error {
	op := bytes.NewBuffer(v)
	lvl := op.Next(1)
	if len(lvl) < 1 {
		return errors.New("out of length")
	}

	value := int(lvl[0])
	if value > 0 {
		iv := op.Next(value)
		chacha.SetIV(iv)
	}
	return nil
}

func init() {
	register(chacha20Name, chacha20Code, &cha20{})
}
