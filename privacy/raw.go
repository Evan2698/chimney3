package privacy

import (
	"bytes"
	"chimney3/utils"
	"crypto/rand"
	"errors"
	"io"
)

type rawMethod struct {
	iv []byte
}

const (
	rawName = "RAW"
	rawCode = 0x1237
)

func (raw *rawMethod) Compress(src []byte, key []byte, out []byte) (int, error) {
	defer utils.Trace("Compress")()
	n := copy(out, src)
	return n, nil
}

func (raw *rawMethod) Uncompress(src []byte, key []byte, out []byte) (int, error) {
	return raw.Compress(src, key, out)
}

func (raw *rawMethod) MakeSalt() []byte {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil
	}
	return nonce
}

func (raw *rawMethod) GetIV() []byte {
	return raw.iv
}

func (raw *rawMethod) SetIV(iv []byte) {
	raw.iv = make([]byte, len(iv))
	copy(raw.iv, iv)
}

func (raw *rawMethod) GetSize() int {
	return 2 + 1 + len(raw.iv)
}

func (raw *rawMethod) ToBytes() []byte {
	var op bytes.Buffer
	mask := utils.Uint162Bytes(rawCode)
	op.Write(mask)
	lv := (byte)(len(raw.iv))
	op.WriteByte(lv)
	if lv > 0 {
		op.Write(raw.iv)
	}
	return op.Bytes()
}

// From bytes
func (raw *rawMethod) FromBytes(v []byte) error {
	op := bytes.NewBuffer(v)
	lvl := op.Next(1)
	if len(lvl) < 1 {
		return errors.New("out of length")
	}

	value := int(lvl[0])
	if value > 0 {
		iv := op.Next(value)
		raw.SetIV(iv)
	}
	return nil
}

func init() {
	register(rawName, rawCode, &rawMethod{})
}
