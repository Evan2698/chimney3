package privacy

import (
	"bytes"
	"chimney3-go/utils"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"log"
)

type gcm struct {
	iv []byte
}

const (
	gcmName = "AES-GCM"
	gcmCode = 0x1234
)

func (g *gcm) Compress(src []byte, key []byte, out []byte) (int, error) {
	defer utils.Trace("Compress")()

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("key of AES is invalid!")
		return 0, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println("key of AES is invalid!")
		return 0, err
	}

	ciphertext := aesgcm.Seal(nil, g.iv, src, nil)
	n := len(ciphertext)
	if n == 0 {
		return 0, errors.New("compressed failed")
	}

	if len(out) < n {
		return 0, errors.New("out of buffer")
	}

	m := copy(out, ciphertext)

	return m, nil
}

func (g *gcm) Uncompress(src []byte, key []byte, out []byte) (int, error) {
	defer utils.Trace("Uncompress")()

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("key of AES is invalid!(uncompress)")
		return 0, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println("key of AES is invalid!(uncompress)")
		return 0, err
	}

	plaintext, err := aesgcm.Open(nil, g.iv, src, nil)
	n := len(plaintext)

	if n == 0 {
		return 0, errors.New("compressed failed")
	}

	if len(out) < n {
		return 0, errors.New("out of buffer")
	}

	m := copy(out, plaintext)

	return m, err
}

func (g *gcm) MakeSalt() []byte {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil
	}
	return nonce
}

func (g *gcm) GetIV() []byte {
	return g.iv
}

func (g *gcm) SetIV(iv []byte) {
	g.iv = make([]byte, len(iv))
	copy(g.iv, iv)
}

func (g *gcm) GetSize() int {
	return 2 + 1 + len(g.iv)
}

func (g *gcm) ToBytes() []byte {
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
func (g *gcm) FromBytes(v []byte) error {
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
	register(gcmName, gcmCode, &gcm{})
}
