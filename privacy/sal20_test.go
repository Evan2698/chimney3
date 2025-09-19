package privacy

import (
	"bytes"
	"testing"
)

func TestSalsa(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	plaintext := []byte("Hello, World! This is a test message for Salsa20 encryption.")
	s := &salsa_20{}
	s.SetIV(s.MakeSalt())

	// 加密
	ciphertext := make([]byte, len(plaintext))
	n, err := s.Compress(plaintext, key, ciphertext)
	if err != nil || n != len(plaintext) {
		panic("Encryption failed: " + err.Error())
	}

	t.Logf("Ciphertext: %x", ciphertext)

	// 解密
	decrypted := make([]byte, len(ciphertext))
	n, err = s.Uncompress(ciphertext, key, decrypted)
	if err != nil || n != len(ciphertext) {
		panic("Decryption failed: " + err.Error())
	}
	t.Log("Decrypted text:", string(decrypted))

	// 验证
	if !bytes.Equal(plaintext, decrypted) {
		panic("Decrypted text does not match original")
	}
}
