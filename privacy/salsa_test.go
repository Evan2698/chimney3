package privacy

import (
	"chimney3/mem"
	"testing"
)

func TestXxx(t *testing.T) {
	I := NewMethodWithName("SALSA-20")
	nonce := I.MakeSalt()
	I.SetIV(nonce)
	key := MakeCompressKey("SALSA-20")
	buffer := mem.NewApplicationBuffer()
	small := buffer.GetSmall()
	I.Compress([]byte("hello"), key, small)
	out := buffer.GetSmall()
	I.Uncompress(small[:5], key, out)
	result := string(out[:5])
	t.Log(result)
	if result != "hello" {
		t.Error("salsa20 compress error")
	} else {
		t.Log("salsa20 compress ok")
	}

}
