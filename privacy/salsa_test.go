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
	n, _ := I.Compress([]byte("zhangssskkdjdjakg"), key, small)
	out := buffer.GetSmall()
	I.Uncompress(small[:n], key, out)
	result := string(out[:n])
	t.Log(result)
	t.Log(result)
	if result != "hello" {
		t.Error("salsa20 compress error")
	} else {
		t.Log("salsa20 compress ok")
	}

}
