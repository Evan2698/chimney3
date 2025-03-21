package privacy

import (
	"chimney3/utils"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"log"
	"reflect"
)

// EncryptThings for everything protecting
type EncryptThings interface {
	// encrypt the bytes
	Compress(src []byte, key []byte, out []byte) (int, error)

	// descrypt the bytes
	Uncompress(src []byte, key []byte, out []byte) (int, error)

	//iv
	GetIV() []byte

	// salt
	MakeSalt() []byte

	//SetIV
	SetIV([]byte)

	//GetSize
	GetSize() int

	//bytes
	ToBytes() []byte

	//From bytes
	FromBytes(v []byte) error
}

var globalTable map[string]interface{} = make(map[string]interface{})
var globalTablei map[uint16]interface{} = make(map[uint16]interface{})

func register(name string, mask uint16, i interface{}) {
	globalTable[name] = i
	globalTablei[mask] = i
}

// FromBytes ...
func FromBytes(buf []byte) (EncryptThings, error) {
	if buf == nil {
		return nil, errors.New("invalid paramter")
	}

	code := utils.Bytes2Uint16(buf[:2])
	i := newMethodWithCode(code)
	if i == nil {
		return nil, errors.New("use code create method failed")
	}
	if err := i.FromBytes(buf[2:]); err != nil {
		return nil, err
	}
	return i, nil
}

// NewMethodWithName create encrypt method for caller with a name
func NewMethodWithName(name string) EncryptThings {
	if target, ok := globalTable[name]; ok {
		return createObject(target)
	}
	return nil
}

func createObject(target interface{}) EncryptThings {
	t := reflect.New(reflect.TypeOf(target).Elem()).Elem().Addr().Interface()
	if i, ok := t.(EncryptThings); ok {
		i.SetIV(i.MakeSalt())
		return i
	}
	log.Println("create encrypt method failed!!")
	return nil
}

func newMethodWithCode(code uint16) EncryptThings {
	if target, ok := globalTablei[code]; ok {
		return createObject(target)
	}
	return nil
}

// MakeCompressKey ..
func MakeCompressKey(srcKey string) []byte {
	key := []byte("98765432109876543210987654321098")
	tmp := BuildMacHash(key, srcKey)
	out := [32]byte{0}
	copy(out[:], tmp)
	return out[:32]
}

// BuildMacHash ..
func BuildMacHash(key []byte, message string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return h.Sum(nil)
}
