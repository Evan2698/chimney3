package kcpproxy

import (
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltValue = "chimney3kcp"
)

func deriveKey(user string) []byte {
	// 生成一个固定的密钥用于演示目的
	// 在生产环境中，应使用更安全的密钥管理方法
	demoKey := pbkdf2.Key([]byte(user), []byte(saltValue), 4096, 32, sha1.New)
	return demoKey
}
