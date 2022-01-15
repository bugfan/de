package de

import (
	"os"

	"github.com/bugfan/to"
)

var (
	DesKey       = "abcd1234" // des必须使用8个字节（3des需使用24字节）
	DesExp int64 = 60         // 默认60秒之内可以解开
)

func init() {
	key := os.Getenv("DES_KEY")
	if key != "" {
		DesKey = key
	}
	exp := to.Int64(os.Getenv("DES_EXP"))
	if exp > 0 {
		DesExp = exp
	}
}

func SetKey(key string) {
	DesKey = key
}

func SetExp(e int64) {
	DesExp = e
}
