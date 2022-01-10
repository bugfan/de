package de

import (
	"os"

	"github.com/bugfan/to"
)

var (
	DesKey       = "abcd1234" // must be 8 bytes
	DesExp int64 = 60         // default 60s 内可以解开
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
