package de

import (
	"os"

	"github.com/bugfan/to"
)

func init() {
	if key := os.Getenv("DES_KEY"); key != "" {
		Default.desKey = key
	}

	if exp := to.Int64(os.Getenv("DES_EXPIRE")); exp > 0 {
		Default.desExpire = exp
	}
}

func SetKey(key string) {
	Default.desKey = key
}

func SetExpire(e int64) {
	Default.desExpire = e
}
