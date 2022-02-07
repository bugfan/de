package de

import (
	"os"

	"github.com/bugfan/to"
)

func init() {
	if key := os.Getenv("DES_KEY"); key != "" {
		Default.desKey = key
	}

	if exp := to.Int64(os.Getenv("DES_EXP")); exp > 0 {
		Default.desExp = exp
	}
}

func SetKey(key string) {
	Default.desKey = key
}

func SetExp(e int64) {
	Default.desExp = e
}
