package de

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bugfan/to"
)

func Decode(data []byte) ([]byte, error) {
	key := []byte(DesKey)
	data, err := DesDecrypt(data, key)
	return data, err
}

func Encode(data []byte) ([]byte, error) {
	cryptData, err := DesEncrypt(data, []byte(DesKey))
	return cryptData, err
}

func DecodeWithBase64(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return []byte{}, errors.New("empty data")
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return []byte{}, errors.New(fmt.Sprintf("decode error:%v", err))
	}
	key := []byte(DesKey)
	sourceData, err := DesDecrypt(decoded, key)
	if err != nil || len(sourceData) < 1 {
		return []byte{}, errors.New("decrypt fail")
	}
	arr := strings.Split(string(sourceData), ":")
	if len(arr) > 1 && time.Now().Unix()-to.Int64(arr[1]) < DesExp {
		return sourceData, nil
	}
	return []byte{}, errors.New("decrypt fail:time out")
}

func EncodeWithBase64() ([]byte, error) {
	data := []byte(fmt.Sprintf("starsource is best:%s", to.String(time.Now().Unix())))
	cryptData, err := DesEncrypt(data, []byte(DesKey))
	encoded := base64.StdEncoding.EncodeToString(cryptData)
	return []byte(encoded), err
}

var iv = []byte("12345678")

// des的CBC加密
// 编写填充函数, 如果最后一个分组字节数不够, 填充
// ......字节数刚好合适, 添加一个新的分组
// 填充个的字节的值 == 缺少的字节的数
func paddingLastGroup(plainText []byte, bloclSize int) []byte {
	// 1. 求出最后一个组中剩余的字节数 28 % 8 = 3...4  32 % 8 = 4 ...0
	padNum := bloclSize - len(plainText)%bloclSize
	// 2. 创建新的切片, 长度 == padNum, 每个字节值 byte(padNum)
	char := []byte{byte(padNum)} // 长度1,
	// 切片创建, 并初始化
	newPlain := bytes.Repeat(char, padNum)
	// 3. newPlain数组追加到原始明文的后边
	newText := append(plainText, newPlain...)
	return newText
}

// 去掉填充的数据
func unPaddingLastGrooup(plainText []byte) []byte {
	// 1. 拿去切片中的最后一个字节
	length := len(plainText)
	lastChar := plainText[length-1] //
	number := int(lastChar)         // 尾部填充的字节个数
	return plainText[:length-number]
}

// des加密
func DesEncrypt(plainText, key []byte) ([]byte, error) {
	// 1. 建一个底层使用des的密码接口
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// 2. 明文填充
	newText := paddingLastGroup(plainText, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, iv)
	// 4. 加密
	cipherText := make([]byte, len(newText))
	blockMode.CryptBlocks(cipherText, newText)
	// blockMode.CryptBlocks(newText, newText)
	return cipherText, nil
}

// des解密
func DesDecrypt(cipherText, key []byte) ([]byte, error) {
	// 1. 建一个底层使用des的密码接口
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// 2. 创建一个使用cbc模式解密的接口
	blockMode := cipher.NewCBCDecrypter(block, iv)
	// 3. 解密
	blockMode.CryptBlocks(cipherText, cipherText)
	// 4. cipherText现在存储的是明文, 需要删除加密时候填充的尾部数据
	plainText := unPaddingLastGrooup(cipherText)
	return plainText, nil
}
