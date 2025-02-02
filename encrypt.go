package de

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bugfan/to"
)

var Default = &cryptor{
	desKey:    "12345678", // 默认 12345678, des必须使用8个字节（3des需使用24字节）
	desExpire: 60,         // 默认60秒之内可以解开
}

type Cryptor interface {
	Decode([]byte) ([]byte, error)
	Encode([]byte) ([]byte, error)
	DecodeHex([]byte) ([]byte, error)
	EncodeHex([]byte) ([]byte, error)
	DecodeBase64([]byte) ([]byte, error)
	EncodeBase64([]byte) ([]byte, error)
	NativeDecodeHex([]byte) ([]byte, error)
	NativeEncodeHex([]byte) ([]byte, error)
	NativeDecodeBase64([]byte) ([]byte, error)
	NativeEncodeBase64([]byte) ([]byte, error)
}

func New(key string, args ...interface{}) Cryptor {
	var exp int64 = 60
	if len(args) > 0 && to.Int64(args[0]) > 0 {
		exp = to.Int64(args[0])
	}
	return &cryptor{
		desKey:    key,
		desExpire: exp,
	}
}

type cryptor struct {
	desKey    string
	desExpire int64
}

func (c cryptor) Key() string {
	return c.desKey
}

func (c cryptor) Exp() int64 {
	return c.desExpire
}

func (c cryptor) DecodeHex(data []byte) ([]byte, error) {
	src, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	return c.Decode([]byte(src))
}
func (c cryptor) Decode(data []byte) ([]byte, error) {
	key := []byte(c.desKey)
	data, err := DesDecrypt(data, key)
	return data, err
}
func (c cryptor) EncodeHex(data []byte) ([]byte, error) {
	cryptData, err := DesEncrypt(data, []byte(c.desKey))
	if err != nil {
		return cryptData, err
	}
	dst := hex.EncodeToString(cryptData)
	return []byte(dst), nil
}
func (c cryptor) Encode(data []byte) ([]byte, error) {
	cryptData, err := DesEncrypt(data, []byte(c.desKey))
	return cryptData, err
}
func (c cryptor) DecodeBase64(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return []byte{}, errors.New("empty data")
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return []byte{}, errors.New(fmt.Sprintf("decode error:%v", err))
	}
	key := []byte(c.desKey)
	sourceData, err := DesDecrypt(decoded, key)

	if err != nil || len(sourceData) < 1 {
		return []byte{}, errors.New("decrypt fail")
	}
	str := string(sourceData)
	idx := strings.LastIndex(str, ":")
	if time.Now().Unix()-to.Int64(str[idx+1:]) < c.desExpire {
		return sourceData[0:idx], nil
	}
	return []byte{}, errors.New("decrypt fail:time out")
}
func (c cryptor) EncodeBase64(bs []byte) ([]byte, error) {
	data := []byte(fmt.Sprintf("%s:%s", to.String(bs), to.String(time.Now().Unix())))
	cryptData, err := DesEncrypt(data, []byte(c.desKey))
	encoded := base64.StdEncoding.EncodeToString(cryptData)
	return []byte(encoded), err
}

func (c cryptor) NativeDecodeBase64(data []byte) ([]byte, error) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Printf("native decode:%v\n", e)
		}
	}()
	cipherData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	block, err := des.NewCipher([]byte(c.desKey))
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherData, cipherData)
	padLen := int(cipherData[len(cipherData)-1])
	return cipherData[:len(cipherData)-padLen], nil
}

func (c cryptor) NativeEncodeBase64(plainData []byte) ([]byte, error) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Printf("native encode:%v\n", e)
		}
	}()
	// 使用 PKCS5 填充
	blockSize := des.BlockSize
	padLen := blockSize - len(plainData)%blockSize
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	plainData = append(plainData, padText...)
	// 创建 DES 密码块
	block, err := des.NewCipher([]byte(c.desKey))
	if err != nil {
		return nil, err
	}
	// 创建 CBC 加密模式
	mode := cipher.NewCBCEncrypter(block, iv)
	encryptedData := make([]byte, len(plainData))
	mode.CryptBlocks(encryptedData, plainData)
	// 将加密后的数据进行 Base64 编码
	encryptedText := base64.StdEncoding.EncodeToString(encryptedData)
	return []byte(encryptedText), nil
}

func (c cryptor) NativeEncodeHex(plainData []byte) ([]byte, error) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Printf("native encode:%v\n", e)
		}
	}()
	// 使用 PKCS5 填充
	blockSize := des.BlockSize
	padLen := blockSize - len(plainData)%blockSize
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	plainData = append(plainData, padText...)
	// 创建 DES 密码块
	block, err := des.NewCipher([]byte(c.desKey))
	if err != nil {
		return nil, err
	}
	// 创建 CBC 加密模式
	mode := cipher.NewCBCEncrypter(block, iv)
	encryptedData := make([]byte, len(plainData))
	mode.CryptBlocks(encryptedData, plainData)
	// 将加密后的数据进行 Hex 编码
	dst := hex.EncodeToString(encryptedData)
	return []byte(dst), nil
}

func (c cryptor) NativeDecodeHex(data []byte) ([]byte, error) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Printf("native decode:%v\n", e)
		}
	}()
	cipherData, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	block, err := des.NewCipher([]byte(c.desKey))
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherData, cipherData)
	padLen := int(cipherData[len(cipherData)-1])
	return cipherData[:len(cipherData)-padLen], nil
}

// default usage
func Decode(data []byte) ([]byte, error) {
	key := []byte(Default.desKey)
	data, err := DesDecrypt(data, key)
	return data, err
}

func Encode(data []byte) ([]byte, error) {
	cryptData, err := DesEncrypt(data, []byte(Default.desKey))
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
	key := []byte(Default.desKey)
	sourceData, err := DesDecrypt(decoded, key)
	if err != nil || len(sourceData) < 1 {
		return []byte{}, errors.New("decrypt fail")
	}
	arr := strings.Split(string(sourceData), ":")
	if len(arr) > 1 && time.Now().Unix()-to.Int64(arr[1]) < Default.desExpire {
		return sourceData, nil
	}
	return []byte{}, errors.New("decrypt fail:time out")
}

func EncodeWithBase64() ([]byte, error) {
	data := []byte(fmt.Sprintf("starsource is best:%s", to.String(time.Now().Unix())))
	cryptData, err := DesEncrypt(data, []byte(Default.desKey))
	encoded := base64.StdEncoding.EncodeToString(cryptData)
	return []byte(encoded), err
}

func NativeDecodeWithBase64(data []byte) ([]byte, error) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Printf("native decode:%v\n", e)
		}
	}()
	cipherData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	block, err := des.NewCipher([]byte(Default.desKey))
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherData, cipherData)
	padLen := int(cipherData[len(cipherData)-1])
	return cipherData[:len(cipherData)-padLen], nil
}

func NativeDecodeWithHex(data []byte) ([]byte, error) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Printf("native decode:%v\n", e)
		}
	}()
	cipherData, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	block, err := des.NewCipher([]byte(Default.desKey))
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherData, cipherData)
	padLen := int(cipherData[len(cipherData)-1])
	return cipherData[:len(cipherData)-padLen], nil
}

func NativeEncodeWithBase64(plainData []byte) ([]byte, error) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Printf("native encode:%v\n", e)
		}
	}()
	// 使用 PKCS5 填充
	blockSize := des.BlockSize
	padLen := blockSize - len(plainData)%blockSize
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	plainData = append(plainData, padText...)
	// 创建 DES 密码块
	block, err := des.NewCipher([]byte(Default.desKey))
	if err != nil {
		return nil, err
	}
	// 创建 CBC 加密模式
	mode := cipher.NewCBCEncrypter(block, iv)
	encryptedData := make([]byte, len(plainData))
	mode.CryptBlocks(encryptedData, plainData)
	// 将加密后的数据进行 Base64 编码
	encryptedText := base64.StdEncoding.EncodeToString(encryptedData)
	return []byte(encryptedText), nil
}

func NativeEncodeWithHex(plainData []byte) ([]byte, error) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Printf("native encode:%v\n", e)
		}
	}()
	// 使用 PKCS5 填充
	blockSize := des.BlockSize
	padLen := blockSize - len(plainData)%blockSize
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	plainData = append(plainData, padText...)
	// 创建 DES 密码块
	block, err := des.NewCipher([]byte(Default.desKey))
	if err != nil {
		return nil, err
	}
	// 创建 CBC 加密模式
	mode := cipher.NewCBCEncrypter(block, iv)
	encryptedData := make([]byte, len(plainData))
	mode.CryptBlocks(encryptedData, plainData)
	// 将加密后的数据进行 Hex 编码
	dst := hex.EncodeToString(encryptedData)
	return []byte(dst), nil
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
func unPaddingLastGrooup(plainText []byte) ([]byte, error) {
	// 1. 拿去切片中的最后一个字节
	length := len(plainText)
	lastChar := plainText[length-1] //
	number := int(lastChar)         // 尾部填充的字节个数
	cap := length - number
	if cap < 0 {
		return nil, errors.New("error plain text")
	}
	return plainText[:cap], nil
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
	ch := make(chan struct{}, 1)
	go func() {
		defer func() {
			ch <- struct{}{}
			recover()
		}()
		blockMode.CryptBlocks(cipherText, cipherText)
	}()
	_ = <-ch
	// 4. cipherText现在存储的是明文, 需要删除加密时候填充的尾部数据
	plainText, err := unPaddingLastGrooup(cipherText)
	return plainText, err
}
