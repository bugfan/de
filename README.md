# 简介 de (data encryption)
- 通用消息传递加密库，使用des对称加/解密，可用于http消息加密传递，tcp字节流加密，在两端设置相同的密钥，保证两端信息传递安全

### 组成
- [x] des
- [x] 加/解密API
- [x] 自定义加/解密有效时间
- [x] 自定义加/解密Key

### 使用
#### 方式一
```
import (
	"github.com/bugfan/de"
)
...
var cryptor = de.New("abcd1234") //实例化
data,err := cryptor.EncodeHex(xxxx)
...
plainText,err := cryptor.DecodeHex(data)

```
#### 方式二 
```
import (
	"github.com/bugfan/de"
)
...
de.SetKey("vb123456")
data,err := de.EncodeWithBase64(xxxx)
...
data,err := de.NativeEncodeWithHex(xxxx)
```
#### 其他
```
其他配置/使用直接查看 encrypt.go 和 conf.go 代码使用

......

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
.....

```
