# 简介 de (data encryption)
- 通用消息传递加密库，使用des对称加/解密，可用于http消息加密传递，tcp字节流加密，在两端设置相同的密钥，保证两端信息传递安全

### 组成
- [x] des
- [x] 加/解密API
- [x] 自定义加/解密有效时间
- [x] 自定义加/解密Key

### 使用
```
go get github.com/bugfan/de

func init(){
    de.SetKey("ttttqwer")   //设置八位密钥
    de.SetExp(30)           //设置加密后token有效时间 单位(秒)
}

/*
    A发送数据到B，B通过de解密成功才处理
*/

// 方式一 (使用默认加密函数)
// A 
func main(){
    token, _ := de.EncodeWithBase64()	// this 'de.EncodeWithBase64()' api will use expire time  which you excute 'de.SetExp(30)' before
    // token, _ := de.Encode([]byte(`some private data`))
    ...
    ...
    req, _ := http.NewRequest("POST", https://xxx.com/aaa, yourbody)
	req.Header.Add("MyToken", string(token))
	resp,err:=http.DefaultClient.Do(req)
	...
    ...
}

// B
func main(){

    auth := func(w http.ResponseWriter, r *http.Request) {
	    token := r.Header.Get("MyToken")
	     _, err := de.DecodeWithBase64([]byte(token))
	     // _, err := de.Decode([]byte(token))
	    if err != nil {
            log.Error("can not handle this request...")
            w.WriteHeader(403)
            return
        }
    }

    ....
    ....
    http.ListenAndServe(....)
}

// 方式二 (新建加密对象进行加解密)
// A 
func main(){
    // new cryptor
    cryptor := de.New("qwer1234")
    token, _ := cryptor.Encode([]byte(`some private data`))
    // token, _ := cryptor.EncodeHex([]byte(`some private data`))   // token is hex string
    ...
    ...
    req, _ := http.NewRequest("POST", https://xxx.com/aaa, yourbody)
	req.Header.Add("MyToken", string(token))
	resp,err:=http.DefaultClient.Do(req)
	...
    ...
}


// B
func main(){
    // new same cryptor
    cryptor := de.New("qwer1234")

    auth := func(w http.ResponseWriter, r *http.Request) {
	    token := r.Header.Get("MyToken")
	     _, err := cryptor.Decode([]byte(token))
	     // _, err := cryptor.DecodeHex([]byte(token))  // if token is hex string,use 'DecodeHex' func
	    if err != nil {
            log.Error("can not handle this request...")
            w.WriteHeader(403)
            return
        }
    }

    ....
    ....
    http.ListenAndServe(....)
}
```
