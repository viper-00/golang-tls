# Golang-TLS

## 生成私钥(.key)

```
# 方式一：使用算法 “RSA” 需要考虑的因素 >= 2048-bit
openssl genrsa -out server.key 2048

# 方式二：使用算法 “ECDSA” 需要考虑的因素 (X25519 || ≥ secp384r1)
# https://safecurves.cr.yp.to/
# 查看 ECDSA（Elliptic Curve Digital Signature Algorithm） 算法支持的曲线 （openssl ecparam -list_curves）
openssl ecparam -genkey -name secp384r1 -out server.key
```

基于私钥（`.key`）生成自签名（x509）公钥（PEM-encodings `.pem|.crt`）

```
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
```

## 用Golang实现简单的 HTTPS/TLS 服务

```go
package main

import (
    "net/http"
    "log"
)

func HelloServer(w http.ResponseWriter, req *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte("This is an example server.\n"))
}

func main() {
    http.HandleFunc("/hello", HelloServer)
    err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
    if err != nil {
        log.Fatal("ListenAndServeTLS: ", err)
    }
}
```

注意：使用 `https` 以及端口的地址访问，浏览器访问会下载文件。

```
$ curl -sL https://localhost:443 | xxd
0000000: 1503 0100 0202 0a                .......
```

## TLS（transport layer security）传输层安全 - Server

```go
package main

import (
    "log"
    "crypto/tls"
    "net"
    "bufio"
)

func main() {
    log.SetFlags(log.Lshortfile)

    cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Println(err)
        return
    }

    config := &tls.Config{Certificates: []tls.Certificate{cer}}
    ln, err := tls.Listen("tcp", 443, config)
    if err != nil {
        log.Println(err)
        return
    }

    defer ln.Close()

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()
    r := bufio.NewReader(conn)
    for {
        msg, err := r.ReadString("\n")
        if err != nil {
            log.Println(err)
            return
        }

        println(msg)

        n, err := conn.Write([]byte("world\n"))
        if err != nil {
            log.Println(n, err)
            return
        }
    }
}
```

## TLS（transport layer security）传输层安全 - Client

```go
package main

import (
    "log"
    "crypto/tls"
)

func main() {
    log.SetFlags(log.Lshortfile)

    conf := &tls.Config{
        //InsecureSkipVerify: true,
    }

    conn, err := tls.Dial("tcp", "127.0.0.1:443", conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()

    n, err := conn.Write([]byte("hello"))
    if err != nil {
        log.Println(n, err)
        return
    }

    buf := make([]byte, 100)
    n, err = conn.Read(buf)
    if err != nil {
        log.Println(n, err)
        return
    }

    println(string(buf[:n]))
}
```

## Golang 实现完整的 SSL 配置流程

```go
package main

import (
    "crypto/tls"
    "log"
    "net/http"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
        w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        w.Write([]byte("This is an example server.\n"))
    })
    cfg := &tls.Config{
        MinVersion:               tls.VersionTLS12,
        CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
        },
    }
    srv := &http.Server{
        Addr:         ":443",
        Handler:      mux,
        TLSConfig:    cfg,
        TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
    }
    log.Fatal(srv.ListenAndServeTLS("tls.crt", "tls.key"))
}
```

一行命令生成自签名证书，私钥（`.key`）文件和公钥（PEM-encodings `.pem|.crt`）文件：

```
# ECDSA recommendation key ≥ secp384r1
openssl req -x509 -nodes -newkey ec:secp384r1 -keyout server.ecdsa.key -out server.ecdsa.crt -days 3650
# openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) -keyout server.ecdsa.key -out server.ecdsa.crt -days 3650
# -pkeyopt ec_paramgen_curve:… / ec:<(openssl ecparam -name …) / -newkey ec:…
ln -sf server.ecdsa.key server.key
ln -sf server.ecdsa.crt server.crt

# RSA recommendation key ≥ 2048-bit
openssl req -x509 -nodes -newkey rsa:2048 -keyout server.rsa.key -out server.rsa.crt -days 3650
ln -sf server.rsa.key server.key
ln -sf server.rsa.crt server.crt
```

- `.crt` — Alternate synonymous most common among *nix systems .pem (pubkey).
- `.csr` — Certficate Signing Requests (synonymous most common among *nix systems).
- `.cer` — Microsoft alternate form of .crt, you can use MS to convert .crt to .cer (DER encoded .cer, or base64[PEM] encoded .cer).
- `.pem` = The PEM extension is used for different types of X.509v3 files which contain ASCII (Base64) armored data prefixed with a «—– BEGIN …» line. These files may also bear the cer or the crt extension.
- `.der` — The DER extension is used for binary DER encoded certificates.

### 生成单个证书请求

```
openssl req -new -sha256 -key server.key -out server.csr
openssl x509 -req -sha256 -in server.csr -signkey server.key -out server.crt -days 3650
```

## ECDSA & RSA — FAQ

- 验证 elliptic 曲线参数 `-check`
- 查看所有支持 "ECDSA" 的椭圆曲线 `-list_curves`
- 编码成 explicit "ECDSA" `-param_enc explicit`
- 转换并压缩 "ECDSA" `-conv_form compressed`
- "EC" 参数和私钥 `-genkey`

## CA Bundle Path

| 发行平台 | 包 | CA路径 |
| --- | --- | --- |
| Fedora, RHEL, CentOS | ca-certificates | /etc/pki/tls/certs/ca-bundle.crt |
| Debian, Ubuntu, Gentoo, Arch Linux | ca-certificates | /etc/ssl/certs/ca-certificates.crt |
| SUSE, openSUSE | ca-certificates | /etc/ssl/ca-bundle.pem |
| FreeBSD | ca_root_nss | /usr/local/share/certs/ca-root-nss.crt |
| Cygwin | | /usr/ssl/certs/ca-bundle.crt |
| macOS (MacPorts) | curl-ca-bundle | /opt/local/share/curl/curl-ca-bundle.crt |
| Default cURL CA bunde path (without --with-ca-bundle option) | /usr/local/share/curl/curl-ca-bundle.crt |
| Really old RedHat? | /usr/share/ssl/certs/ca-bundle.crt |

## 其他

翻译来自：[golang-tls](https://github.com/denji/golang-tls)

MIT
