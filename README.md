## go-netcat 简介

README in [English](./README_en.md) 、 [中文](./README.md)

`go-netcat` 是一个基于 Golang 的 `netcat` 工具，旨在更方便地建立点对点通信。其主要特点包括：

- 🔁 **自动化内网穿透**：使用 `-p2p` 自动实现 TCP/UDP 的 NAT 打洞与点对点连接，无需手动配置，依赖公共 STUN 和 MQTT 服务交换地址信息。
- 🚀 **UDP 稳定传输通道**：集成 KCP 协议，在 TCP 无法穿透 NAT 的情况下，基于 UDP 的 KCP 也能保持通信的可靠性。
- 🔒 **端到端双向认证的加密**：支持 TCP 的 TLS 和 UDP 的 DTLS 加密传输，可基于口令双向身份认证。
- 🧩 **可嵌入服务程序**：通过 `-exec` 将工具作为子服务启动，结合多路复用能力，支持流量转发、Socks5 代理和 HTTP 文件服务等场景。
- 🖥️ **伪终端支持**：配合 `-exec` 和 `-pty`，为类似 `/bin/sh` 的交互式程序提供伪终端环境，增强 shell 控制体验（支持 TAB、Ctrl+C 等）。
- 💻 **原始输入模式**：`-pty` 启用控制台 `raw` 模式，在获取 shell 时提供更贴近原生终端的操作体验。
- 📈 **实时速度统计**：提供发送与接收方向的实时速度统计，便于测试传输性能。

---

## 使用示例

### 基本用法
- 像 `nc` 一样使用：
    ```bash
    gonc www.baidu.com 80
    gonc -tls www.baidu.com 443
    ```

### 高安全性加密 P2P 通信
- 在两个不同内网中实现高安全性加密 P2P 通信，需约定一个口令（建议使用 `gonc -psk .` 生成高熵口令替换randomString）。该口令用于两端互相发现并派生证书，通信基于 TLS 1.3 保证安全性。
    ```bash
    gonc -p2p randomString
    ```
    另一端使用相同参数（程序会自己尝试TCP或UDP建立通信（TCP优先），自己会协商角色（tls client/server）并完成TLS协议）：
    ```bash
    gonc -p2p randomString
    ```

### 反弹 Shell（类UNIX支持pseudo-terminal shell ）
- 监听端（不使用 `-keep-open`，仅接受一次连接；未使用 `-psk`，无身份认证）：
    ```bash
    gonc -tls -pty -exec /bin/bash -l 1234
    ```
- 另一端连接获取 Shell（支持 TAB、Ctrl+C 等操作）：
    ```bash
    gonc -tls -pty x.x.x.x 1234
    ```
- 使用 P2P 方式反弹 Shell（`randomString` 用于身份认证，基于 TLS 1.3 实现安全通信）：
    ```bash
    gonc -pty -exec /bin/bash -p2p randomString
    ```
    另一端：
    ```bash
    gonc -pty -p2p randomString
    ```

### 传输速度测试
- 发送数据并统计传输速度（内置 `/dev/zero` 和 `/dev/urandom`）：
    ```bash
    gonc.exe -send /dev/zero -P x.x.x.x 1234
    ```
    输出示例：
    ```
    IN: 76.8 MiB (80543744 bytes), 3.3 MiB/s | OUT: 0.0 B (0 bytes), 0.0 B/s | 00:00:23
    ```
    另一端接收：
    ```bash
    gonc -P -l 1234 > NUL
    ```

### P2P 隧道与 Socks5 代理
- 等待建立隧道：
    ```bash
    gonc -p2p randomString -socks5server
    ```
- 另一端将本机监听端口127.0.0.1:3080提供socks5服务：
    ```bash
    gonc -p2p randomString -socks5local-port 3080
    ```

### P2P 隧道与 HTTP 文件服务器
- 启动 HTTP 文件服务器：
    ```bash
    gonc -p2p randomString -httpserver c:/RootDir
    ```
- 另一端访问文件列表（需手动打开浏览器访问 http://127.0.0.1:9999 可实现浏览对端的文件列表和下载文件）：
    ```bash
    gonc -p2p randomString -httplocal-port 9999
    ```
    支持递归下载所有文件到本地并断点续传：
    ```bash
    gonc -p2p randomString -download c:/SavePath
    ```

### 灵活服务配置
- -exec可灵活的设置为每个连接提供服务的应用程序(-exec参数值中的第一个.代表gonc自身路径)，除了指定/bin/bash这种提供shell命令的方式，也可以用来端口转发流量，不过下面这种每个连接进来就会开启一个新的gonc进程：
    ```bash
    gonc -keep-open -exec ". -tls www.baidu.com 443" -l 8000
    ```
- 避免大量子进程，使用内置流量转发模块：
    ```bash
    gonc -keep-open -exec ":pf -tls www.baidu.com 443" -l 8000
    ```

### Socks5 代理服务
- 配置客户端模式：
    ```bash
    gonc -x s.s.s.s:port x.x.x.x 1234
    ```
- 内置 Socks5 服务端，使用-e :s5s提供socks5标准服务，支持-auth设置一个socks5的账号密码，用-keep-open可提供持续接受客户端连入socks5服务器，受益于golang的协程，可以获得不错的多客户端并发性能：
    ```bash
    gonc -e ":s5s -auth user:passwd" -keep-open -l 1080
    ```
- 使用高安全性 Socks5 over TLS，由于标准socks5是不加密的，我们可使用[`-e :s5s`](#)，结合[`-tls`](#)和[`-psk`](#)定制高安全性的socks5 over tls通讯，使用[`-P`](#)统计连接传输信息，还可以使用[`-acl`](#)对接入和代理目的地实现访问控制。acl.txt文件格式详见[acl-example.txt](./acl-example.txt)。

    `gonc.exe -tls -psk randomString -e :s5s -keep-open -acl acl.txt -P -l 1080`

     另一端使用:pf（内置的端口转发命令）把socks5 over tls转为标准socks5，在本地127.0.0.1:3080提供本地客户端接入

    `gonc.exe -e ":pf -tls -psk randomString x.x.x.x 1080" -keep-open -l -local 127.0.0.1:3080`
