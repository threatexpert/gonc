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
    gonc -tls -exec ":sh /bin/bash" -l 1234
    ```
- 另一端连接获取 Shell（支持 TAB、Ctrl+C 等操作）：
    ```bash
    gonc -tls -pty x.x.x.x 1234
    ```
- 使用 P2P 方式反弹 Shell（`randomString` 用于身份认证，基于 TLS 1.3 实现安全通信）：
    ```bash
    gonc -exec ":sh /bin/bash" -p2p randomString
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

### 多服务监听模式
- 参考SSH的22端口，既可提供shell也提供sftp和端口转发功能，gonc使用 -e ":service" 也可监听在一个服务端口，基于tls+psk安全认证提供shell、socks5(支持CONNECNT+BIND)和文件服务。（请务必使用gonc -psk .生成高熵PSK替换randomString）

    `gonc -k -l -local :2222 -tls -psk randomString -e ":service" -:sh "/bin/bash" -:s5s "-c -b" -:mux "httpserver /"`

    另一端使用获得shell

    `gonc -tls -psk randomString -remote <server-ip>:2222 -call :sh -pty`

    另一端把socks5 over tls转为本地标准socks5端口1080

    `gonc -e ":pf -tls -psk randomString -call :s5s <server-ip>:2222" -k -P -l -local 127.0.0.1:1080`

    另一端把文件服务为本地标准HTTP端口8000

    `gonc -tls -psk randomString -remote <server-ip>:2222 -call :mux -httplocal-port 8000`


### 给其他应用建立通道
- 帮WireGuard打洞组VPN

    两端的WireGuard节点都配置Endpoint = 127.0.0.1:51821，并且在两端都运行下面同样的参数：

    `gonc -e ":pf -p2p randomString -kcp" -u -k -l 127.0.0.1 51821`

    如果有一端需要走socks5代理，代理的参数要在:pf里的-x

    `gonc -e ":pf -x \"-psk randomString -tls <socks5server-ip>:1080\" -p2p randomString -kcp" -u -k -l 127.0.0.1 51821`


## P2P NAT 穿透能力

### gonc如何建立P2P？

 - 并发使用多个公用 STUN 服务，探测本地的 TCP / UDP NAT 映射，并智能识别 NAT 类型
 - 通过基于 SessionKey 派生的哈希作为 MQTT 共享话题，借助公用 MQTT 服务安全交换地址信息
 - 按优先级顺序尝试直连：IPv6 TCP > IPv4 TCP > IPv4 UDP，尽可能实现真正的点对点通信
 - 没有设立中转服务器，不提供备用转发模式：要么连接失败，要么成功就是真的P2P

### 如何部署中转服务器适应实在无法P2P的条件？

 - 需要自己有一个公网IP的服务器，运行gonc本身的socks5代理服务器便可让其成为中转服务器。

    下面命令启动了支持UDP转发功能的socks5代理，-psk和-tls开启了加密和认证

    `gonc -e ":s5s -u" -psk randomString -tls -k -l 1080`

 - P2P遇到困难的时候，只需要有一端的gonc使用-x参数再进行P2P就可以。

    `gonc -p2p randomString -x "-psk randomString -tls <socks5server-ip>:1080"`

例如原本两端都是对称型NAT，无法P2P，现在一端使用了socks5代理（UDP模式），就相当于转为容易型的NAT了，于是就能很容易和其他建立连接，数据加密仍然是端到端的。


### 内置的公用服务器（STUN和MQTT）：

		"tcp://turn.cloudflare.com:80",
		"udp://turn.cloudflare.com:53",
		"udp://stun.l.google.com:19302",
		"udp://stun.miwifi.com:3478",
		"global.turn.twilio.com:3478",
		"stun.nextcloud.com:443",

 		"tcp://broker.hivemq.com:1883",
		"tcp://broker.emqx.io:1883",
		"tcp://test.mosquitto.org:1883",


### gonc的NAT穿透成功率如何？

#### 除了两端都是对称类型的情况，其他都有非常高的成功率

gonc将NAT类型分为3种：

当固定一个内网端口去访问多个STUN服务器，根据多个STUN服务器反馈的地址研判：

 1. 容易型：NAT端口与内网端口都是保持不变的
 2. 困难型：NAT端口都变为另一个共同的端口号，相对1困难。
 3. 对称型：NAT端口每个都不一样，算是最困难的类型

针对这些类型，gonc采用了如下一些NAT穿透策略：
 - 使用多个STUN服务器检测NAT地址并研判NAT类型，以及发现多IP出口的网络环境
 - 双方都有ipv6地址时优先使用ipv6地址建立直连
 - 有一端是容易型的才建立TCP P2P，因为与STUN服务器的TCP一旦断开容易影响这个洞，而确定是容易型后可以直接约定新的端口号，并避开使用与STUN服务器连接的源端口
 - TCP两端都处于监听状态，复用端口，并相互dial对方建立直连
 - 相对容易的一端延迟UDP发包，避免触发困难端的洞（端口号）变更
 - 相对困难的一端使用小TTL值UDP包，降低触发对端的洞的防火墙策略
 - 使用生日悖论，当简单策略无法打通时，相对困难的一端使用600个随机源端口，与另一端使用600个随机目的端口进行碰撞。
