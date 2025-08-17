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

[最新版本下载](https://github.com/threatexpert/gonc/releases/latest)

---

## 使用示例

### 基本用法
- 可像 `nc` 一样使用：
    ```bash
    gonc www.baidu.com 80
    gonc -tls www.baidu.com 443
    gonc -l 4444  #监听模式
    ```

### P2P 传输文件的例子
- 发送文件的一端，执行下面命令启动 HTTP 文件服务器，最后一个参数c:/RootDir就是要发送的文件所在目录：
    ```bash
    gonc -p2p <口令> -httpserver c:/RootDir
    ```
- 另一端下载文件的2种方式：
    
    1、执行下面命令后，会自动下载完整目录，支持递归下载所有文件到本地，中断重新执行会自动断点续传：
    ```bash
    gonc -p2p <口令> -download c:/SavePath
    ```

    2、这种不会自动开始下载，需手动打开浏览器访问 http://127.0.0.1:9999 浏览对端的文件列表和针对性下载文件
    ```bash
    gonc -p2p <口令> -httplocal-port 9999
    ```


### 玩转 P2P 通信
- 双方约定一个相同的口令，然后双方都执行下面命令：
    ```bash
    gonc -p2p <口令>
    ```

    双方就能基于口令发现彼此的网络地址，内网穿透 NAT ，双向认证和加密通讯。双方都用口令派生证书，基于 TLS 1.3 保证安全通信。（口令相当于证书私钥，建议使用 `gonc -psk .` 随机生成高强度的口令）

    注意这条命令在两端的运行时差不能太久（30秒以内），否则错过NAT打洞时机会失败退出。因此还支持基于MQTT消息订阅的等待机制，使用-mqtt-wait和-mqtt-hello来同步双方开始P2P的时机。例如，下面用了-mqtt-wait可以持续等待，

    ```bash
    gonc -p2p <口令> -mqtt-wait
    ```
    另一端使用：
    ```bash
    gonc -p2p <口令> -mqtt-hello
    ```

    以上这样建立的裸连接，也只是可以互相打字发消息哦。如果你是懂nc的，现在要p2p传输数据的话，例如发送文件的命令应该类似是这样：

    ```bash
    cat 文件路径 | gonc -p2p 口令 -mqtt-wait    #linux风格
    
    或

    gonc -p2p 口令 -mqtt-wait -send 文件路径    #用-send参数，兼容linux和windows
    ```

    另一端使用：

    ```bash
    gonc -p2p 口令 > 保存文件名
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
- 使用 P2P 方式反弹 Shell（`<口令>` 用于身份认证，基于 TLS 1.3 实现安全通信）：
    ```bash
    gonc -exec ":sh /bin/bash" -p2p <口令>
    ```
    另一端：
    ```bash
    gonc -pty -p2p <口令>
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
    gonc -p2p <口令> -socks5server
    ```
- 另一端将本机监听端口127.0.0.1:3080提供socks5服务：
    ```bash
    gonc -p2p <口令> -socks5local-port 3080
    ```

    这时如果你的客户端不支持设置socks5代理，例如远程桌面（mstsc），你想连接远程网络的10.0.0.1:3389，你可以直接在远程桌面客户端填要连接的地址为：
    
    ```
    10.0.0.1-3389.gonc.cc:3080
    ```

    该域名会被解析为类似127.b.c.d的IP，因此远程桌面客户端会连入本地的socks5代理端口3080，然后gonc根据连接一端的127.b.c.d地址去反解析出域名中的10.0.0.1-3389这个信息。


### 灵活服务配置
- -exec可灵活的设置为每个连接提供服务的应用程序，除了指定/bin/bash这种提供shell命令的方式，也可以用来端口转发流量，不过下面这种每个连接进来就会开启一个新的gonc进程：
    ```bash
    gonc -keep-open -exec "gonc -tls www.baidu.com 443" -l 8000
    ```
- 避免大量子进程，使用内置命令方式调用nc模块：
    ```bash
    gonc -keep-open -exec ":nc -tls www.baidu.com 443" -l 8000
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

     另一端使用:nc把socks5 over tls转为标准socks5，在本地127.0.0.1:3080提供本地客户端接入

    `gonc.exe -e ":nc -tls -psk randomString x.x.x.x 1080" -keep-open -l -local 127.0.0.1:3080`

### 多服务监听模式
- 参考SSH的22端口，既可提供shell也提供sftp和端口转发功能，gonc使用 -e ":service" 也可监听在一个服务端口，基于tls+psk安全认证提供shell、socks5(支持CONNECNT+BIND)和文件服务。（请务必使用gonc -psk .生成高熵PSK替换randomString）

    `gonc -k -l -local :2222 -tls -psk randomString -e ":service" -:sh "/bin/bash" -:s5s "-c -b" -:mux "httpserver /"`

    另一端使用获得shell

    `gonc -tls -psk randomString -remote <server-ip>:2222 -call :sh -pty`

    另一端把socks5 over tls转为本地标准socks5端口1080

    `gonc -e ":nc -tls -psk randomString -call :s5s <server-ip> 2222" -k -P -l -local 127.0.0.1:1080`

    另一端把文件服务为本地标准HTTP端口8000

    `gonc -tls -psk randomString -remote <server-ip>:2222 -call :mux -httplocal-port 8000`


### 给其他应用建立通道
- 帮WireGuard打洞组VPN

    在被动等待连接的PC-S运行下面的参数（直接拿节点公钥来当口令，接口的监听端口51820）：

    `gonc -p2p PS-S的公钥 -mqtt-wait -u -k -e ":nc -u 127.0.0.1 51820"`

    其他发起主动连接的PC-C，设置WireGuard节点PS-S公钥的Endpoint = 127.0.0.1:51821，接口的监听端口51820，gonc运行下面的参数，-k可以让gonc在网络异常后自动重新建立连接。

    `gonc -p2p PS-S的公钥 -mqtt-hello -u -k -e ":nc -u -local 127.0.0.1:51821 127.0.0.1 51820"`


## P2P NAT 穿透能力

### gonc如何建立P2P？

 - 并发使用多个公用 STUN 服务，探测本地的 TCP / UDP NAT 映射，并智能识别 NAT 类型
 - 通过基于口令(SessionKey)派生的哈希作为 MQTT 共享话题，借助公用 MQTT 服务安全交换地址信息
 - 按优先级顺序尝试直连：IPv6 TCP > IPv4 TCP > IPv4 UDP，尽可能实现真正的点对点通信
 - 没有设立中转服务器，不提供备用转发模式：要么连接失败，要么成功就是真的P2P

### 如何部署中转服务器适应实在无法P2P的条件？

 - 一个公网IP上支持UDP ASSOCIATE的Socks5服务器就可以，也可以用自己的VPS，运行gonc本身的socks5代理服务器便可让其成为中转服务器。

    下面命令启动了仅支持UDP转发功能的socks5代理，-psk和-tls开启了加密和PSK口令认证。注意防火墙不能只开放1080，因为每次提供转发的UDP端口是随机。

    `gonc -e ":s5s -u -c=0" -psk 口令 -tls -k -l 1080`

 - P2P遇到困难的时候，只需要有一端的gonc使用-x参数再进行P2P就可以。你也可以把-x换为-x2，这样就是先P2P，失败了再尝试用中转

    `gonc -p2p randomString -x "-psk 口令 -tls <socks5server-ip>:1080"`

 - 下面例子是使用标准的socks5代理服务器（需服务器支持UDP）。

    `gonc -p2p randomString -x "<socks5server-ip>:1080" -auth "user:password"`


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
 - 使用多个STUN服务器(涵盖国内外和TCP/UDP协议)检测NAT地址并研判NAT类型，以及发现多IP出口的网络环境
 - 双方都有ipv6地址时优先使用ipv6地址建立直连
 - 有一端是容易型的才建立TCP P2P，因为与STUN服务器的TCP一旦断开容易影响这个洞，而确定是容易型后可以直接约定新的端口号，并避开使用与STUN服务器连接的源端口
 - TCP两端都处于监听状态，复用端口，并相互dial对方建立直连
 - 相对容易的一端延迟UDP发包，避免触发困难端的洞（端口号）变更
 - 相对困难的一端使用小TTL值UDP包，降低触发对端的洞的防火墙策略
 - 使用生日悖论，当简单策略无法打通时，相对困难的一端使用600个随机源端口，与另一端使用600个随机目的端口进行碰撞。
