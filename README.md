## go-netcat 简介

golang版 netcat, 更方便的建立点对点通信。

有以下特点：

 - 🔁 自动化内网穿透：使用 -p2p 自动实现 TCP/UDP 的 NAT 打洞与点对点连接，无需手动配置，依赖公共 STUN 和 MQTT 服务交换地址信息。

 - 🚀 UDP 稳定传输通道：集成 KCP 协议，TCP无法穿透NAT的情况，用基于UDP的KCP也能保持通信的可靠性。

 - 🔒 加密支持：支持 TCP 的 TLS 和 UDP 的 DTLS 加密传输。

 - 🧩 可嵌入服务程序：通过 -exec 将工具作为子服务启动，结合多路复用能力，支持流量转发、Socks5代理和http文件服务等场景。

 - 🖥️ 伪终端支持：配合 -exec 和 -pty，为类似 /bin/sh 的交互式程序提供伪终端环境，增强 shell 控制体验（支持 TAB、Ctrl+C 等）。

 - 💻 原始输入模式：-pty 启用控制台 raw 模式，在获取 shell 时提供更贴近原生终端的操作体验。

 - 📈 实时速度统计：提供发送与接收方向的实时速度统计，便于测试传输性能。


## 例子

- 这个工具可以像nc那样用，例如

    `gonc.exe www.baidu.com 80`

    `gonc.exe -tls www.baidu.com 443`


- 用TCP直接在两个内网P2P通信，要自己约定一个唯一ID，例如 randomString ，每次用都随机换ID避免和别人一样。

    `gonc.exe -p2p randomString`

    另一端用也完全一样的的参数，程序会自己尝试TCP或UDP建立通信，自己协商角色（tls client/server）并完成TLS协议

    `gonc.exe -p2p randomString`


- 支持使用socks5代理

    `gonc.exe -s5 s.s.s.s:port x.x.x.x 1234`

- 反弹shell，类UNIX支持pseudo-terminal shell 

    监听

    `gonc -tls -pty -exec /bin/bash -l 1234`

    连接获得shell(windows和linux都支持console raw模式，该模式下支持TAB、ctrl+c等输入)

    gonc.exe -tls -pty x.x.x.x 1234

    还可以P2P的方式反弹shell：

    `gonc -tls -pty -exec /bin/bash -p2p-tcp randomString`

    另一端这样可以得到shell

    `gonc -tls -pty -p2p-tcp randomString`


- 还可以像socat那样建立左右两个通道转发数据

    `gonc.exe -keep-open -exec "./gonc -tls www.baidu.com 443" -l 8000`
    
    另一端用

    `gonc.exe 127.0.0.1 8000 > NUL`

- 发送和统计传输速度，内置/dev/zero和/dev/urandom实现，这样windows下也可以用/dev/zero和/dev/urandom

    `gonc.exe -sendfile /dev/zero -progress x.x.x.x 1234`

    `IN: 76.8 MiB (80543744 bytes), 3.3 MiB/s | OUT: 0.0 B (0 bytes), 0.0 B/s | 00:00:23`

    另一端用

    `gonc.exe -l 1234 > NUL`

- 建立P2P隧道并提供端口转发、socks5代理或http文件服务器
    
    端口转发

    `gonc.exe -p2p randomString -exec "-app-mux 127.0.0.1 3389"`

    或

    `gonc.exe -p2p randomString -exec "-app-mux socks5"`

    或

    `gonc.exe -p2p randomString -exec "-app-mux httpserver c:/RootDir"`


    另一端(本机监听端口)，例如对端使用了httpserver参数，那么访问本机9999端口可实现浏览对端的文件列表

    `gonc.exe -p2p randomString -exec "-app-mux -l 9999"`
