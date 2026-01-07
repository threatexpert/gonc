# 欢迎使用 gonc

[![Go Report Card](https://goreportcard.com/badge/github.com/threatexpert/gonc)](https://goreportcard.com/report/github.com/threatexpert/gonc)
[![GitHub license](https://img.shields.io/github/license/threatexpert/gonc)](https://github.com/threatexpert/gonc/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/threatexpert/gonc)](https://github.com/threatexpert/gonc/stargazers)

**gonc** 是一个现代化的、功能增强版的网络瑞士军刀。它保留了经典 `netcat` 的简洁管道设计，并针对现代复杂的网络环境（NAT、防火墙）引入了 **P2P 穿透**、**多路复用**、**强加密** 以及 **内置服务模块**。

如果你习惯使用 `nc`，那么 `gonc` 将给你带来“鸟枪换炮”的体验。

---

## 核心特性

<div class="grid cards" markdown>

-   :material-lan-connect: **P2P NAT 穿透**
    ---
    无需公网 IP，双方仅需约定一个口令，通过内置的 STUN/MQTT 协议，轻松打通两台内网机器的直连隧道。

-   :material-flash: **多路复用 (Mux)**
    ---
    在 NAT 穿透成功后，仅建立一条底层 TCP/UDP 通道，并在其上通过 smux/yamux 多路复用，实现互相并发访问彼此的多项内网服务。

-   :material-server-network: **内置服务模块 (-e)**
    ---
    通过参数 -e 可灵活的设置为每个连接提供服务的应用程序，例如-e /bin/sh可提供远程cmdshell，还可以使用内置的虚拟命令便捷的使用socks5服务、http文件服务和流量转发功能。

-   :material-lock: **企业级安全**
    ---
    端到端双向认证的加密，支持 TCP 的 TLS1.3 和 UDP 的 DTLS 加密传输。

</div>

---

## 🚀 快速安装

=== "Go Install (推荐)"

    如果你已安装 Go 环境 (1.24.3+)：
    ```bash
    go install github.com/threatexpert/gonc/v2@latest
    $HOME/go/bin/gonc
    ```

=== "Windows"

    1. 下载 [https://www.gonc.cc/gonc.exe](https://www.gonc.cc/gonc.exe)
    2. 放入 `C:\Windows\System32` 或添加到 PATH 环境变量中。


=== "Linux"

    从 Release 页面下载二进制文件：
    ```bash
    curl -L https://www.gonc.cc/gonc_linux_amd64 -o gonc
    chmod +x gonc
    sudo mv gonc /usr/local/bin/
    ```

=== "macOS"

    从 Release 页面下载二进制文件：
    ```bash
    curl -L https://www.gonc.cc/gonc_darwin_arm64 -o gonc
    chmod +x gonc
    sudo mv gonc /usr/local/bin/
    ```

---

## ⚡️ 极速上手

### 1. 经典用法：像 Netcat 一样点对点聊天
除了兼容 `nc` 常用的监听和主动连接的模式，现在还可以这样：

`gonc -p2p 口令`

例如：主机A和主机B执行下面相同的命令，注意等待零一端25秒将超时

```bash
gonc -p2p mysecret123

```

两端用同样的口令，然后双方就能基于口令发现彼此的网络地址，穿透 NAT ，双向认证和加密通讯。 默认优先 tcp 尝试直连，不行再试 udp ，一旦连接建立成功，和传统 nc 一样你可以利用管道重定向实现自己的数据传输。

还可以使用MQTT协议等待直到另一端发起P2P连接，

```bash
# Server (-mqtt-wait可以一直等待客户端)
gonc -p2p mysecret123 -mqtt-wait

# Client (任何时候，主动发起P2P)
gonc -p2p mysecret123 -mqtt-hello
```
