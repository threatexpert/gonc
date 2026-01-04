# 基础连接参数

本章节介绍 `gonc` 最基础的网络连接功能。如果你使用过传统的 `netcat`，这部分内容会让你倍感亲切。

---

## 💻 客户端与服务端模式

`gonc` 的工作模式取决于是否指定了监听参数。

### 客户端模式 (Client)

默认情况下，`gonc` 运行在主动连接模式。

**语法：**
```bash
gonc [选项] <目标主机> <目标端口>

```

| 参数 | 说明 | 示例 |
| --- | --- | --- |
| `<host> <port>` | **位置参数**目标地址和端口。 | `gonc 192.168.1.1 80` |
| **`-remote`** | **指定目标 (可选)**如果不希望使用位置参数，可以使用此选项显式指定目标。 | `gonc -remote 192.168.1.1:80` |
| **`-local`** | **绑定本地网卡 (可选)**如果你有多个IP，可明确使用哪个IP外连。 | `gonc -local 192.168.1.2:0 -remote 192.168.1.1:80` |

!!! tip "为什么需要 `-remote` ?"
在编写复杂的 Shell 脚本时，位置参数容易混淆。使用 `-remote` 可以让命令意图更清晰。例如：
`gonc -remote baidu.com:443 -tls`

### 服务端模式 (Server)

**语法：**

```bash
gonc -l [端口]

```

| 参数 | 作用 | 说明 |
| --- | --- | --- |
| **`-l`** | **监听模式 (Listen)** | 开启服务端，绑定本地端口等待连接。 |
| **`-local`** | **绑定本地地址** | 格式为 `ip:port`。如果只指定端口 (如 `-l 8080`)，默认绑定 `0.0.0.0`。使用 `-local 127.0.0.1:8080` 可限制只允许本机访问。 |
| **`-k`, `-keep-open`** | **保持监听** | 传统netcat客户端断开后服务端会退出。开启此选项后，服务端会保持运行，等待下一个客户端连接（类似守护进程）。 |
| **`-U`** | **Unix Domain Socket** | 监听或连接 Unix Socket 文件而非 TCP/UDP 端口。 |

**示例：**
=== "一次性监听"
客户端断开后，gonc 立即退出。
```bash
gonc -l 8080
```
=== "持续监听"
适合作为服务运行。
```bash
gonc -k -l 8080
```

=== "绑定特定网卡"
假如你有个IP是192.168.1.5，可以限定绑定在 192.168.1.5。
```bash
gonc -l -local 192.168.1.5:8080
```

---

## 🔄 传输协议控制

控制底层传输协议和 IP 版本。

| 参数 | 说明 | 备注 |
| --- | --- | --- |
| **(默认)** | **TCP 协议** | 如果不指定 `-u`，默认为 TCP。 |
| **`-u`** | **UDP 协议** | 使用无连接的 UDP 传输。 |
| **`-4`** | **强制 IPv4** | DNS 解析和连接建立仅使用 IPv4。 |
| **`-6`** | **强制 IPv6** | DNS 解析和连接建立仅使用 IPv6。 |
| **`-dns`** | **自定义 DNS** | 指定 DNS 服务器地址 (如 `8.8.8.8:53`)，绕过系统默认 DNS。 |
| **`-tls`/`-tls10`~`-tls13`** | **自定义 tls版本** | 支持1.0至1.3 |
| **`-kcp`** | **KCP 协议** | 使用基于UDP的稳定传输协议 |
| **`-psk`** | **共享密钥** | 当配合tls时，psk用于派生证书和身份认证。否则用于加密数据。 |

!!! warning "UDP 注意事项"
使用 `-u` 模式时，由于 UDP 是无状态的，`gonc` 依靠 **`-udp-timeout`** (默认 300秒) 来判定空闲的会话何时结束。

---

## 🌍 代理支持 (Proxy)

`gonc` 原生支持通过前置代理连接TCP/UDP目标，也支持通过代理监听TCP端口。

### `-x` 参数详解

**语法：**

```bash
gonc -x "[选项] <proxy_ip>:<port>" <target> <target_port>

```

* **支持协议**：SOCKS5 (默认), HTTP Connect。
* **支持加密**：代理连接本身支持 TLS 和 PSK 加密。

**查看-x的所有子选项（gonc -x "-h"）：**

```bash
gonc -x "-h"
-x Usage: [options] <host:port>
Or:    [options]  <host> <port>

Options:
  -4    Use IPv4 (default is tcp)
  -6    Use IPv6
  -kcp
        KCP over udp
  -psk string
        Pre-shared key for deriving TLS certificate identity (anti-MITM); also key for TCP/KCP encryption
  -tls
        Enable TLS encryption
  -u    UDP socket

Examples:
  -x "-tls -psk randomString <host:port>"
```

**常见用法示例：**

=== "HTTP 代理"
-X connect指定HTTP代理协议 连接 Google。
```bash
gonc -X connect -x 127.0.0.1:9050 google.com 80
```

=== "SOCKS5 代理连接"
通过本地 Tor 连接 Google。
```bash
gonc -x 127.0.0.1:9050 google.com 80
```

=== "SOCKS5 代理监听"
请求代理持续监听8000。如果配合-e ":nc 127.0.0.1 80"相当于把本地的80端口暴露到代理服务器的8000端口上。
```bash
gonc -x server-ip:1080 -k -l 8000
```

=== "带认证的代理"
连接需要账号密码的 SOCKS5 代理。
```bash
gonc -x 192.168.1.1:1080 -auth "user:simplekey123" 10.0.0.1 80
```

=== "使用加密代理"
*高级用法*：如果代理服务器也是 `gonc` 搭建的加密 SOCKS5 (`-e :s5s -tls -psk`)：
```bash
# 这里的 -x 字符串中包含了连接代理所需的 TLS 和 PSK 参数
gonc -x "-tls -psk mykey 1.2.3.4:1080" 10.0.0.5 22
```

| 辅助参数 | 说明 |
| --- | --- |
| **`-x2`** | **备用代理**仅适用 `-p2p` 模式，当尝试P2P失败时，自动回退使用的代理地址。 |
| **`-X`** | **指定代理协议**默认为 SOCKS5。可选值：`connect` (HTTP HTTPS代理)。 |
| **`-auth`** | **代理认证**格式 `user:password`。 |

---

## 📊 输出与日志

| 参数 | 说明 |
| --- | --- |
| **`-v`** | **详细模式 (Verbose)**默认开启。显示连接建立、断开、P2P 打洞进度等日志。如果用于脚本管道，建议关闭或重定向 stderr。 |
| **`-P` / `-progress`** | **传输进度条**显示实时传输速度和流量统计。在传输文件时非常有用。 |

**效果演示：**

```bash
$ gonc -P -send bigfile.iso 192.168.1.2 8888
OUT: 45.2 MiB (47392122 bytes), 11.5 MiB/s | 00:00:04
```
