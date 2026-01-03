# 内置服务模块 (-e)

`gonc` 的 `-e` (exec) 参数不仅支持像传统 `netcat` 那样执行外部程序（如 `/bin/bash`），更引入了强大的 **内置 Go 模块**。

这些模块直接在内存中运行，无需磁盘上有对应的二进制文件，无需创建子进程、性能更好。

!!! info "语法格式"
    ```bash
    gonc -e ":<command> [args]" ...
    ```
    注意：内置命令始终以冒号 `:` 开头。要查看特定模块的帮助，可运行 `gonc -e ":<cmd> -h"`，例如 `gonc -e ":s5s -h"`。

---

## 🐚 `:sh` - 远程 Shell

提供交互式的命令行访问。这是最常用的模块。

**原理**：
将网络连接的标准输入/输出 (Stdin/Stdout) 绑定到系统的 Shell 进程，不支持Windows，Linux/Mac 为 `/bin/sh` 或 `/bin/bash`。

**参数**：
* `[path]`: (可选) 指定 Shell 的路径。

**示例**：

=== "Linux / macOS"
    ```bash
    # 默认调用 /bin/sh
    gonc -e ":sh" -l 1234 
    
    # 指定 bash
    gonc -e ":sh /bin/bash" -l 1234 
    ```

=== "Windows"
    ```bash
    # :sh不支持windows，-e可以直接执行cmd，但客户端不支持用-pty的方式
    gonc -l 1234 -e "cmd"
    ```

!!! tip "获取完美的 Shell 体验"
    客户端连接时建议加上 **`-pty`** 参数，这样可以使用 `Ctrl+C`、`Vim` 和 `Tab` 补全等功能，否则只是简单的管道流。
    ```bash
    gonc -pty <target_ip> 1234
    ```

---

## 🌐 `:s5s` - SOCKS5 代理服务

将当前连接转换为一个标准的 SOCKS5 代理服务器。

**原理**：
`gonc` 实现了完整的 SOCKS5 协议栈（支持 CONNECT 、BIND 和 UDP ASSOCIATE）。当连接建立后，`gonc` 不再进行简单的流量转发，而是解析 SOCKS5 协议头，根据请求动态连接目标。

**参数**：

* `-auth <user:pass>`: 启用用户名密码认证。

* `-u`: 允许 UDP 转发 (UDP Associate)，默认不开启。

* `-c`: 是CONNECT方法，默认启用，可以-c=0关闭。

* `-b`: 是BIND方法，默认不开启。

* `-http`: 开启兼容HTTP代理协议，这样同时能支持HTTP代理的客户端了。

* `-local`: 如果你的服务器有多个IP，可以限定使用的出口IP

* `-server-ip`: 设置针对BIND或UDP请求的绑定地址，服务器默认绑定地址是0.0.0.0。

**示例**：

```bash
# 启动一个监听在 1080 的 SOCKS5 代理服务器，带认证
gonc -k -e ":s5s -auth user:simplekey123" -l 1080 
```

**高级组合 (Socks5 over TLS)**：
利用 `gonc` 的加密通道保护 SOCKS5 流量。

=== "SOCKS5服务器（加密）"

```bash
# 服务端：加密监听，-b开启SOCKS5的BIND命令
gonc -tls -psk simplekey123 -e ":s5s -b" -k -l 8443

```

本地需要再运行一个gonc将加密的SOCKS5转标准SOCKS5。

=== "本地标准SOCKS5"

    ```bash
    # 客户端调用:nc建立加密TCP连接。不支持代理UDP
    gonc -e ":nc -tls -psk simplekey123 <serverIP> 8443" -k -l 127.0.0.1 1080

    ```

=== "BIND实现反向代理"

    ```bash
    # 实现类似frp反向代理，请求代理服务器保持开启23306端口，并转发到本机127.0.0.1 3306
    gonc -x "-tls -psk simplekey123 <serverIP>:8443" -e ":nc 127.0.0.1 3306" -k -l 23306

    ```

---

## 🔀 `:tp` - 透明代理

:tp 是一种透明端口转发机制，用于在客户端不支持或不便配置代理的场景下，通过本地监听端口自动完成代理转发。

客户端只需按“直连地址”方式连接，实际流量会被 :tp 无感接管并转发至指定的上游代理。

**语法**：

=== "SOCKS5代理（默认）"
    监听本地 3080 端口作为透明代理入口，所有连接将通过 127.0.0.1:1080 的 SOCKS5 代理转发：
    ```bash
    gonc -e ":tp -x 127.0.0.1:1080" -k -l 3080

    ```

=== "HTTP代理"
    监听本地 3080 端口作为透明代理入口，并通过 HTTP CONNECT 方式转发至 127.0.0.1:1080：
    ```bash
    gonc -e ":tp -X connect -x 127.0.0.1:1080 -auth user:pass" -k -l 3080

    ```

**使用说明（仅适用Windows/Linux）**：

以 远程桌面客户端（RDP） 为例，用户在客户端中填入地址：

`10.0.0.5-3389.gonc.cc:3080`

连接过程如下：

- 客户端解析 10.0.0.5-3389.gonc.cc，得到形如 127.a.b.c 的回环地址

- 客户端认为自己在直连目标服务，并实际连接到本机的 3080 端口

- :tp 用127.a.b.c反查域名，解析出真实目标 10.0.0.5:3389

- :tp 自动通过配置好的上游代理（如 127.0.0.1:1080）发起代理连接

- 客户端与远端服务之间的通信在整个过程中无需任何代理配置

---

## 🔗 `:nc` - 端口转发 (Netcat)

:nc安全等效于gonc本身，即gonc可以在内存中执行自己，不用开启子进程，因此可以实现高效的将流量转发到另一个地址。

**原理**：
类似于 SSH 的 `-L` 本地转发。当连接建立后，`:nc` 模块会主动向指定的目标发起连接，并双向通过管道交换数据。

**语法**：
```bash
-e ":nc [options] <target_host> <target_port>"
```

**示例1 (跳板机场景)**：
假设你想通过 A 访问内网数据库 B (192.168.1.50:3306)。

```bash
# 在机器 A 上运行
gonc -e ":nc 192.168.1.50 3306" -k -l 3306
```
现在，访问机器 A 的 3306 端口，就等于访问 B 的数据库。

**示例2 (UDP端口转发)**：

```bash
# 监听在[::]:53，转发到8.8.8.8 53。-framed是防止-e的管道机制导致UDP粘包
gonc -e ":nc -framed -u 8.8.8.8 53" -framed -udp-timeout 2 -u -k -l 53
```

---

## 📂 `:httpserver` - 文件服务器

快速共享文件或目录。

**原理**：
启动一个轻量级的 HTTP 服务器，它支持递归遍历目录，下载文件时支持zstd压缩传输。

**参数**：

* `-webmode`: 默认启用，如果目录存在index.html或index.htm文件，会展示index页面内容，而不是浏览目录。
* `<root_dir>`: 要共享的根目录路径。支持指定多个路径。

**示例**：

```bash
# 共享当前目录 (.)
gonc -e ":httpserver ." -k -l 8080

# 共享多个指定路径
gonc -e ":httpserver /var/www/html /tmp/test" -k -l 8080
```

---

## 🧬 `:mux` - 多路复用的文件服务和代理服务

`:mux` 主要用于建立隧道，它可用在单个TCP/KCP会话上创建多个虚拟流，为本地接入的客户端提供并发访问的体验。目前基于mux集成了两个应用功能：HTTP文件服务和SOCKS5/HTTP代理服务。通过传统方式建立的连接或P2P建立的连接都可以使用mux来提供文件服务和代理服务。

**核心引擎**：
可以通过 `-mux-engine` 参数切换底层引擎： `smux` (默认)。`yamux`另一个流行mux引擎。

**语法**：
```bash
-e ":mux <sub-command> [args]"

```

### 1. 隧道构建 (`link` / `linkagent`)

这是构建复杂端口映射和内网穿透的核心功能。

* **`:mux linkagent`**: 启动双向代理 Agent，通常在**服务端**（等待连接的一方）使用。
* **`:mux link "<L-Config>;<R-Config>"`**: 定义隧道规则，通常在**客户端**（发起连接的一方）使用。

### **Link 配置详解**

Link 字符串定义了隧道两端的行为，格式为分号分隔的 **双端配置**：

```text
"本地监听配置;远程监听配置"

```

!!! note "配置逻辑"
* **左侧 (本地)**：使用link的一端。
* **右侧 (远程)**：使用linkagent的一端。
* **`none`**：表示该端不进行任何监听操作。

#### **(1) 代理协议 (`x://`)**

启动一个同时支持 HTTP 和 SOCKS5 的标准代理服务。代理请求访问的地址将转发到另一端去访问。

**语法格式**：
`x://[user:pass@]ip:port?[params]`

* **认证 (可选)**：在 IP 前加上 `user:password@` 即可启用代理认证。
* **支持参数**：

| 参数 | 示例 | 说明 |
| --- | --- | --- |
| **`tproxy`** | `tproxy=1` | 启用透明代理支持 (Linux TProxy)。 |
| **`allow`** | `allow=domain` | 使透明代理允许代理访问域名。 |
| **`outbound_bind`** | `outbound_bind=10.0.0.5` | **指定出口 IP**。当对端机器有多个 IP 时，强制代理流量从指定网卡发出。 |

#### **(2) 转发协议 (`f://`)**

端口转发模式 (Port Forwarding)。监听一端的端口，将流量转发到另一端可达的目标地址。

**语法格式**：
`f://ip:port?to=target:port&[params]`

* **核心参数**：
* **`to` (必填)**：流量转发的目标地址。


* **支持参数**：

| 参数 | 示例 | 说明 |
| --- | --- | --- |
| **`outbound_bind`** | `outbound_bind=10.0.0.5` | 指定连接目标地址时使用的源 IP。 |

#### **(3) TLS 加密扩展 (`+tls`)**

上述 `x` 和 `f` 协议均支持启用 TLS，用于在本地/远程监听加密端口（而非明文端口）。

**语法格式**：
`x+tls://...` 或 `f+tls://...`

* **支持参数**：

| 参数 | 示例 | 说明 |
| --- | --- | --- |
| **`cert`** | `cert=server.pem` | 指定 TLS 证书文件路径。 |
| **`key`** | `key=server.key` | 指定 TLS 私钥文件路径。 |

---

#### **📝 配置示例**

以下示例的link配置假设左侧是家里，右侧是公司。使用P2P建立连接的方式。

首先假设公司已经启动了linkagent服务。它会一直订阅MQTT消息等待客户端唤起连接，支持多个客户端同时建立隧道。

=== "服务端（公司）"
    ```bash
    gonc -p2p mysecret123 -k -mqtt-wait -e ":mux linkagent"
    ```

=== "支持简化语法"
    ```bash
    gonc -p2p mysecret123 -linkagent
    ```

接下来示例是从家里客户端发起link请求，默认使用**TCP+TLS+PSK的通讯加密方案**，如果TCP无法穿透会自动尝试UDP，你可以仅从客户端追加参数来设定两端的传输协议，例如添加`-u`将限定使用**UDP+KCP+DTLS+PSK的通讯加密方案**，如果再添加`-ss`将限定使用**UDP+KCP+SS的通讯加密方案**。

=== "开启双向代理互相访问"
    ```bash
    gonc -p2p mysecret123 -k -mqtt-hello -e ":mux link x://:1080;x://:3080"
    ```

=== "支持简化语法"
    ```bash
    gonc -p2p mysecret123 -link "x://:1080;x://:3080"
    ```

家里和公司分别监听1080和3080的SOCKS5+HTTP代理，彼此可通过一个隧道互访对方网络。

用-link参数会自动添加-k -mqtt-hello -e 调用":mux"

=== "透明代理与多 IP"
家里开启透明代理，公司不监听端口，公司转发流量时使用指定IP：192.168.1.5。透明代理只支持绑定在0.0.0.0，但只允许来自loopback地址访问。
```bash
gonc -p2p mysecret123 -link "x://0.0.0.0:1080?tproxy=1;none?outbound_bind=192.168.1.5"
```

=== "反向代理"
家里不监听端口，公司监听端口在0.0.0.0:8080，转发到家里的192.168.0.1:80。
```bash
gonc -p2p mysecret123 -link "none;f://0.0.0.0:8080?to=192.168.0.1:80"
```

=== "TLS 安全监听"
本地监听加密的 SOCKS5 端口（需要客户端用 TLS 连入）。
```bash
gonc -p2p mysecret123 -link "x+tls://0.0.0.0:8443?cert=ca.pem&key=key.pem;none"
```


### 2. 文件传输 (`httpserver` / `httpclient`)

在复用通道中直接传输文件，无需建立额外的连接，支持断点续传。

* **`:mux httpserver <dir1> [dir2]...`**: 在通道一端启动文件服务。
* **`:mux httpclient <saveDir> <remotePath>`**: 在通道另一端请求下载。

**示例：目录同步**

=== "发送端"
    ```bash
    gonc -p2p mysecret123 -k -mqtt-wait -e ":mux httpserver D:/Data1 D:/Data2"
    ```

=== "支持简化语法"
    ```bash
    gonc -p2p mysecret123 -httpserver D:/Data1 D:/Data2
    ```

以上命令开启共享 D 盘的 Data1 和 Data2 目录。

=== "接收端"
    将远程的 Data 目录都下载到本地的 /tmp/download。
    ```bash
    # 注意：<remotePath>为/表示下载全部，也可以指定具体某个文件或目录
    gonc -p2p mysecret123 -k -mqtt-hello -e ":mux httpclient /tmp/download /"
    ```
    若这样则不下载，只监听8080端口，可使用浏览器访问 http://127.0.0.1:8080
    ```bash
    gonc -p2p mysecret123 -k -mqtt-hello -e ":mux -l 8080"
    ```

=== "支持简化语法"
    将远程的 Data 目录下载到本地的 /tmp/download。
    ```bash
    # 注意：还可以-download-subpath指定具体要下载的某目录
    gonc -p2p mysecret123 -download /tmp/download
    ```
    若这样则不下载，只监听8080端口，可使用浏览器访问 http://127.0.0.1:8080
    ```bash
    gonc -p2p mysecret123 -httplocal-port 8080
    ```

### 3. 监听模式 (`-l`)

**语法**：

```bash
gonc -p2p mysecret123 -k -mqtt-wait -e ":mux -l <port>"

```

指定 `:mux` 模块在特定的本地端口上监听，对端httpserver时，指定本地监听 <port> 作为mux的入口，共浏览器或gonc访问对端的HTTP服务。


### 4. `socks5`

类似linkagent，不展开介绍，新版的linkagent功能已经取代它。

```bash
gonc -p2p mysecret123 -k -mqtt-wait -e ":mux socks5"
```


---

## 🤖 `:service` - 动态服务 (Super Server)

它允许在一个监听端口上，根据客户端的请求（Call）动态提供不同的服务。类似于 Linux 的 `inetd` 或 SSH 的多功能端口。

**工作流程**：

1.  **服务端配置**：使用 `-:xxx` 参数预定义好各种服务（如 `-:sh`, `-:s5s`）。
2.  **服务端运行**：使用 `-e ":service"` 启动主控循环。
3.  **客户端调用**：连接时使用 `-call :xxx` 告诉服务端“我想要什么服务”。

### 服务端配置示例

启动一个端口 `2222`，同时提供 Shell、SOCKS5 和 HTTP 服务，并使用 TLS+PSK 加密：

```bash
gonc -l -local :2222 -tls -psk mysecret123 -keep-open \
    -e ":service" \
    -:sh "/bin/bash"  \
    -:s5s "-http" \
    -:httpserver "/tmp"

```

### 客户端调用示例

=== "调用 Shell"
    ```bash
    gonc -remote <server-ip>:2222 -tls -psk mysecret123 -call :sh -pty
    ```

=== "调用 SOCKS5"
    在本地启动 1080 端口，通过 server 的 :s5s 模块代理上网。
    ```bash
    gonc -e ":nc -tls -psk mysecret123 -call :s5s <server-ip> 2222" -k -l 127.0.0.1 1080 
    ```

=== "调用 HTTP"
    将服务端的 /tmp 映射到本地 8000 端口
    ```bash
    gonc -e ":nc -tls -psk mysecret123 -call :httpserver <server-ip> 2222" -k -l 127.0.0.1 8080 
    ```

### 为什么使用 `:service`？
* **隐蔽性**：只开放一个端口（如 443），却能干所有的事情。
* **灵活性**：不需要为传文件单独开一个进程，也不需要为 Shell 单独开一个端口。
