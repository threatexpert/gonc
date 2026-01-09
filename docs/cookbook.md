
# 常用场景

这里汇集了 `gonc` 最常用的实战用法，有文件快传，端口转发，反向Shell等等。你可以直接复制命令并在终端运行。

---

## 📂 文件快传 {: #file }

告别 `tar` 和 `scp`，使用 P2P 协议在两台内网机器间高速传输文件或目录。gonc内置的httpserver会自动识别文件类型，适当启用zstd实时压缩传输。

### 场景 1：文件/目录传输

将机器 A 的文件夹完整同步到机器 B，支持断点续传。

=== "发送端 (Server)"

    启动 HTTP 文件服务，指定要共享的目录（支持多个路径，可以文件也可以是目录）。
    
    ```bash
    gonc -p2p mysecret123 -httpserver /path1/to/share /path2/to/share
    ```
    上面这个命令是为了使用起来相对方便，`-httpserver`实际会转为这样调用-e的模块`-e ":mux httpserver /path1/to/share /path2/to/share"`，以及使用-k -mqtt-wait持续等待客户端连接。


=== "接收端 (Client)"

    方式1：P2P连接后自动下载远程目录到本地。
    
    ```bash
    # -download 指定保存路径
    gonc -p2p mysecret123 -download /path/to/save
    ```

    方式2：不会自动开始下载，P2P连接成功后仅将远程HTTP服务映射到127.0.0.1:9999 端口（指定绑定到0.0.0.0:9999），该端口是多路复用的入口。
    ```bash
    gonc -p2p mysecret123 -httplocal-port 9999
    ```
    然后打开浏览器访问 `http://127.0.0.1:9999`。
    接着还可以用gonc -http-download下载指定文件夹
    ```bash
    gonc -http-download /path/to/save http://127.0.0.1:9999/subpath
    ```

更多参数说明在[:mux 多路复用文件传输](guide/modules.md#file)章节

---

## 🌐 代理与隧道 {: #link }

将 `gonc` 变成随身携带的 VPN 网关。

### 场景 1：P2P 隧道 (内网穿透访问)

**需求**：你在家里，想访问公司内网的 服务器远程桌面 (例如 10.0.0.1:3389)，或者通过公司的网络上网。

=== "公司电脑"

开启 Link Agent 模式，会一直等待连接，支持接入多个客户端。

```bash
gonc -p2p mysecret123 -linkagent
```

=== "家里电脑"

建立连接，并在本地开启 SOCKS5+HTTP 代理端口1080。使用SOCKS5协议时，支持UDP，UDP将封装进入p2p的隧道中。

```bash
# 在本地 1080 开启代理，流量将从公司电脑出去
gonc -p2p mysecret123 -link 1080
```


!!! tip "透明代理魔法 (Magic DNS)"
连接建立后，如果你想直接访问公司内网的远程桌面 (10.0.0.1:3389)，虽然`mstsc`(远程桌面客户端)不支持代理，你也无需配置端口转发。

=== "依赖公网DNS"

    直接连接目标地址：

    ```
    10.0.0.1-3389.gonc.cc:1080
    ```
    10.0.0.1-3389.gonc.cc (注意中间是横杠)，该域名会被解析为类似127.b.c.d的IP，因此`mstsc`会连入本地的socks5代理端口1080，然后`gonc`根据连接一端的127.b.c.d地址去反解析出域名中的10.0.0.1-3389这个信息。

    !!! warning "隐私和安全问题"

        这个特性依赖ns.gonc.cc公网DNS解析，出于对用户隐私和安全保护，gonc的透明代理默认只接受内网私有IP段，不接受公网IP或域名方式，例如tonypc.corp.lan-3389.gonc.cc。除非用户明确的使用参数-link "x://:1080?tproxy=1&allow=domain;none"

        需要说明的是，`ns.gonc.cc` 服务器只能看到 `*.gonc.cc` 的 DNS 解析请求记录，通常无法获知具体客户端的真实 IP 地址。这是因为（DNS递归查询机制）客户端的请求一般会先经过ISP的DNS或公共 DNS 运营商（如 8.8.8.8），再由其转发至 ns.gonc.cc。

        关于安全问题，例如在处理`mstsc`连接时，如果 DNS 被恶意篡改，理论上可能得到`1.2.3.4-3389`这样的地址，而不是预期的`10.0.0.1-3389`。
        由于`gonc`默认只允许内网 IP 段，这类异常连接会被拒绝，保证透明代理不会将客户端流量发送到公司内网之外的目的地。

        因此，在默认配置下，该机制通常不会带来额外的隐私或安全风险。

=== "无需DNS"

    gonc透明代理也支持不依赖公网DNS解析的方式：
    ```bash
    # -magicdns指定为公司网络的IP段，但只支持一个段，并设置最后段是0
    gonc -p2p mysecret123 -link 1080 -magicdns 10.0.0.0
    ```
    假如准备连接10.0.0.5:3389，我们借助ping先计算一下magic ip，
    ```bash
    ping 127.5.3389
    PING 127.5.3389 (127.5.13.61) 56(84) bytes of data.
    64 bytes from 127.5.13.61: icmp_seq=1 ttl=128 time=0.302 ms
    ^C
    ```
    得到直接连接目标地址：
    ```
    127.5.13.61:1080
    ```

### 场景 2：高级端口映射 (-link 配置详解)

`-link` 参数非常强大，可以实现类似SSH的-D、-L、-R功能，且支持双向的，以及透明代理和TLS加密。格式为 `"本地配置;远程配置"`，注意要使用引号。

```bash
# 1. 双向 SOCKS5+HTTP：两边都开启 1080 端口，互通互连
gonc -p2p mysecret123 -link "1080;1080"

# 2. 远程端口转发：将本地 1080 流量转发给远程去访问 1.2.3.4:80
gonc -p2p mysecret123 -link "f://127.0.0.1:1080?to=1.2.3.4:80;none"

# 3. 本地端口转发：让远程监听 80，流量转发给本地的 127.0.0.1:80
gonc -p2p mysecret123 -link "none;f://0.0.0.0:80?to=127.0.0.1:80"

```

### 场景 3：快速开启 SOCKS5 代理 server

在公司内网开启一个标准代理服务，供其他设备使用，为了持续提供服务必须使用-k(-keep-open)，否则gonc监听端口只接受一个连接。

```bash
# 监听 1080 端口，-auth设置账号密码，-b/-u分别启用BIND/UDP模式，-http是兼容HTTP代理协议
gonc -e ":s5s -b -u -http -auth user:simplekey123" -k -l 1080 

```

如果把SOCKS5运行在公网，建议使用TLS+PSK的加密认证，不过其他应用客户端就不支持直接接入了，需要本地再开一个gonc协助加密转发（只支持TCP），不支持SOCKS5代理UDP。
<div class="interactive-box">
  <label>🛠️设置示例server-ip:</label>
  <input type="text" placeholder="server-ip" value="server-ip" oninput="updateServerIP(this)">
</div>

=== "服务端 (监听)"

    ```bash
    # 这次:s5s没有用-auth user:pass，因为有TLS+PSK保护也具备加密和认证
    gonc -e ":s5s -b -u" -tls -psk mysecret123  -k -l 3080 
    ```

=== "客户端 (加密转发代理)"

    ```bash
    # 类似SSH，应用客户端通过1080接入代理服务器
    gonc -e ":nc -tls -psk mysecret123 server-ip 3080" -k -l 1080
    ```

=== "客户端（BIND加密反向代理）"

    ```bash
    # 在代理服务器保持开启23306端口，并转发到本机127.0.0.1 3306
    # -k参数可以保持把本机3306暴露在公网23306，类似frp反向代理
    gonc -x "-tls -psk mysecret123 server-ip:3080" -e ":nc 127.0.0.1 3306" -k -l 23306
    ```

### 场景 4：端口转发

=== "TCP端口转发"

    ```bash
    # 监听在[::]:80，可持续将客户端转发到127.0.0.1 8000
    gonc -e ":nc 127.0.0.1 8000" -k -l 80
    ```

=== "UDP端口转发"

    ```bash
    # 监听在[::]:53，转发到8.8.8.8 53。-framed是防止-e的管道机制导致UDP粘包
    gonc -e ":nc -framed -u 8.8.8.8 53" -framed -udp-timeout 2 -u -k -l 53
    ```

更多参数说明在[:mux 多路复用](guide/modules.md#mux)章节

---

## 🐚 远程管理 (Shell) {: #shell }

类似于 SSH，但你可以用正向、反弹或P2P的方式来获得Shell。以下统一用TCP的TLS+PSK加密方式，你也可以都加上-kcp使用UDP的加密方式。

### 方式1：P2P Shell

=== "控制端"
    ```bash
    gonc -pty -p2p mysecret123 -mqtt-hello
    ```

=== "被控端"

    ```bash
    gonc -e ":sh" -p2p mysecret123 -k -mqtt-wait
    ```

### 方式2：传统反弹 Shell

<div class="interactive-box">
  <label>🛠️设置示例server-ip:</label>
  <input type="text" placeholder="server-ip" value="server-ip" oninput="updateServerIP(this)">
</div>

=== "控制端"

    等待连接并获取交互式 Shell（-pty可支持 Tab 补全和 Ctrl+C）。
    
    ```bash
    gonc -pty -tls -psk mysecret123 -l 2222
    ```

=== "被控端"

    ```bash
    gonc -e ":sh" -tls -psk mysecret123 server-ip 2222
    ```


### 方式3：正向 Shell (传统监听模式)

=== "服务端 (监听)"

    ```bash
    # 监听 2222 端口，启用 TLS+PSK 加密, 启用-k(-keep-open)
    gonc -e ":sh" -tls -psk mysecret123 -k -l 2222
    ```

=== "客户端 (连接)"

    ```bash
    # 连接目标
    gonc -tls -psk mysecret123 -pty server-ip 1234
    ```

更多参数说明在[:shell](guide/modules.md#shell)章节

---

## 🧠 高级技巧：多服务复用 (Mux Service) {: #service }

<div class="interactive-box">
  <label>🛠️设置示例server-ip:</label>
  <input type="text" placeholder="server-ip" value="server-ip" oninput="updateServerIP(this)">
</div>

=== "传统连接方式"

    就像 SSH 的 22 端口一样，你可以在一个 `gonc` 端口上同时运行 Shell、SOCKS5 和 HTTP 服务，并通过 TLS + PSK 保护。

    **服务端配置：**

    ```bash
    # 启动一个超级服务端口 2222，实现远程shell、文件共享、流量转发
    gonc -l -local :2222 -tls -psk mysecret123 -keep-open \
        -e ":service" \
        -:sh "/bin/bash" \
        -:httpserver "/tmp /var/log" \
        -:mux "linkagent"

    ```

    **客户端调用：**

    客户端连接同一个端口 `2222`，但通过 `-call` 参数调用不同服务：

    * **连 Shell**:
    ```bash
    gonc -remote server-ip:2222 -tls -psk mysecret123 -call :sh -pty

    ```


    * **连 HTTP** (映射到本地 8800):
    ```bash
    gonc -e ":nc -tls -psk mysecret123 -call :httpserver server-ip 2222" -k -l -local :8800

    ```


    * **SOCKS5+HTTP代理** (本地监听1080):
    ```bash
    gonc -remote server-ip:2222 -tls -psk mysecret123 -call :mux -link 1080

    ```


=== "mux连接方式"

    就像 SSH 的 22 端口一样，你可以在一个 `gonc` 端口上同时运行 Shell、SOCKS5 和 HTTP 服务，并通过 TLS + PSK 保护。

    **服务端配置：**

    ```bash
    # 启动一个超级服务端口 2222，实现远程shell、文件共享、流量转发，-:mux不能和-mux一起
    gonc -l -local :2222 -tls -psk mysecret123 -keep-open -mux \
        -e ":service" \
        -:sh "/bin/bash"  \
        -:httpserver "/tmp /var/log" \
        -:s5s "-http"
    ```

    **客户端调用：**

    客户端连接同一个端口 `2222`，但通过 `-call` 参数调用不同服务：


    * **连 Shell**: `-mux-l`用`-`表示不用本地再监听端口，直接用stdio接入
        ```bash
        gonc server-ip 2222 -tls -psk mysecret123 -call :sh -pty -mux-l -
        ```

    * **连 HTTP**: 将服务端的 /tmp 映射到本地 8800 端口
        ```bash
        gonc server-ip 2222 -tls -psk mysecret123 -call :httpserver -mux-l 8800 
        ```

    * **SOCKS5+HTTP代理**: 在本地启动 1080 端口，通过 server 的 `:s5s` 模块代理上网。
        ```bash
        gonc server-ip 2222 -tls -psk mysecret123 -call :s5s -mux-l 1080 
        ```

=== "P2P连接方式"

    gonc服务端不需要监听端口，基于连接MQTT服务器订阅消息，等待客户端P2P连接提供服务，P2P模式，客户端支持设置传输协议，包括TCP/UDP(参数-u)，加密套件TLS/ShadowStream(参数-ss)。

    **服务端配置：**

    ```bash
    gonc -p2p mysecret123 -k -mqtt-wait \
        -e ":service" \
        -:sh "/bin/bash" \
        -:httpserver "/tmp /var/log" \
        -:mux "linkagent"
    ```

    **客户端调用：**

    客户端使用P2P方式连接，通过 `-call` 参数调用不同服务：

    * **连 Shell**:
    ```bash
    # 可以加上-u 或 -ss 或两者来实现P2P成功后与服务端的传输协议。
    gonc -p2p mysecret123 -mqtt-hello -call :sh -pty
    ```

    * **连 HTTP**: 将服务端的 /tmp 映射到本地 8800 端口
    ```bash
    gonc -p2p mysecret123 -mqtt-hello -call :httpserver -mux-l 8800 
    ```

    * **SOCKS5+HTTP代理** (本地监听1080):
    ```bash
    gonc -p2p mysecret123 -mqtt-hello -call :mux -link "1080;none" 
    ```

更多参数说明在[:service](guide/modules.md#service)章节

---

## 🔧 网络诊断与测试 {: #test }

### 检测 NAT 类型

在进行 P2P 连接前，了解当前的网络环境至关重要。

```bash
gonc -nat-checker

```

**输出解读：**

* **(easy)**: 容易穿透。NAT端口与内网端口总是保持不变的。
* **(hard)**: NAT端口与内网端口不一致，但连接不同目的地址，源端口会复用。
* **(symm)**: NAT端口每个都不一样，无法预测，算是最困难的类型。

### 宽带测速

测试两点之间的纯粹带宽（不写磁盘），下面命令也兼容windows，gonc在windows下兼容实现了/dev/null、/dev/zero和/dev/urandom。

=== "传统连接方式"

    === "接收端"
    ```bash
    gonc -P -write /dev/null -l 8888
    ```

    === "发送端"
    ```bash
    # 发送零数据流
    gonc -send /dev/zero -P <接收端IP> 8888
    ```

=== "P2P连接方式"

    === "接收端"
    ```bash
    gonc -P -write /dev/null -p2p mysecret123 -mqtt-wait
    ```

    === "发送端"
    ```bash
    # 发送零数据流
    gonc -send /dev/zero -P -p2p mysecret123 -mqtt-hello
    ```
