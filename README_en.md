## Introduction to go-netcat

README in [English](./README_en.md) and [中文](./README.md)

`go-netcat` is a Golang-based `netcat` tool designed to facilitate peer-to-peer communication. Its main features include:

- 🔁 **Automated NAT Traversal**: Use `-p2p` to automatically perform TCP/UDP NAT traversal and establish peer-to-peer connections without manual configuration, relying on public STUN and MQTT services for address exchange.
- 🚀 **Reliable UDP Transmission**: Integrated with the KCP protocol, ensuring reliable communication over UDP when TCP cannot traverse NAT.
- 🔒 **End-to-End Encrypted Authentication**: Supports TLS for TCP and DTLS for UDP with mutual authentication based on a shared passphrase.
- 🧩 **Embeddable Service Program**: Use `-exec` to run the tool as a sub-service, supporting scenarios like traffic forwarding, Socks5 proxy, and HTTP file service with multiplexing capabilities.
- 🖥️ **Pseudo-Terminal Support**: Combined with `-exec` and `-pty`, it provides a pseudo-terminal environment for interactive programs like `/bin/sh`, enhancing shell control (supports TAB, Ctrl+C, etc.).
- 💻 **Raw Input Mode**: Enables console `raw` mode with `-pty`, offering a native terminal-like experience when accessing a shell.
- 📈 **Real-Time Speed Statistics**: Displays real-time speed statistics for both sending and receiving directions, useful for testing transmission performance.

---

[Latest version download](https://github.com/threatexpert/gonc/releases/latest)

---

## Usage Examples

### Basic Usage
- Use it like `nc`:
    ```bash
    gonc www.baidu.com 80
    gonc -tls www.baidu.com 443
    ```

### P2P Tunnel and HTTP File Server
- Both sides agree on the same passphrase. On the file-sending side, run the following command to start an HTTP file server. The last argument c:/RootDir is the directory containing the files to be sent:
    ```bash
    gonc -p2p passphrase -httpserver c:/RootDir
    ```
- On the receiving side, there are two options:

1. Automatically download the entire directory

    After running the following command, all files will be downloaded recursively to the local machine. If the process is interrupted, re-running the command will automatically resume from where it left off:

    ```bash
    gonc -p2p <passphrase> -download c:/SavePath
    ```

2. Browse and selectively download via browser

    This option does not start downloading automatically. Instead, you need to manually open a browser and visit http://127.0.0.1:9999 to view the peer’s file list and download files as needed:

    ```bash
    gonc -p2p <passphrase> -httplocal-port 9999
    ```

### Secure Encrypted P2P Communication
- Establish secure encrypted P2P communication between two different networks by agreeing on a passphrase (use `gonc -psk .` to generate a high-entropy passphrase to replace `passphrase`). This passphrase is used for mutual discovery and certificate derivation, ensuring communication security with TLS 1.3.
    ```bash
    gonc -p2p passphrase
    ```
    On the other side, use the same parameters (the program will automatically attempt TCP or UDP communication (TCP preferred), negotiate roles (TLS client/server), and complete the TLS protocol):
    ```bash
    gonc -p2p passphrase
    ```

    Note that if the other end delays the running time, it will exit if it cannot find the other end to interact with information within about half a minute. Therefore, it also supports a waiting mechanism based on MQTT message subscription, using -mqtt-wait and -mqtt-hello to synchronize the timing of the two parties to start P2P. For example, the following uses -mqtt-wait to wait continuously，

    ```bash
    gonc -p2p passphrase -mqtt-wait
    ```
    On the other side, 
    ```bash
    gonc -p2p passphrase -mqtt-hello
    ```

### Reverse Shell (Pseudo-Terminal Support for UNIX-like Systems)
- Listener (does not use `-keep-open`, accepts only one connection; no authentication with `-psk`):
    ```bash
    gonc -tls -exec ":sh /bin/bash" -l 1234
    ```
- Connect to obtain a shell (supports TAB, Ctrl+C, etc.):
    ```bash
    gonc -tls -pty x.x.x.x 1234
    ```
- Use P2P for reverse shell (`passphrase` is used for authentication, ensuring secure communication with TLS 1.3):
    ```bash
    gonc -exec ":sh /bin/bash" -p2p passphrase
    ```
    On the other side:
    ```bash
    gonc -pty -p2p passphrase
    ```

### Transmission Speed Test
- Send data and measure transmission speed (built-in `/dev/zero` and `/dev/urandom`):
    ```bash
    gonc.exe -send /dev/zero -P x.x.x.x 1234
    ```
    Example output:
    ```
    IN: 76.8 MiB (80543744 bytes), 3.3 MiB/s | OUT: 0.0 B (0 bytes), 0.0 B/s | 00:00:23
    ```
    On the receiving side:
    ```bash
    gonc -P -l 1234 > NUL
    ```

### P2P Tunnel and Socks5 Proxy
- Wait for the tunnel to be established:
    ```bash
    gonc -p2p passphrase -socks5server
    ```
- On the other side, expose a local SOCKS5 service on port 3080:
    ```bash
    gonc -p2p passphrase -socks5local-port 3080
    ```

    Next, for example, if you want to connect to 10.0.0.1:3389 in the remote network, you can simply enter the following address in your local Remote Desktop client:

    ```
    10.0.0.1-3389.gonc.cc:3080
    ```

    This domain will be resolved into an IP in the form of 127.b.c.d. As a result, the Remote Desktop client will connect to the local SOCKS5 proxy on port 3080, and then gonc will reverse-parse the 127.b.c.d address to extract the information 10.0.0.1-3389 from the domain name.

### Flexible Service Configuration
- Use `-exec` to flexibly configure the application to provide services for each connection. For example, instead of specifying `/bin/bash` for shell commands, it can also be used for port forwarding. However, the following example starts a new `gonc` process for each connection:
    ```bash
    gonc -keep-open -exec "gonc -tls www.baidu.com 443" -l 8000
    ```
- To avoid spawning multiple child processes, use the built-in nc module:
    ```bash
    gonc -keep-open -exec ":nc -tls www.baidu.com 443" -l 8000
    ```

### Socks5 Proxy Service
- Configure client mode:
    ```bash
    gonc -x s.s.s.s:port x.x.x.x 1234
    ```
- Built-in Socks5 server: Use `-e :s5s` to provide standard Socks5 service. Support `-auth` to set a username and password for Socks5. Use `-keep-open` to continuously accept client connections to the Socks5 server. Thanks to Golang's goroutines, it achieves good multi-client concurrency performance:
    ```bash
    gonc -e ":s5s -auth user:passwd" -keep-open -l 1080
    ```
- Secure Socks5 over TLS: Since standard Socks5 is unencrypted, use [`-e :s5s`](#) with [`-tls`](#) and [`-psk`](#) to customize secure Socks5 over TLS communication. Use [`-P`](#) to monitor connection transmission information, and [`-acl`](#) to implement access control for incoming connections and proxy destinations. For the `acl.txt` file format, see [acl-example.txt](./acl-example.txt).

    `gonc.exe -tls -psk passphrase -e :s5s -keep-open -acl acl.txt -P -l 1080`

    On the other side, use `:nc` (built-in nc command) to convert Socks5 over TLS to standard Socks5, providing local client access on 127.0.0.1:3080:

    `gonc.exe -e ":nc -tls -psk passphrase x.x.x.x 1080" -keep-open -l -local 127.0.0.1:3080`

### Establishing a Tunnel for Other Applications
 - Assist WireGuard in NAT Traversal to Form a VPN

    On the passive (listening) side, PC-S, run the following command (using the WireGuard peer’s public key as the passphrase, and assuming WireGuard is listening on port 51820):

    `gonc -p2p <PublicKey-of-PS-S> -mqtt-wait -u -k -e ":nc -u 127.0.0.1 51820"`

    On the active (initiating) side, PC-C, set the WireGuard peer (PS-S)'s Endpoint to 127.0.0.1:51821, with its own WireGuard interface listening on 51820. Then run the following command. The -k flag allows gonc to automatically reconnect if the network drops:

    `gonc -p2p <PublicKey-of-PS-S> -mqtt-hello -u -k -e ":nc -u -local 127.0.0.1:51821 127.0.0.1 51820"`


## P2P NAT Traversal Capabilities
### How does gonc establish a P2P connection?

 - Concurrently uses multiple public STUN servers to detect local TCP/UDP NAT mappings and intelligently determine NAT type
 - Exchanges address information securely via public MQTT servers, using a hash derived from the SessionKey as the shared topic
 - Attempts direct connection in the following priority order: IPv6 TCP > IPv4 TCP > IPv4 UDP, aiming for true peer-to-peer communication
 - No relay servers are used, and no fallback mechanisms are provided — either the connection fails, or it's a real P2P success

### How to Deploy a Relay Server for Cases Where P2P Is Not Feasible
 - A SOCKS5 server with UDP ASSOCIATE support running on a public IP is sufficient as a relay. You can also run gonc's built-in SOCKS5 proxy on your own VPS to act as a relay server.

    The following command starts a SOCKS5 proxy that only supports UDP forwarding. The -psk and -tls options enable encryption and PSK-based authentication. Note: Don’t just open port 1080 in your firewall—UDP forwarding uses random ports for each session.

    `gonc -e ":s5s -u -c=0" -psk <password> -tls -k -l 1080`

 - When P2P fails, you only need one side of gonc to retry the P2P process using the -x option to route through the SOCKS5 relay:

    `gonc -p2p <passphrase> -x "-psk <password> -tls <socks5server-ip>:1080" `

    Alternatively, you can use a standard SOCKS5 proxy server that supports UDP forwarding:

    `gonc -p2p <passphrase> -x "<socks5server-ip>:1080" -auth "user:password"`

For example, if both peers are behind symmetric NATs and P2P fails, having just one side use a SOCKS5 UDP relay effectively changes its NAT behavior to “easy,” making it much easier to establish a connection. The data remains end-to-end encrypted.


### Used public servers（STUN & MQTT）：

		"tcp://turn.cloudflare.com:80",
		"udp://turn.cloudflare.com:53",
		"udp://stun.l.google.com:19302",
		"udp://stun.miwifi.com:3478",
		"global.turn.twilio.com:3478",
		"stun.nextcloud.com:443",

 		"tcp://broker.hivemq.com:1883",
		"tcp://broker.emqx.io:1883",
		"tcp://test.mosquitto.org:1883",

### How effective is gonc at NAT traversal?

#### Except in symmetric NAT scenarios on both ends, gonc achieves a very high success rate

gonc classifies NAT types into three categories:

 1. Easy: A single internal port maps to the same external port across multiple STUN servers

 2. Hard: A single internal port maps to a consistent but different external port across STUN servers — harder than type 1

 3. Symmetric: A single internal port maps to different external ports depending on the destination — the most difficult type

To handle these NAT types, gonc employs several traversal strategies:

 - Uses multiple STUN servers to detect NAT behavior and identify multi-exit IP scenarios

 - Prefers IPv6 connections when both sides support it (e.g., TCP6-to-TCP6 direct dial)

 - Both peers listen on TCP while simultaneously dialing each other to increase TCP hole punching success

 - The peer with the easier NAT delays its initial UDP packet to avoid triggering port changes on the harder side

 - The peer with the harder NAT sends UDP packets with a low TTL to reduce interference from the remote firewall

 - As a last resort, uses a "birthday paradox" strategy: the harder side uses 600 random source ports, and the other side tries 600 random destination ports, increasing the chance of a successful UDP port collision

The following diagram shows the process of gonc establishing a P2P connection between a home broadband network (hard NAT) and a peer on a mobile network (symmetric NAT). Since both sides have IPv6, the -4 option is used on both ends to force IPv4 in order to demonstrate NAT traversal.

![hole-punching](./hole-punching.gif)
