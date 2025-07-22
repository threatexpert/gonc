## Introduction to go-netcat

README in [English](./README_en.md) and [中文](./README.md)

`go-netcat` is a Golang-based `netcat` tool designed to facilitate peer-to-peer communication. Its main features include:

- 🔁 **Automated NAT Traversal**: Use `-p2p` to automatically perform TCP/UDP NAT traversal and establish peer-to-peer connections without manual configuration, relying on public STUN and MQTT services for address exchange.
- 🚀 **Reliable UDP Transmission**: Integrated with the KCP protocol, ensuring reliable communication over UDP when TCP cannot traverse NAT.
- 🔒 **End-to-End Encrypted Authentication**: Supports TLS for TCP and DTLS for UDP with mutual authentication based on a shared password.
- 🧩 **Embeddable Service Program**: Use `-exec` to run the tool as a sub-service, supporting scenarios like traffic forwarding, Socks5 proxy, and HTTP file service with multiplexing capabilities.
- 🖥️ **Pseudo-Terminal Support**: Combined with `-exec` and `-pty`, it provides a pseudo-terminal environment for interactive programs like `/bin/sh`, enhancing shell control (supports TAB, Ctrl+C, etc.).
- 💻 **Raw Input Mode**: Enables console `raw` mode with `-pty`, offering a native terminal-like experience when accessing a shell.
- 📈 **Real-Time Speed Statistics**: Displays real-time speed statistics for both sending and receiving directions, useful for testing transmission performance.

---

## Usage Examples

### Basic Usage
- Use it like `nc`:
    ```bash
    gonc www.baidu.com 80
    gonc -tls www.baidu.com 443
    ```

### Secure Encrypted P2P Communication
- Establish secure encrypted P2P communication between two different networks by agreeing on a password (use `gonc -psk .` to generate a high-entropy password to replace `randomString`). This password is used for mutual discovery and certificate derivation, ensuring communication security with TLS 1.3.
    ```bash
    gonc -p2p randomString
    ```
    On the other side, use the same parameters (the program will automatically attempt TCP or UDP communication (TCP preferred), negotiate roles (TLS client/server), and complete the TLS protocol):
    ```bash
    gonc -p2p randomString
    ```

### Reverse Shell (Pseudo-Terminal Support for UNIX-like Systems)
- Listener (does not use `-keep-open`, accepts only one connection; no authentication with `-psk`):
    ```bash
    gonc -tls -pty -exec /bin/bash -l 1234
    ```
- Connect to obtain a shell (supports TAB, Ctrl+C, etc.):
    ```bash
    gonc -tls -pty x.x.x.x 1234
    ```
- Use P2P for reverse shell (`randomString` is used for authentication, ensuring secure communication with TLS 1.3):
    ```bash
    gonc -pty -exec /bin/bash -p2p randomString
    ```
    On the other side:
    ```bash
    gonc -pty -p2p randomString
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
- Wait to establish a tunnel:
    ```bash
    gonc -p2p randomString -socks5server
    ```
- On the other side, provide a Socks5 service on the local port 127.0.0.1:3080:
    ```bash
    gonc -p2p randomString -socks5local-port 3080
    ```

### P2P Tunnel and HTTP File Server
- Start an HTTP file server:
    ```bash
    gonc -p2p randomString -httpserver c:/RootDir
    ```
- Access the file list from the other side (manually open a browser to access http://127.0.0.1:9999 to browse and download files):
    ```bash
    gonc -p2p randomString -httplocal-port 9999
    ```
    Support recursive download of all files with resume capability:
    ```bash
    gonc -p2p randomString -download c:/SavePath
    ```

### Flexible Service Configuration
- Use `-exec` to flexibly configure the application to provide services for each connection. For example, instead of specifying `/bin/bash` for shell commands, it can also be used for port forwarding. However, the following example starts a new `gonc` process for each connection:
    ```bash
    gonc -keep-open -exec ". -tls www.baidu.com 443" -l 8000
    ```
- To avoid spawning multiple child processes, use the built-in traffic forwarding module:
    ```bash
    gonc -keep-open -exec ":pf -tls www.baidu.com 443" -l 8000
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

    `gonc.exe -tls -psk randomString -e :s5s -keep-open -acl acl.txt -P -l 1080`

    On the other side, use `:pf` (built-in port forwarding command) to convert Socks5 over TLS to standard Socks5, providing local client access on 127.0.0.1:3080:

    `gonc.exe -e ":pf -tls -psk randomString x.x.x.x 1080" -keep-open -l -local 127.0.0.1:3080`
