package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type HttpConnectClient struct {
	ProxyAddr string // HTTP CONNECT 代理服务器地址
	Username  string // 用户名 (可选)
	Password  string // 密码 (可选)
}

func NewHttpConnectClient(proxyAddr, username, password string) *HttpConnectClient {
	return &HttpConnectClient{
		ProxyAddr: proxyAddr,
		Username:  username,
		Password:  password,
	}
}

func getFullHttpHeader(conn net.Conn) (string, error) {
	result := ""
	for {
		line, err := ReadString(conn, '\n')
		if err != nil {
			return "", fmt.Errorf("failed to read headers: %v", err)
		}
		result += line

		if line == "\r\n" || line == "\n" {
			break
		}
	}

	return result, nil
}

// Dial 实现 HttpConnectClient 的拨号逻辑
func (c *HttpConnectClient) Dial(network, address string) (net.Conn, error) {
	// 1. 连接HTTP代理服务器
	proxyConn, err := net.Dial(network, c.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to HTTP proxy server failed: %w", err)
	}

	// 2. 发送CONNECT请求
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address}, // Use Opaque for CONNECT
		Host:   address,                   // Set Host header for CONNECT
	}
	if c.Username != "" && c.Password != "" {
		if connectReq.Header == nil {
			connectReq.Header = make(http.Header)
		}
		connectReq.SetBasicAuth(c.Username, c.Password)
	}

	err = connectReq.Write(proxyConn)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("write HTTP CONNECT request failed: %w", err)
	}

	// 3. 读取HTTP代理服务器响应，不要直接bufio.NewReader(stringReader)，他可能读取过多数据并缓存在其内部
	//	需要使用自定义的getFullHttpHeader函数来确保仅仅读取完整的HTTP头部
	header, err := getFullHttpHeader(proxyConn)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("read HTTP Header failed: %w", err)
	}
	stringReader := strings.NewReader(header)
	bufReader := bufio.NewReader(stringReader)
	resp, err := http.ReadResponse(bufReader, connectReq)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("read HTTP CONNECT response failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		proxyConn.Close()
		return nil, fmt.Errorf("HTTP CONNECT failed with status: %s", resp.Status)
	}

	return proxyConn, nil
}

// ProxyClient 通用代理客户端
type ProxyClient struct {
	ProxyProt string // 代理协议类型："socks5" 或 "http"
	ProxyAddr string // 代理服务器地址 (e.g., "127.0.0.1:1080")
	Username  string // 用户名 (可选)
	Password  string // 密码 (可选)

	dialer Dialer // 实际的拨号器
}

// NewProxyClient 构造函数
func NewProxyClient(proxyProt, proxyAddr, username, password string) (*ProxyClient, error) {
	pc := &ProxyClient{
		ProxyProt: strings.ToLower(proxyProt),
		ProxyAddr: proxyAddr,
		Username:  username,
		Password:  password,
	}

	switch pc.ProxyProt {
	case "socks5":
		pc.dialer = NewSocks5Client(proxyAddr, username, password)
	case "http":
		pc.dialer = NewHttpConnectClient(proxyAddr, username, password)
	case "":
		pc.dialer = &net.Dialer{}
	default:
		return nil, fmt.Errorf("unsupported proxy protocol: %s", proxyProt)
	}
	return pc, nil
}

// Dial 实现 ProxyClient 的拨号逻辑，委托给内部的 dialer
func (c *ProxyClient) Dial(network, address string) (net.Conn, error) {
	if c.dialer == nil {
		return nil, fmt.Errorf("proxy client not initialized, call NewProxyClient first")
	}
	return c.dialer.Dial(network, address)
}
