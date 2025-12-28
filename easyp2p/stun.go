package easyp2p

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v3"
	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
)

var (
	lastStunClient     *stun.Client
	lastStunClientConn net.Conn
	lastStunClientLock sync.Mutex
	STUNServers        []string = []string{
		"tcp://turn.cloudflare.com:80",
		"udp://turn.cloudflare.com:53?3478",
		"udp://stun.l.google.com:19302",
		"udp://stun.miwifi.com:3478",
		"global.turn.twilio.com:3478",
		"stun.nextcloud.com:443",
	}
)

// GetPublicIP 获取公网IP，返回第一个成功响应的STUN服务器的结果
func GetPublicIP(network, bind string, timeout time.Duration) (index int, localAddr, natAddr string, err error) {
	// 1. result 结构体包含连接和客户端
	type result struct {
		index  int
		local  string
		nat    string
		err    error
		client *stun.Client
		conn   net.Conn
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	results := make(chan result, len(STUNServers))
	var wg sync.WaitGroup

	netLower := strings.ToLower(network)
	netProto := "udp"
	if strings.HasPrefix(netLower, "tcp") {
		netProto = "tcp"
	}
	isIPv6 := strings.HasSuffix(netLower, "6")

	resolveAddr := func(proto string) (string, net.Addr, error) {
		var network string
		if proto == "tcp" {
			network = "tcp4"
			if isIPv6 {
				network = "tcp6"
			}
			addr, err := net.ResolveTCPAddr(network, bind)
			return network, addr, err
		}
		network = "udp4"
		if isIPv6 {
			network = "udp6"
		}
		addr, err := net.ResolveUDPAddr(network, bind)
		return network, addr, err
	}

	for i, rawAddr := range STUNServers {
		scheme := ""
		addr := rawAddr

		if strings.HasPrefix(rawAddr, "udp://") {
			scheme = "udp"
			addr = strings.TrimPrefix(rawAddr, "udp://")
		} else if strings.HasPrefix(rawAddr, "tcp://") {
			scheme = "tcp"
			addr = strings.TrimPrefix(rawAddr, "tcp://")
		}

		//选择匹配network的stun服务器
		if scheme != "" && scheme != netProto {
			continue
		}

		wg.Add(1)
		go func(index int, stunAddr string) {
			defer wg.Done()

			// 检查 context 是否已经被取消，避免不必要的拨号
			if ctx.Err() != nil {
				//logSTUN("Err: %s ...\n", stunAddr)
				return
			}

			useNetwork, laddr, err := resolveAddr(netProto)
			if err != nil {
				//logSTUN("stun resolve local addr: %s://%s err: %v\n", useNetwork, stunAddr, err)
				results <- result{err: fmt.Errorf("resolve local addr: %v", err)}
				return
			}

			// 为拨号器创建一个带 context 的超时
			dialer := &net.Dialer{LocalAddr: laddr}
			if strings.HasPrefix(useNetwork, "tcp") {
				dialer.Control = netx.ControlTCP
			} else {
				dialer.Control = netx.ControlUDP
			}

			//logSTUN("stun dial: %s://%s ...\n", useNetwork, stunAddr)
			var conn net.Conn
			if strings.Contains(stunAddr, "?") {
				conn, err = netx.DialRace(ctx, useNetwork, stunAddr, dialer.DialContext)
			} else {
				conn, err = dialer.DialContext(ctx, useNetwork, stunAddr)
			}
			if err != nil {
				//logSTUN("STUN dial failed: %s://%s err: %v\n", useNetwork, stunAddr, err)
				// 如果 context 被取消，错误会是 "context canceled"
				results <- result{err: fmt.Errorf("STUN dial failed: %v", err)}
				return
			}
			//logSTUN("stun dial: %s://%s OK\n", useNetwork, stunAddr)

			//这个conn不能defer Close，后面它可能是要保活的tcp。
			//为了打洞的TCP在程序结束后该端口不出现TIME_WAIT，方便再次复用端口。使用策略：
			// 1）并发多个stun查询的tcp，除了第一个成功的要保留，其他程序主动要关闭的可以SetLinger(0)就不会出现TIME_WAIT。
			// 2）第一个成功stun查询的TCP不主动关闭（主动正常关闭一定会有TIME_WAIT），要用Read等待的方式保活，可以做可以在程序退出时触发系统RST，RST就不会出现TIME_WAIT.
			//    但如果对方主动挥手，可能打开的洞还在通讯，这边被动正常关闭不会TIME_WAIT，不能SetLinger(0)避免RST导致打开的tcp的洞失效。
			// 3) 程序再次重新打洞时，上次第一个成功stun查询的TCP要SetLinger(0)主动关闭

			client, err := stun.NewClient(conn)
			if err != nil {
				//logSTUN("STUN NewClient failed: %s://%s err: %v\n", useNetwork, stunAddr, err)
				conn.Close()
				results <- result{err: fmt.Errorf("STUN NewClient failed: %v", err)}
				return
			}

			var xorAddr stun.XORMappedAddress
			var noneXorAddr stun.MappedAddress
			var callErr error

			req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

			//logSTUN("stun do request: %s://%s\n", useNetwork, stunAddr)

			// client.Do 不直接支持 context，但拨号阶段已经支持了。
			// STUN 请求通常很快，超时主要由外层 context 控制。
			err = client.Do(req, func(e stun.Event) {
				if e.Error != nil {
					callErr = e.Error
				} else if err := xorAddr.GetFrom(e.Message); err != nil {
					// 尝试使用非 XOR-MAPPED-ADDRESS 获取地址（某些 STUN 服务器可能只返回 MAPPED-ADDRESS）
					if err2 := noneXorAddr.GetFrom(e.Message); err2 != nil {
						callErr = err
					} else {
						xorAddr.IP = noneXorAddr.IP
						xorAddr.Port = noneXorAddr.Port
					}
				}
			})

			if err != nil {
				//logSTUN("STUN Do failed: %s://%s err: %v\n", useNetwork, stunAddr, err)
				client.Close() //前面不能用defer Close，要自己Close
				results <- result{err: fmt.Errorf("STUN Do failed: %v", err)}
				return
			}
			if callErr != nil {
				//logSTUN("STUN response error: %s://%s err: %v\n", useNetwork, stunAddr, callErr)
				client.Close()
				results <- result{err: fmt.Errorf("STUN response error: %v", callErr)}
				return
			}

			//logSTUN("stun result: %s://%s(%s) %s\n", useNetwork, stunAddr, conn.RemoteAddr().String(), xorAddr.String())

			// 2. 将成功的结果（包括连接和客户端）发送到 channel
			// 注意：UDP连接是无状态的，不需要保留。TCP连接需要保留用于打洞。
			// 这里我们统一将 client 和 conn 传出，由主循环决定如何处理。
			results <- result{
				index:  i,
				local:  conn.LocalAddr().String(),
				nat:    xorAddr.String(),
				client: client,
				conn:   conn,
			}

		}(i, addr)

		if bind != "" && !strings.HasSuffix(bind, ":0") && strings.HasPrefix(netProto, "udp") {
			//由于UDP SO_REUSEADDR明确端口的话，只有一个能收到回复数据，所以只选第一个可用的stunServer
			break
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// 3. for-select 循环
	for {
		select {
		case <-ctx.Done():
			// 超时或被主动取消。
			// 启动一个 goroutine 来排空 channel，确保所有子 goroutine 都能退出。
			go func() {
				for r := range results {
					// 丢弃所有剩余结果
					if r.client != nil {
						if r.conn != nil {
							if tcpConn, ok := r.conn.(*net.TCPConn); ok {
								tcpConn.SetLinger(0) // 立即关闭，发送 RST
							}
						}
						//logSTUN("stun close: %s\n", r.conn.RemoteAddr().String())
						r.client.Close()
					}
				}
			}()
			return -1, "", "", fmt.Errorf("timeout or cancelled while waiting for STUN response")

		case r, ok := <-results:
			if !ok {
				// Channel 已关闭，说明所有 goroutine 都已执行完毕且无一成功。
				return -1, "", "", fmt.Errorf("all STUN servers failed")
			}

			if r.err == nil {
				// **** 找到第一个成功者 ****

				// a. 立即通知其他 goroutine 停止
				cancel()

				// b. 如果是 TCP，执行保存连接的逻辑
				if netProto == "tcp" {
					lastStunClientLock.Lock()
					if lastStunClient != nil {
						if tcpConn, ok := lastStunClientConn.(*net.TCPConn); ok {
							_ = tcpConn.SetLinger(0)
						}
						lastStunClient.Close()
					}
					// 重要：接管获胜的 client 和 conn，防止它们被 defer client.Close() 关闭
					lastStunClient = r.client
					lastStunClientConn = r.conn
					lastStunClientLock.Unlock()

					// 启动你的连接保活/监听关闭的 goroutine
					go func(tc net.Conn, sc *stun.Client) {
						buf := make([]byte, 1)
						// 这个 Read 会一直阻塞，直到远端关闭连接或发生错误
						_, _ = tc.Read(buf)
						// 读取到数据或错误后，关闭客户端
						sc.Close()
					}(r.conn, r.client)
				} else {
					r.client.Close()
				}

				// c. 启动清理 goroutine，排空 channel，关闭其他可能成功的 TCP 连接
				go func() {
					for otherResult := range results {
						if otherResult.client != nil {
							if otherResult.conn != nil {
								if tcpConn, ok := otherResult.conn.(*net.TCPConn); ok {
									tcpConn.SetLinger(0) // 立即关闭，发送 RST
								}
							}
							//logSTUN("stun close: %s\n", otherResult.conn.RemoteAddr().String())
							otherResult.client.Close()
						}
					}
				}()

				// d. 返回成功结果
				return r.index, r.local, r.nat, nil
			}
			// 如果 r.err != nil，忽略该错误结果，继续等待下一个
		}
	}
}

// STUNResult struct holds the outcome of a single STUN request.
// It's used both internally and as the return type for the function.
type STUNResult struct {
	Index   int // Original index of the STUN server in the input slice
	Network string
	Local   string // Local IP address and port used for the STUN request
	Nat     string // NAT IP address and port returned by the STUN server
	Remote  string // Stun Server address used
	Err     error  // Error, if any, encountered during the STUN request
}

// GetPublicIPs attempts to discover public IP addresses using STUN servers.
// It collects as many unique NAT IP addresses (by IP address only, ignoring port)
// as possible within the specified timeout, and returns all results (unique successful ones and errors).
func GetPublicIPs(network, bind string, timeout time.Duration, natIPUniq bool, shPktCon net.PacketConn) ([]*STUNResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel() // Ensure cancel is called to release context resources

	resultsChan := make(chan STUNResult, len(STUNServers)) // Channel to collect results from goroutines
	var wg sync.WaitGroup                                  // WaitGroup to wait for all goroutines to finish

	netLower := strings.ToLower(network)
	isIPv6 := strings.HasSuffix(netLower, "6")
	netProto := "udp"
	var UDPDialer *netx.UDPSessionDialer
	if strings.HasPrefix(netLower, "tcp") {
		netProto = "tcp"
	} else {
		localAddr, err := net.ResolveUDPAddr("udp", bind)
		if err != nil {
			return nil, err
		}
		basedUDPConn := shPktCon
		if basedUDPConn == nil {
			sharedUDPConn, err := net.ListenUDP("udp", localAddr)
			if err != nil {
				return nil, err
			}
			defer sharedUDPConn.Close()
			basedUDPConn = sharedUDPConn
		}

		logDiscard := misc.NewLog(io.Discard, "[UDPSession] ", log.LstdFlags|log.Lmsgprefix|log.Lshortfile)
		UDPDialer, err = netx.NewUDPSessionDialer(basedUDPConn, false, 4096, logDiscard)
		if err != nil {
			return nil, err
		}
		defer UDPDialer.Close()
	}

	resolveAddr := func(proto string) (string, net.Addr, error) {
		var network string
		if proto == "tcp" {
			network = "tcp4"
			if isIPv6 {
				network = "tcp6"
			}
			addr, err := net.ResolveTCPAddr(network, bind)
			return network, addr, err
		}
		network = "udp4"
		if isIPv6 {
			network = "udp6"
		}
		addr, err := net.ResolveUDPAddr(network, bind)
		return network, addr, err
	}

	for i, rawAddr := range STUNServers {
		scheme := ""
		addr := rawAddr

		// Parse STUN server address scheme
		if strings.HasPrefix(rawAddr, "udp://") {
			scheme = "udp"
			addr = strings.TrimPrefix(rawAddr, "udp://")
		} else if strings.HasPrefix(rawAddr, "tcp://") {
			scheme = "tcp"
			addr = strings.TrimPrefix(rawAddr, "tcp://")
		}

		// Skip STUN servers that don't match the desired network protocol
		if scheme != "" && scheme != netProto {
			continue
		}

		wg.Add(1)
		go func(index int, stunAddr string) {
			defer wg.Done()

			// Check if context is already canceled to avoid unnecessary dialing
			if ctx.Err() != nil {
				return
			}
			var err error

			// Get the network type (e.g., "udp4", "tcp6")
			useNetwork, laddr, err := resolveAddr(netProto)
			if err != nil {
				//logSTUN("stun resolve local addr: %s://%s err: %v\n", useNetwork, stunAddr, err)
				resultsChan <- STUNResult{Index: index, Network: useNetwork, Err: fmt.Errorf("resolveAddr failed: %v", err)}
				return
			}
			var conn net.Conn
			dialer := &net.Dialer{LocalAddr: laddr}
			if strings.HasPrefix(useNetwork, "tcp") {
				dialer.Control = netx.ControlTCP
				if strings.Contains(stunAddr, "?") {
					conn, err = netx.DialRace(ctx, useNetwork, stunAddr, dialer.DialContext)
				} else {
					conn, err = dialer.DialContext(ctx, useNetwork, stunAddr)
				}
			} else {
				if strings.Contains(stunAddr, "?") {
					conn, err = netx.DialRace(ctx, useNetwork, stunAddr, UDPDialer.DialContext)
				} else {
					conn, err = UDPDialer.DialContext(ctx, useNetwork, stunAddr)
				}
			}

			if err != nil {
				resultsChan <- STUNResult{Index: index, Network: useNetwork, Err: fmt.Errorf("STUN dial failed: %v", err)}
				return
			}
			defer conn.Close() // Ensure connection is closed when the goroutine finishes

			// For TCP connections, set linger to 0 for immediate close
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetLinger(0)
			}

			client, err := stun.NewClient(conn)
			if err != nil {
				resultsChan <- STUNResult{Index: index, Network: useNetwork, Err: fmt.Errorf("STUN NewClient failed: %v", err)}
				return
			}
			defer client.Close() // Ensure client is closed when the goroutine finishes

			var xorAddr stun.XORMappedAddress
			var noneXorAddr stun.MappedAddress
			var callErr error

			req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

			err = client.Do(req, func(e stun.Event) {
				if e.Error != nil {
					callErr = e.Error
				} else if err := xorAddr.GetFrom(e.Message); err != nil {
					// 尝试使用非 XOR-MAPPED-ADDRESS 获取地址（某些 STUN 服务器可能只返回 MAPPED-ADDRESS）
					if err2 := noneXorAddr.GetFrom(e.Message); err2 != nil {
						callErr = err
					} else {
						xorAddr.IP = noneXorAddr.IP
						xorAddr.Port = noneXorAddr.Port
					}
				}
			})

			if err != nil {
				resultsChan <- STUNResult{Index: index, Network: useNetwork, Err: fmt.Errorf("STUN Do failed: %v", err)}
				return
			}
			if callErr != nil {
				resultsChan <- STUNResult{Index: index, Network: useNetwork, Err: fmt.Errorf("STUN response error: %v", callErr)}
				return
			}

			// Send the successful result to the channel
			resultsChan <- STUNResult{
				Index:   index,
				Network: useNetwork,
				Local:   conn.LocalAddr().String(),
				Nat:     xorAddr.String(),
				Remote:  conn.RemoteAddr().String(),
				Err:     nil,
			}

		}(i, addr)

		// The UDP SO_REUSEADDR optimization is no longer necessary as we are not binding to a fixed port.
		// Each dial will get a new random ephemeral port.
	}

	// Goroutine to close the results channel once all workers are done
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// --- Collect and filter results ---
	collectedResults := make([]*STUNResult, 0)
	// Use a map to track unique NAT IP addresses (excluding port)
	uniqueNatIPs := make(map[string]bool)

	for {
		select {
		case <-ctx.Done():
			// Timeout or cancelled. Process collected results and exit.
			// Drain the channel to ensure all goroutines can finish (and their defers run).
			go func() {
				for range resultsChan {
					// Simply drain; defers in goroutines handle connection/client closure
				}
			}()
			if len(collectedResults) > 0 {
				return collectedResults, nil
			} else {
				return nil, ctx.Err() // Return collected results and the context error
			}

		case r, ok := <-resultsChan:
			if !ok {
				// Channel closed, all goroutines finished.
				// Return the collected unique results.
				return collectedResults, nil
			}

			if r.Err == nil {
				// Successfully got a STUN result.
				// Extract the NAT IP address without the port for uniqueness check.
				natIP, _, err := net.SplitHostPort(r.Nat)
				if err != nil {
					// Handle cases where nat string might not be a valid host:port
					// If SplitHostPort fails, assume the whole string is the IP for uniqueness.
					natIP = r.Nat
				}
				_, found := uniqueNatIPs[natIP]
				if !natIPUniq || !found {
					// This NAT IP is unique, add it to our collection.
					uniqueNatIPs[natIP] = true
					collectedResults = append(collectedResults, &STUNResult{
						Index:   r.Index,
						Network: r.Network,
						Local:   r.Local,
						Nat:     r.Nat,
						Remote:  r.Remote,
						Err:     nil, // No error for successful results
					})
				}
			} else {
				_, found := uniqueNatIPs[""]
				if !natIPUniq || !found {
					// If there's an error, still create one STUNResult for it.
					collectedResults = append(collectedResults, &STUNResult{
						Index:   r.Index,
						Network: r.Network,
						Local:   r.Local,
						Nat:     r.Nat, // Might be empty or partial if error occurred early
						Remote:  r.Remote,
						Err:     r.Err,
					})
				}
			}
		}
	}
}

// GetFreePort 尝试找到一个可同时绑定 TCP 和 UDP 的端口
func GetFreePort() (int, error) {
	const maxTry = 100

	for i := 0; i < maxTry; i++ {
		// 绑定 TCP 端口
		tcpListener, err := net.Listen("tcp", ":0")
		if err != nil {
			return 0, fmt.Errorf("TCP listen failed: %v", err)
		}

		// 获取系统分配的端口
		addr := tcpListener.Addr().(*net.TCPAddr)
		port := addr.Port

		// 尝试绑定相同端口的 UDP
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
		if err != nil {
			tcpListener.Close()
			return 0, fmt.Errorf("ResolveUDPAddr failed: %v", err)
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err == nil {
			// 成功，关闭后返回端口
			udpConn.Close()
			tcpListener.Close()
			return port, nil
		}

		// UDP 绑定失败，关闭 TCP 后继续尝试
		tcpListener.Close()
	}

	return 0, fmt.Errorf("no free TCP/UDP ports available")
}

func GetNetworksPublicIPs(networkList []string, bind string, timeout time.Duration, shPktCon net.PacketConn) ([]*STUNResult, error) {
	var wg sync.WaitGroup
	resultsChan := make(chan []*STUNResult, len(networkList))
	errorsChan := make(chan error, len(networkList))
	bindUnspecified := false
	if bind == "" {
		bindUnspecified = true
		port, err := GetFreePort()
		if err != nil {
			return nil, err
		}
		bind = fmt.Sprintf(":%d", port)
	} else if strings.HasSuffix(bind, ":0") {
		host, _, err := net.SplitHostPort(bind)
		if err != nil {
			return nil, fmt.Errorf("invalid bind address: %v", err)
		}
		port, err := GetFreePort()
		if err != nil {
			return nil, err
		}
		bind = net.JoinHostPort(host, fmt.Sprintf("%d", port))
	}

	udpAttemptNumber := 0
	for _, network := range networkList {
		bindAddrCandidate := bind
		if shPktCon != nil {
			if !strings.HasPrefix(network, "udp") {
				continue
			}
			// PacketConn 只支持 UDP
		} else {
			if udpAttemptNumber > 0 && bindUnspecified {
				//并发的时候，除非第一个的udp需要调整端口，
				//例如第一个GetPublicIPs(udp6，5555)成功接着GetPublicIPs(udp4, 5555)就无法绑定这个端口了
				port, err := GetFreePort()
				if err == nil {
					bindAddrCandidate = fmt.Sprintf(":%d", port)
				}
			}
		}
		if strings.HasPrefix(network, "udp") {
			udpAttemptNumber += 1
		}
		wg.Add(1)
		go func(network string) {
			defer wg.Done()
			results, err := GetPublicIPs(network, bindAddrCandidate, timeout, false, shPktCon)
			if err != nil {
				errorsChan <- fmt.Errorf("network %s: %v", network, err)
				return
			}
			resultsChan <- results
		}(network)
	}

	wg.Wait()
	close(resultsChan)
	close(errorsChan)

	// Collect and display results
	var allResults []*STUNResult
	for results := range resultsChan {
		allResults = append(allResults, results...)
	}

	if len(allResults) == 0 {
		return nil, fmt.Errorf("no public IP addresses found or all attempts failed")
	} else {
		return allResults, nil
	}
}

type AnalyzedStunResult struct {
	NATType string `json:"nattype"` // "easy", "hard", "symm"
	Network string `json:"network"`
	LAN     string `json:"lan"`
	NAT     string `json:"nat"`
}

// NatIPLocalKey serves as a key to group results by NAT IP and local address,
// to check port consistency for 'hard' vs 'symm' behavior within a specific NAT IP.
type NatIPLocalKey struct {
	Network string
	Local   string
	NATIP   string // Only NAT IP part
}

func succeededSTUNResults(allResults []*STUNResult) int {
	succeed := 0
	for _, r := range allResults {
		if r.Err != nil {
			continue // Only analyze successful results
		}
		succeed += 1
	}
	return succeed
}

// analyzeSTUNResults analyzes the collected STUN results to determine NAT types
// based on the user's specific logic (primarily port consistency).
func analyzeSTUNResults(allResults []*STUNResult) []*AnalyzedStunResult {
	// Group all successful results by (Network, Local IP:Port)
	groupedByNetworkLocal := make(map[NatIPLocalKey][]*STUNResult)
	for _, r := range allResults {
		if r.Err != nil {
			continue // Only analyze successful results
		}
		natIP, _, _ := net.SplitHostPort(r.Nat)

		key := NatIPLocalKey{Network: r.Network, Local: r.Local, NATIP: natIP}
		groupedByNetworkLocal[key] = append(groupedByNetworkLocal[key], r)
	}

	var analyzedOutputs []*AnalyzedStunResult

	for key, results := range groupedByNetworkLocal {
		if len(results) == 0 {
			continue
		}
		_, lanPortStr, _ := net.SplitHostPort(key.Local)
		_, natPortStr, _ := net.SplitHostPort(results[0].Nat)
		seenPorts := make(map[string]struct{})

		for _, r := range results {
			_, portStr, _ := net.SplitHostPort(r.Nat)
			seenPorts[portStr] = struct{}{}
		}

		if len(results) == 1 {
			if lanPortStr == natPortStr {
				analyzedOutputs = append(analyzedOutputs, &AnalyzedStunResult{
					NATType: "easy",
					Network: key.Network,
					LAN:     key.Local,
					NAT:     results[0].Nat,
				})
			} else {
				analyzedOutputs = append(analyzedOutputs, &AnalyzedStunResult{
					NATType: "hard",
					Network: key.Network,
					LAN:     key.Local,
					NAT:     results[0].Nat,
				})
			}

		} else {
			if len(seenPorts) == 1 {
				if lanPortStr == natPortStr {
					analyzedOutputs = append(analyzedOutputs, &AnalyzedStunResult{
						NATType: "easy",
						Network: key.Network,
						LAN:     key.Local,
						NAT:     results[0].Nat,
					})
				} else {
					analyzedOutputs = append(analyzedOutputs, &AnalyzedStunResult{
						NATType: "hard",
						Network: key.Network,
						LAN:     key.Local,
						NAT:     results[0].Nat,
					})
				}
			} else {
				analyzedOutputs = append(analyzedOutputs, &AnalyzedStunResult{
					NATType: "symm",
					Network: key.Network,
					LAN:     key.Local,
					NAT:     results[0].Nat,
				})
			}
		}
	}

	return analyzedOutputs
}

// func logSTUN(format string, v ...interface{}) {
// 	now := time.Now()
// 	ts := now.Format("15:04:05.000")
// 	args := append([]interface{}{ts}, v...)
// 	fmt.Fprintf(os.Stderr, "[%s] [STUN] "+format+"\n", args...)
// }
