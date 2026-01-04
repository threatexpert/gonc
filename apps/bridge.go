package apps

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/threatexpert/gonc/v2/easyp2p"
	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
	"github.com/threatexpert/gonc/v2/secure"
)

// ==========================================
// Section 1: Configuration & Flags
// ==========================================

type AppBridgeConfig struct {
	ncconfig *AppNetcatConfig
}

// AppBridgeConfigByArgs 解析给定的 []string 参数，生成 AppBridgeConfig
func AppBridgeConfigByArgs(logWriter io.Writer, args []string) (*AppBridgeConfig, error) {
	// 由于bridge的功能都可以调用nc的功能实现，所以这里直接调用AppNetcatConfigByArgs进行解析
	config := &AppBridgeConfig{}
	var err error
	config.ncconfig, err = AppNetcatConfigByArgs(logWriter, ":br", args)
	if err != nil {
		return nil, err // 解析错误直接返回
	}
	config.ncconfig.Logger = misc.NewLog(logWriter, "[:br] ", log.LstdFlags|log.Lmsgprefix)
	config.ncconfig.ConsoleMode = false
	config.ncconfig.progressEnabled = false

	//但:br限定两种模式：
	// 1：p2p + mqtt hello
	// 2：dial模式
	//搭桥

	if config.ncconfig.useMQTTHello && config.ncconfig.p2pSessionKey != "" && len(config.ncconfig.featureModulesRun) == 0 {
		//这是模式1
		config.ncconfig.keepOpen = true
	} else if !config.ncconfig.listenMode && config.ncconfig.p2pSessionKey == "" && len(config.ncconfig.featureModulesRun) == 0 {
		//这是模式2
		config.ncconfig.keepOpen = false
		config.ncconfig.localbind = ""
		config.ncconfig.localbindIP = ""
	} else {
		return nil, fmt.Errorf("bridge mode requires dial mode when not using mqtt hello")
	}

	return config, nil
}

// ==========================================
// Section 2: Session Cache (For Mode 2)
// ==========================================

type cachedSession struct {
	localBind string
	expiry    time.Time
	conn      net.Conn      // 当前活跃的目标连接，用于强制关闭（踢出会话）或复用
	done      chan struct{} // 会话结束信号，用于等待旧会话完全退出
}

var (
	brDialSessCache    sync.Map // map[string]cachedSession
	brAcceptSessCache  sync.Map // map[string]string
	brConnCache        sync.Map // map[Int64]net.Conn
	brConnLastId       atomic.Int64
	startOnceForBridge sync.Once
)

func brRegisterConn(conn net.Conn) int64 {
	id := brConnLastId.Add(1)
	brConnCache.Store(id, conn)
	return id
}

func brStartConnDebugHTTP() (listenAddr string, err error) {
	var ln net.Listener

	for port := 8800; port < 9000; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			listenAddr = addr
			break
		}
	}
	if ln == nil {
		return "", fmt.Errorf("no available port in range 8800-8899")
	}

	mux := http.NewServeMux()

	// GET /conns
	mux.HandleFunc("/conns", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		type ConnInfo struct {
			ID     int64  `json:"id"`
			Local  string `json:"local"`
			Remote string `json:"remote"`
		}

		var list []ConnInfo

		brConnCache.Range(func(key, value any) bool {
			id, ok1 := key.(int64)
			conn, ok2 := value.(net.Conn)
			if ok1 && ok2 && conn != nil {
				list = append(list, ConnInfo{
					ID:     id,
					Local:  conn.LocalAddr().String(),
					Remote: conn.RemoteAddr().String(),
				})
			}
			return true
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	})

	// GET /close?id=123
	mux.HandleFunc("/close", func(w http.ResponseWriter, r *http.Request) {

		idStr := r.URL.Query().Get("id")
		if idStr == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}

		v, ok := brConnCache.Load(int64(id))
		if !ok {
			http.Error(w, "conn not found", http.StatusNotFound)
			return
		}

		conn := v.(net.Conn)

		// 触发 read unblock + close
		_ = conn.SetReadDeadline(time.Now())
		_ = conn.Close()

		brConnCache.Delete(int64(id))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	go func() {
		_ = http.Serve(ln, mux)
	}()

	return listenAddr, nil
}

// 定期清理过期的 session
func brSessCacheCleanRoutine() {
	for {
		time.Sleep(1 * time.Minute)
		now := time.Now()
		brDialSessCache.Range(func(key, value interface{}) bool {
			if s, ok := value.(cachedSession); ok {
				// [Modified] 清理逻辑：如果超时，强制关闭连接并删除
				if s.done == nil {
					if now.After(s.expiry) {
						if s.conn != nil {
							s.conn.Close()
						}
						brDialSessCache.Delete(key)
					}
				}
			}
			return true
		})
	}
}

func brDialSessKickByConnAddr(localStr, remoteStr string) bool {
	var found bool

	brDialSessCache.Range(func(key, value any) bool {
		s, ok := value.(cachedSession)
		if !ok || s.conn == nil {
			return true
		}

		// 匹配 local / remote 地址
		if s.conn.LocalAddr().String() == localStr &&
			s.conn.RemoteAddr().String() == remoteStr {

			// 触发 read unblock
			_ = s.conn.SetReadDeadline(time.Now())
			_ = s.conn.Close()

			found = true
			return false // 停止 Range
		}

		return true
	})

	return found
}

func brAcceptSessKickByConnAddr(localStr, remoteStr string) bool {
	sesskey := fmt.Sprintf("%s-%s", localStr, remoteStr)
	var deleted bool
	brAcceptSessCache.Range(func(key, value any) bool {
		if deleted {
			return false
		}
		if v, ok := value.(string); ok && v == sesskey {
			brAcceptSessCache.Delete(key)
			deleted = true
			return false
		}
		return true
	})
	return deleted
}

func Bridge_IsP2PHelloAllowed(MQTTHelloAppPayload string) bool {
	parts := strings.Split(MQTTHelloAppPayload, "#")
	if len(parts) != 2 {
		return false
	}
	sessid := parts[0]
	count, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	if count > 1 {
		// ask to resume
		_, ok := brDialSessCache.Load(sessid)
		if !ok {
			//not found for resume. rejected
			return false
		}
	}

	return true
}

// ==========================================
// Section 3: Main Logic
// ==========================================
func App_Bridge_main_withconfig(sess net.Conn, MQTTHelloAppPayload string, ncconfig *AppNetcatConfig, config *AppBridgeConfig) {

	startOnceForBridge.Do(func() {
		go brSessCacheCleanRoutine()

		if os.Getenv("BR_DEBUG") != "" {
			addr, err := brStartConnDebugHTTP()
			if err != nil {
				log.Fatal(err)
			}
			config.ncconfig.Logger.Println("conn debug http listening on", addr)
		}
	})

	defer sess.Close()

	if config.ncconfig.framedStdio {
		sess = netx.NewFramedConn(sess, sess)
	}

	if config.ncconfig.useMQTTHello {
		// --- 模式1: P2P Client (Initiator) ---
		// 逻辑: 建立 P2P 连接 -> 发送握手信息 -> 等待确认 -> 转发数据

		//生成一个sessid，用于恢复会话
		sessid_L8 := secure.GenerateSeededRandomString(8, secure.MakeSeed())
		//只有在第一次建立成功后，sessid才标志为激活
		sessid_actived := false
		max_errors := 4
		times_tried := 0
		round := 0
		sessidround := ""
		sesskey := fmt.Sprintf("%s-%s", sess.LocalAddr().String(), sess.RemoteAddr().String())

		brAcceptSessCache.Store(sessid_L8, sesskey)
		defer func() {
			brAcceptSessCache.Delete(sessid_L8)
		}()

		for {
			if times_tried >= max_errors {
				ncconfig.Logger.Printf("Bridge(%s) failed after %d attempts.", sessid_L8, max_errors)
				return
			}

			if _, ok := brAcceptSessCache.Load(sessid_L8); !ok {
				ncconfig.Logger.Printf("Bridge(%s) aborted.", sessid_L8)
				return
			}

			if sessid_actived {
				sessidround = fmt.Sprintf("%s#%d", sessid_L8, round+1)
			} else {
				//未激活sessid前，一直发送1，表示首次建立
				sessidround = fmt.Sprintf("%s#1", sessid_L8)
			}
			config.ncconfig.MQTTHelloPayload = easyp2p.HelloPayload{
				App:   "br",
				Param: sessidround,
			}

			round += 1

			ncconfig.Logger.Printf("Establishing Bridge(%s) ...", sessidround)

			// 1. 建立 P2P 连接
			nconn, err := do_P2P(config.ncconfig)
			if err != nil {
				ncconfig.Logger.Printf("P2P connection failed: %v", err)
				ncconfig.Logger.Printf("Will retry in 10 seconds...")
				time.Sleep(10 * time.Second)
				times_tried += 1
				continue
			}

			cid := brRegisterConn(nconn)

			sessid_actived = true
			times_tried = 1 // reset on success

			ncconfig.Logger.Printf("Bridge(%s) established via P2P. Forwarding...", sessidround)

			// 记录开始时间，用于判断是否是闪断
			start := time.Now()
			sess.SetReadDeadline(time.Time{})
			bidirectionalCopy2(config.ncconfig, sess, nconn)
			nconn.Close()
			brConnCache.Delete(cid)
			duration := time.Since(start)

			if duration < 2*time.Second {
				ncconfig.Logger.Printf("Bridge(%s) closed too quickly (%v). Stopping bridge.", sessidround, duration)
				return
			}

			ncconfig.Logger.Printf("Bridge(%s) Connection lost after %v. Retrying in 1 second...", sessidround, duration)
			time.Sleep(1 * time.Second)
		}
	} else {
		// --- 模式2: Receiver (Dialer) ---
		// sess 是 P2P 建立进来的连接

		cid := brRegisterConn(sess)
		defer brConnCache.Delete(cid)

		bridgeinfo := MQTTHelloAppPayload
		ncconfig.Logger.Printf("Received bridge info: %s", bridgeinfo)

		// 2. 解析 sessid 和 序号
		parts := strings.Split(bridgeinfo, "#")
		if len(parts) != 2 {
			ncconfig.Logger.Printf("Invalid handshake format")
			return
		}
		sessid := parts[0]
		count, err := strconv.Atoi(parts[1])
		if err != nil {
			ncconfig.Logger.Printf("Invalid retry count: %v", err)
			return
		}

		localbind := config.ncconfig.localbind
		var targetConn net.Conn

		// 3. 检查缓存与 Session 冲突/复用处理
		if oldVal, ok := brDialSessCache.Load(sessid); ok {
			oldSess := oldVal.(cachedSession)

			if count > 1 {
				// --- Resume Logic ---
				// 尝试复用 active connection (支持 TCP/UDP)
				if oldSess.conn != nil {
					ncconfig.Logger.Printf("Resuming session %s, Kicking old handler...", sessid)
					// 踢出会话：设置 ReadDeadline 让旧的 bidirectionalCopy2 退出
					oldSess.conn.SetReadDeadline(time.Now())

					// 等待旧会话退出，释放控制权
					if oldSess.done != nil {
						select {
						case <-oldSess.done:
							ncconfig.Logger.Printf("Previous session(%s) detached.", sessid)
						case <-time.After(5 * time.Second):
							ncconfig.Logger.Printf("Warning: Timeout waiting for previous session(%s) detach..", sessid)
							return
						}
					}

					// 复位 Deadline
					oldSess.conn.SetReadDeadline(time.Time{})
					targetConn = oldSess.conn
				} else {
					// 缓存里没有 conn 对象
					ncconfig.Logger.Printf("Session %s not found for resume. rejected", sessid)
					return
				}
			} else {
				// --- Collision Logic (Count <= 1 but cache exists) ---
				ncconfig.Logger.Printf("New session %s collision, closing old session...", sessid)
				if oldSess.conn != nil {
					oldSess.conn.SetReadDeadline(time.Now())
					oldSess.conn.Close() // 强制关闭旧连接
				}
				if oldSess.done != nil {
					select {
					case <-oldSess.done:
					case <-time.After(5 * time.Second):
						return
					}
				}
			}
		} else if count > 1 {
			ncconfig.Logger.Printf("Session %s not found for resume. rejected", sessid)
			return
		}

		// 4. 如果没有复用到连接，建立新连接
		if targetConn == nil {
			var err error
			targetConn, err = dialWithLocalBind(config.ncconfig.network, config.ncconfig.host, config.ncconfig.port, localbind)
			if err != nil {
				ncconfig.Logger.Printf("Dial target failed: %v", err)
				return
			}
			ncconfig.Logger.Printf("Dialed new target: %s -> %s", targetConn.LocalAddr(), targetConn.RemoteAddr())
		} else {
			ncconfig.Logger.Printf("Reusing existing target connection(%s): %s-> %s", sessid, targetConn.LocalAddr(), targetConn.RemoteAddr())
		}

		// 创建当前会话的结束信号
		sessionDone := make(chan struct{})

		// 更新缓存: 无论新旧连接，都更新 active conn 和 done channel
		brDialSessCache.Store(sessid, cachedSession{
			localBind: targetConn.LocalAddr().String(),
			expiry:    time.Now().Add(3 * time.Minute),
			conn:      targetConn,
			done:      sessionDone,
		})

		// 确保函数退出时关闭 done channel，通知等待者
		defer close(sessionDone)

		ncconfig.Logger.Printf("Bridge(%s) connected to target. Forwarding...", bridgeinfo)

		// 执行转发
		bidirectionalCopy2(config.ncconfig, targetConn, sess)
		ncconfig.Logger.Printf("Bridge(%s) finished.", bridgeinfo)

		brDialSessCache.Store(sessid, cachedSession{
			localBind: targetConn.LocalAddr().String(),
			expiry:    time.Now().Add(3 * time.Minute), // 刷新有效期
			conn:      targetConn,                      // 保持连接对象
			done:      nil,                             // 当前处理协程退出，done 会在 defer 中关闭，cache 里置空 done 表示没有活跃协程
		})
	}
}

// dialWithLocalBind 根据参数建立到目标的连接 (支持 TCP/UDP)
func dialWithLocalBind(network, host, port, localbind string) (net.Conn, error) {
	var localAddr net.Addr
	var err error

	// [Modified] 移除 UDP 前缀检查，支持 TCP
	if localbind != "" {
		if strings.HasPrefix(network, "udp") {
			localAddr, err = net.ResolveUDPAddr(network, localbind)
		} else if strings.HasPrefix(network, "tcp") {
			localAddr, err = net.ResolveTCPAddr(network, localbind)
		}
		if err != nil {
			return nil, fmt.Errorf("resolve localbind failed: %v", err)
		}
	}

	dialer := &net.Dialer{}
	if localAddr != nil {
		dialer.LocalAddr = localAddr
		if strings.HasPrefix(network, "udp") {
			dialer.Control = netx.ControlUDP // 地址复用
		} else if strings.HasPrefix(network, "tcp") {
			dialer.Control = netx.ControlTCP
		}
	}

	targetAddr := net.JoinHostPort(host, port)
	conn, err := dialer.Dial(network, targetAddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %v", targetAddr, err)
	}

	//只考虑实现本地的搭桥，忽略-tls等其他协议层（忽略secure.DoNegotiation），
	//BUG：安全协议层目前返回的conn（UDP）已知存在无法SetReadDeadline(time.Now())通知立刻退出问题

	return conn, nil
}

func bidirectionalCopy2(ncconfig *AppNetcatConfig, local net.Conn, stream net.Conn) {
	//不关闭local

	var bufsize int = 32 * 1024
	var blocksize int = bufsize

	var wg sync.WaitGroup
	wg.Add(2)

	// 1: local -> stream
	go func() {
		defer wg.Done()
		IsUDP := strings.HasPrefix(local.LocalAddr().Network(), "udp")
		err := copyWithProgress(ncconfig, stream, local, blocksize, !IsUDP, nil, 0)
		ncconfig.Logger.Printf("Bridge direction local -> stream closed: %v", err)
		stream.Close()
	}()
	// 2: stream -> local
	go func() {
		defer wg.Done()
		IsUDP := strings.HasPrefix(stream.LocalAddr().Network(), "udp")
		err := copyWithProgress(ncconfig, local, stream, bufsize, !IsUDP, nil, 0)
		ncconfig.Logger.Printf("Bridge direction stream -> local closed: %v", err)
		local.SetReadDeadline(time.Now())
	}()
	wg.Wait()
	stream.Close()
}
