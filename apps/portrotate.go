package apps

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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

type AppPortRotateConfig struct {
	RotationTrafficLimit uint64 //触发Rotate的条件，表示传输数据量达到多少字节后进行Rotate
	isRotating           int32  // 0 = not rotating
	Period               uint   //触发Rotate的条件，单位秒，表示数据通道建立的时间周期
	HttpAddr             string // 本地HTTP管理接口地址
	ncconfig             AppNetcatConfig
	ncconfigCopied       bool
	stats_in             *misc.ProgressStats
	stats_out            *misc.ProgressStats
	Logger               *log.Logger
}

// AppPortRotateConfigByArgs 解析给定的 []string 参数，生成 AppPortRotateConfig
func AppPortRotateConfigByArgs(logWriter io.Writer, args []string) (*AppPortRotateConfig, error) {
	config := &AppPortRotateConfig{
		Logger: misc.NewLog(logWriter, "[:pr] ", log.LstdFlags|log.Lmsgprefix),
	}

	// 创建一个新的 FlagSet 实例
	fs := flag.NewFlagSet("AppPortRotateConfig", flag.ContinueOnError)
	fs.SetOutput(logWriter)
	fs.UintVar(&config.Period, "period", 0, "Rotation interval in seconds")
	fs.StringVar(&config.HttpAddr, "http", "", "Local HTTP server address for management (e.g. :8080)")
	strRotationTrafficLimit := ""
	// 默认值改为 0
	fs.StringVar(&strRotationTrafficLimit, "rotate-bytes", "0", "Rotate connection after transferring specified bytes (e.g., 10MB, 1GB)")

	// 设置自定义的 Usage 函数
	fs.Usage = func() {
		App_PortRotate_usage_flagSet(fs)
	}

	// 解析传入的 args 切片
	err := fs.Parse(args)
	if err != nil {
		return nil, err // 解析错误直接返回
	}

	// 检查是否有未解析的（非标志）参数
	if len(fs.Args()) > 0 {
		return nil, fmt.Errorf("unknown positional arguments: %v", fs.Args())
	}

	config.RotationTrafficLimit, err = misc.ParseSize(strRotationTrafficLimit)
	if err != nil {
		return nil, err // 解析错误直接返回
	}

	// 自动补全 HTTP 地址
	if config.HttpAddr != "" && !strings.Contains(config.HttpAddr, ":") {
		config.HttpAddr = "127.0.0.1:" + config.HttpAddr
	}

	return config, nil
}

// App_PortRotate_usage_flagSet 接受一个 *flag.FlagSet 参数，用于打印其默认用法信息
func App_PortRotate_usage_flagSet(fs *flag.FlagSet) {
	fmt.Fprintln(fs.Output(), ":pr Usage: [options]")
	fmt.Fprintln(fs.Output(), "\nOptions:")
	fs.PrintDefaults() // 打印所有定义的标志及其默认值和说明
	fmt.Fprintln(fs.Output(), "\nExample:")
	fmt.Fprintln(fs.Output(), "  :pr -period 300 -rotate-bytes 500MB -http 8080")
}

// ==========================================
// Section 2: Main Logic
// ==========================================

func App_PortRotate_main_withconfig(controlConn net.Conn, nconnConfig *secure.NegotiationConfig, ncconfig *AppNetcatConfig, config *AppPortRotateConfig) {
	// 注意：controlConn 的关闭操作已移交给 RotateController 管理，这里不再直接 defer close

	config.Logger.Printf("PortRotate Starts")

	// 定义退出信号，用于清理监听错误的主协程
	mainDone := make(chan struct{})
	defer close(mainDone)

	// 关闭控制通道的进度条信息，如果有需要，应该开启数据通道的进度条
	ncconfig.sessionReady = false

	if !config.ncconfigCopied {
		config.ncconfig = *ncconfig
		config.ncconfigCopied = true
		config.ncconfig.remoteCall = ""
		config.ncconfig.runCmd = ":mux"
		config.ncconfig.goroutineConnectionCounter = 0
		config.stats_in = misc.NewProgressStats()
		config.stats_out = misc.NewProgressStats()

		if config.ncconfig.progressEnabled {
			wg := &sync.WaitGroup{}
			done := make(chan bool)
			showProgress(&config.ncconfig, config.stats_in, config.stats_out, done, wg)
			defer func() {
				done <- true
				wg.Wait()
			}()
		}
	}
	config.ncconfig.sessionReady = false

	bridge, err := netx.NewBridge()
	if err != nil {
		config.Logger.Printf("NewBridge failed: %v", err)
		controlConn.Close()
		return
	}
	// 确保退出时释放 bridge 资源 (包括内部的 UDP 端口监听)
	defer bridge.Close()

	// 初始化数据 ID 和流量记录
	// 使用 atomic 保证多协程访问安全
	var dataSessId int32 = 1
	var lastRotationTraffic uint64 = bridge.TotalTraffic

	// 建立初始数据连接
	// 初始连接使用配置中的默认网络类型 (空字符串表示不覆盖)
	connC, err := makeP2PDataSession(config, int(dataSessId), "")
	if err != nil {
		config.Logger.Printf("makeP2PDataSession failed: %v", err)
		controlConn.Close()
		return
	}

	bridge.SetForwarder(connC)

	secureConfig := *ncconfig.connConfig
	secureConfig.IsClient = nconnConfig.IsClient
	secureConfig.KcpWithUDP = true
	secureConfig.Key = nconnConfig.Key
	secureConfig.KeyType = nconnConfig.KeyType
	if secureConfig.KeyType == "ECDHE" {
		secureConfig.SecureLayer = "dss"
	} else {
		secureConfig.SecureLayer = "dtls"
	}

	secureDataSess, err := secure.DoNegotiation(&secureConfig, bridge.B, ncconfig.LogWriter)
	if err != nil {
		config.Logger.Printf("DoNegotiation failed: %v", err)
		controlConn.Close()
		return
	}
	// 确保退出时关闭上层连接
	defer secureDataSess.Close()

	config.Logger.Printf("PortRotate data connection is ready")

	// --- 控制器与事件处理器初始化 ---

	// 定义业务处理器，用于处理 RotateController 回调的事件
	handler := &rotateBusinessHandler{
		ncconfig:               &config.ncconfig,
		bridge:                 bridge,
		config:                 config, // 注入配置指针，以便在同步时修改
		dataSessIdPtr:          &dataSessId,
		lastRotationTrafficPtr: &lastRotationTraffic,
		controlConn:            controlConn,
		errCh:                  make(chan error, 1),
		pendingRotations:       make(map[int]*rotateState),
		receiverPending:        make(map[int]net.Conn),
	}

	// 创建控制器
	// 注意：这里传给 NewRotateController 的 config 是值拷贝，仅用于发送给对端初始配置
	// 后续 handler.OnConfigSynced 修改的是上面的 config 指针指向的内存，即主循环使用的配置
	ctrl := NewRotateController(controlConn, nconnConfig.IsClient, *config, handler)
	handler.ctrl = ctrl // 相互引用

	// 启动控制器 (开始 Ping/Pong 和 ReadLoop)
	ctrl.Start()
	defer ctrl.Stop()

	// --- 启动 HTTP 服务 (如果配置了) ---
	if config.HttpAddr != "" {
		go handler.StartHTTPServer(config.HttpAddr)
		// 重要：退出时必须停止 HTTP Server，释放端口
		defer handler.StopHTTPServer()
	}

	// --- 错误监控 ---
	go func() {
		// 监听 Bridge 错误
		select {
		case err := <-bridge.ErrCh:
			if err != nil {
				config.Logger.Printf("BridgeConn fatal error received: %v. Shutting down.", err)
				secureDataSess.Close()
				ctrl.Stop()
			}
		case err := <-handler.errCh:
			// 监听 Controller 错误
			if err != nil {
				config.Logger.Printf("ControlConn fatal error: %v. Shutting down.", err)
				secureDataSess.Close()
				// ctrl 已经停止或正在停止
			}
		case <-mainDone:
			// 重要：主程序退出时，清理此监控协程
			return
		}
	}()

	// --- Client 端的主动轮转逻辑 (定时器) ---
	go func() {
		if !nconnConfig.IsClient {
			return // Server 端只需等待命令，不需要主动检查
		}

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		lastRotateTime := time.Now()

		for {
			select {
			case <-ctrl.closeCh:
				return // 控制器关闭，退出循环
			case <-ticker.C:
				// [Fix] 如果正在轮转中，直接跳过检测，避免日志刷屏 "Traffic limit reached" -> "Skipped"
				if atomic.LoadInt32(&config.isRotating) > 0 {
					continue
				}

				shouldRotate := false

				// 获取当前的配置值（可能已被同步逻辑更新）
				// Period 为 uint，在大多数架构上赋值是原子的，或者在启动初期竞争风险极低，直接读取
				currentPeriod := config.Period
				// Limit 为 uint64，在32位系统上可能非原子，使用 atomic 读取
				currentLimit := atomic.LoadUint64(&config.RotationTrafficLimit)

				// 1. 检查时间周期
				if currentPeriod > 0 && time.Since(lastRotateTime).Seconds() > float64(currentPeriod) {
					config.Logger.Printf("[Trigger] Period limit reached (%ds).", currentPeriod)
					shouldRotate = true
				}

				// 2. 检查流量限制
				currentTotal := bridge.TotalTraffic
				last := atomic.LoadUint64(&lastRotationTraffic)
				// 防止 currentTotal 小于 last (虽然一般递增，但防溢出回绕)
				if currentTotal >= last {
					delta := currentTotal - last
					if currentLimit > 0 && delta > currentLimit {
						// 使用 formatBytes 使日志更易读
						config.Logger.Printf("[Trigger] Traffic limit reached: %s > %s",
							formatBytes(delta), formatBytes(currentLimit))
						shouldRotate = true
					}
				}

				if shouldRotate {
					lastRotateTime = time.Now()
					// 调用 Handler 的触发逻辑 (与 HTTP 触发逻辑共用)
					// 定时器触发默认使用空 network，即沿用配置
					handler.TriggerRotation("Timer", "")
				}
			}
		}
	}()

	config.ncconfig.sessionReady = true
	handleNegotiatedConnection(&misc.ConsoleIO{}, &config.ncconfig, secureDataSess, config.stats_in, config.stats_out)
	handler.Clear()
	config.Logger.Printf("PortRotate ends")
}

func makeP2PDataSession(config *AppPortRotateConfig, id int, networkOverride string) (net.Conn, error) {

	defer atomic.AddInt32(&config.isRotating, -1)
	atomic.AddInt32(&config.isRotating, 1)

	// 确定使用的协议：如果有 Override 则使用，否则使用配置的默认值
	targetNetwork := config.ncconfig.network
	if networkOverride != "" {
		targetNetwork = networkOverride
	}

	config.Logger.Printf("Making P2P data session with id %d (Network: %s)", id, targetNetwork)
	topicSalt := fmt.Sprintf("%d", id)

	// 注意：这里我们将 networkOverride 传递给 Easy_P2P_MP
	connInfo, err := easyp2p.Easy_P2P_MP(config.ncconfig.ctx, targetNetwork, config.ncconfig.localbind, config.ncconfig.p2pSessionKey+topicSalt, false, nil, config.ncconfig.LogWriter)
	if err != nil {
		return nil, err
	}

	return connInfo.Conns[0], nil
}

// ==========================================
// Section 3: Protocol Implementation
// ==========================================

// --- Protocol Constants ---
const (
	MsgPing          uint8 = 0x01
	MsgPong          uint8 = 0x02
	MsgConfigSync    uint8 = 0x03
	MsgPortRotate    uint8 = 0x04
	MsgPortRotateAck uint8 = 0x05 // 此时含义为 Ready
	// MsgPortRotateApply (Deleted)
	// MsgPortRotateApplyAck (Deleted)
	MsgPortRotateCommit uint8 = 0x06 // 新增：确认切换 (Renumbered to 0x06)
)

// --- Payloads ---
type CommandPayload struct {
	ID      int    `json:"id"`
	Network string `json:"network,omitempty"` // 可选参数：指定的网络协议
}

type AckPayload struct {
	ID      int `json:"id"`
	ErrCode int `json:"err_code"`
}

// --- Controller & Interface ---

type RotateEventHandler interface {
	OnConfigSynced(remoteConfig AppPortRotateConfig)
	OnConnectionError(err error)
	OnPortRotate(id int, network string)
	OnPortRotateAck(id int, errCode int)
	OnPortRotateCommit(id int)
}

type RotateController struct {
	conn      net.Conn
	isClient  bool
	config    AppPortRotateConfig
	handler   RotateEventHandler
	sendCh    chan packet
	closeCh   chan struct{}
	closeOnce sync.Once
}

type packet struct {
	msgType uint8
	payload []byte
}

func NewRotateController(conn net.Conn, isClient bool, cfg AppPortRotateConfig, handler RotateEventHandler) *RotateController {
	return &RotateController{
		conn:     conn,
		isClient: isClient,
		config:   cfg,
		handler:  handler,
		sendCh:   make(chan packet, 64),
		closeCh:  make(chan struct{}),
	}
}

func (c *RotateController) Start() {
	go c.writeLoop()
	go c.readLoop()
	c.sendConfig()
}

func (c *RotateController) Stop() {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		c.conn.Close()
	})
}

// --- Send API ---

func (c *RotateController) SendPortRotate(id int, network string) {
	// 构建带有 network 参数的命令
	p := CommandPayload{ID: id, Network: network}
	data, _ := json.Marshal(p)
	c.sendCh <- packet{msgType: MsgPortRotate, payload: data}
}

func (c *RotateController) SendPortRotateAck(id int, errCode int) {
	c.sendAck(MsgPortRotateAck, id, errCode)
}

func (c *RotateController) SendPortRotateCommit(id int) {
	c.sendCommand(MsgPortRotateCommit, id)
}

// --- Internal Helpers ---

func (c *RotateController) sendConfig() {
	data, _ := json.Marshal(c.config)
	c.sendCh <- packet{msgType: MsgConfigSync, payload: data}
}

func (c *RotateController) sendCommand(msgType uint8, id int) {
	p := CommandPayload{ID: id}
	data, _ := json.Marshal(p)
	c.sendCh <- packet{msgType: msgType, payload: data}
}

func (c *RotateController) sendAck(msgType uint8, id int, errCode int) {
	p := AckPayload{ID: id, ErrCode: errCode}
	data, _ := json.Marshal(p)
	c.sendCh <- packet{msgType: msgType, payload: data}
}

func (c *RotateController) writeLoop() {
	// 保活间隔：默认15秒
	interval := 15 * time.Second
	var ticker *time.Ticker

	if c.isClient {
		ticker = time.NewTicker(interval)
	} else {
		ticker = time.NewTicker(24 * time.Hour) // Server 不主动 Ping，仅占位
		ticker.Stop()
	}
	defer ticker.Stop()

	for {
		select {
		case <-c.closeCh:
			return
		case <-ticker.C:
			c.sendCh <- packet{msgType: MsgPing, payload: nil}
		case pkt := <-c.sendCh:
			if err := c.writePacket(pkt); err != nil {
				c.handleError(fmt.Errorf("write error: %v", err))
				return
			}
		}
	}
}

func (c *RotateController) writePacket(pkt packet) error {
	// [Type 1byte] + [Length 4byte] + [Body]
	header := make([]byte, 5)
	header[0] = pkt.msgType
	binary.BigEndian.PutUint32(header[1:], uint32(len(pkt.payload)))

	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	if len(pkt.payload) > 0 {
		if _, err := c.conn.Write(pkt.payload); err != nil {
			return err
		}
	}
	return nil
}

func (c *RotateController) readLoop() {
	defer c.Stop()

	// 读超时设置为 Ping 间隔的 2 倍 + 缓冲
	timeout := 35 * time.Second
	headerBuf := make([]byte, 5)

	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(timeout))

		if _, err := io.ReadFull(c.conn, headerBuf); err != nil {
			c.handleError(fmt.Errorf("read header error: %v", err))
			return
		}

		msgType := headerBuf[0]
		bodyLen := binary.BigEndian.Uint32(headerBuf[1:])

		var body []byte
		if bodyLen > 0 {
			if bodyLen > 65535 {
				c.handleError(errors.New("msg too large"))
				return
			}
			body = make([]byte, bodyLen)
			if _, err := io.ReadFull(c.conn, body); err != nil {
				c.handleError(fmt.Errorf("read body error: %v", err))
				return
			}
		}

		c.dispatchMessage(msgType, body)
	}
}

func (c *RotateController) dispatchMessage(msgType uint8, body []byte) {
	switch msgType {
	case MsgPing:
		c.sendCh <- packet{msgType: MsgPong, payload: nil}
	case MsgPong:
		// Received Pong, connection alive
	case MsgConfigSync:
		var cfg AppPortRotateConfig
		if err := json.Unmarshal(body, &cfg); err == nil {
			c.handler.OnConfigSynced(cfg)
		}
	case MsgPortRotate:
		var p CommandPayload
		json.Unmarshal(body, &p)
		c.handler.OnPortRotate(p.ID, p.Network) // 传递 network 参数
	case MsgPortRotateAck:
		var p AckPayload
		json.Unmarshal(body, &p)
		c.handler.OnPortRotateAck(p.ID, p.ErrCode)
	case MsgPortRotateCommit:
		var p CommandPayload
		json.Unmarshal(body, &p)
		c.handler.OnPortRotateCommit(p.ID)
	}
}

func (c *RotateController) handleError(err error) {
	select {
	case <-c.closeCh:
		return
	default:
		c.handler.OnConnectionError(err)
	}
}

// ==========================================
// Section 4: Business Handler Implementation
// ==========================================

// rotateState 用于追踪发起方（Initiator）的轮转状态
type rotateState struct {
	conn        net.Conn
	ackReceived bool
	mu          sync.Mutex
}

type rotateBusinessHandler struct {
	ncconfig               *AppNetcatConfig
	bridge                 *netx.BridgeConn
	config                 *AppPortRotateConfig
	dataSessIdPtr          *int32
	lastRotationTrafficPtr *uint64 // 用于在手动触发时重置基准
	controlConn            net.Conn
	ctrl                   *RotateController
	errCh                  chan error

	// pendingRotations 追踪我方主动发起的 ID 的准备状态 (Initiator side)
	pendingRotations map[int]*rotateState
	pendingMu        sync.Mutex

	// receiverPending 追踪作为接收方，已经建立但尚未 Commit 的连接
	receiverPending map[int]net.Conn
	recvMu          sync.Mutex

	// 增加 httpServer 字段，用于清理
	httpServer *http.Server
}

// Handler 内部日志方法，复用全局辅助函数
func (h *rotateBusinessHandler) log(format string, v ...interface{}) {
	h.config.Logger.Printf(format, v...)
}

func (h *rotateBusinessHandler) OnConfigSynced(remoteConfig AppPortRotateConfig) {
	// 逻辑：两边配置取较小值（更严格的限制）。
	localPeriod := h.config.Period
	effectivePeriod := localPeriod
	if remoteConfig.Period > 0 {
		if localPeriod == 0 || remoteConfig.Period < localPeriod {
			effectivePeriod = remoteConfig.Period
		}
	}

	localLimit := atomic.LoadUint64(&h.config.RotationTrafficLimit)
	effectiveLimit := localLimit
	if remoteConfig.RotationTrafficLimit > 0 {
		if localLimit == 0 || remoteConfig.RotationTrafficLimit < localLimit {
			effectiveLimit = remoteConfig.RotationTrafficLimit
		}
	}

	// 更新 Period
	if effectivePeriod != localPeriod {
		h.config.Period = effectivePeriod
	}

	// 更新 Limit
	if effectiveLimit != localLimit {
		atomic.StoreUint64(&h.config.RotationTrafficLimit, effectiveLimit)
	}

	// 只打印最终结果
	h.log("Config Synced: Period=%d, Limit=%s", effectivePeriod, formatBytes(effectiveLimit))
}

func (h *rotateBusinessHandler) OnConnectionError(err error) {
	h.log("Connection error: %v", err)
	select {
	case h.errCh <- err:
	default:
	}
}

// OnPortRotate 收到对方发来的轮转命令 (作为接收方)
func (h *rotateBusinessHandler) OnPortRotate(id int, network string) {
	h.log("Received PortRotate command for ID: %d, Network: %s", id, network)

	h.recvMu.Lock()
	pendingCount := len(h.receiverPending)
	h.recvMu.Unlock()

	if pendingCount > 2 {
		h.log("Rotation skipped: too many(%d) pending in progress", pendingCount)
		h.ctrl.SendPortRotateAck(id, 501)
		return
	}

	// 检查是否已有轮转在进行中
	if atomic.LoadInt32(&h.config.isRotating) > 0 {
		h.log("Rotation skipped: already in progress")
		h.ctrl.SendPortRotateAck(id, 502)
		return
	}

	// 在 goroutine 中处理
	go func() {
		h.ncconfig.sessionReady = false

		// 1. 接收方建立 P2P 连接（与发起方并行）
		// 使用命令中指定的 network，如果为空则使用默认
		newConn, err := makeP2PDataSession(h.config, id, network)
		if err != nil {
			h.log("Rotate Error: Receiver makeP2PDataSession failed: %v", err)
			h.ctrl.SendPortRotateAck(id, 500)
			// 失败回滚：恢复 ready 状态
			h.ncconfig.sessionReady = true
			return
		}

		// 2. 暂存连接，不立即切换
		h.recvMu.Lock()
		h.receiverPending[id] = newConn
		h.recvMu.Unlock()

		h.log("Receiver ready (conn established) for ID %d, sending ACK/Ready...", id)

		// 3. 发送 ACK (Ready) 给发起方
		h.ctrl.SendPortRotateAck(id, 0)
	}()
}

// OnPortRotateCommit 收到发起方的提交命令，执行最终切换 (作为接收方)
func (h *rotateBusinessHandler) OnPortRotateCommit(id int) {
	h.log("Received PortRotateCommit for ID: %d", id)

	h.recvMu.Lock()
	conn, exists := h.receiverPending[id]
	delete(h.receiverPending, id) // 取出后删除
	h.recvMu.Unlock()

	if !exists || conn == nil {
		h.log("Error: Commit received for ID %d but no pending connection found.", id)
		// 异常情况，也应尝试恢复状态
		h.ncconfig.sessionReady = true
		return
	}

	// 执行切换
	h.log("Receiver switching to session ID %d...", id)
	h.bridge.SetForwarder(conn)
	atomic.StoreInt32(h.dataSessIdPtr, int32(id))
	h.log("Rotate Success: Receiver switched to session ID %d (after Commit)", id)

	// 切换完成，恢复 ready 状态
	h.ncconfig.sessionReady = true
}

// TriggerRotation 主动发起轮转 (通用逻辑，Timer 或 HTTP 调用)
// 增加 network 参数，用于手动指定协议
func (h *rotateBusinessHandler) TriggerRotation(source string, network string) {
	// 检查是否已有轮转在进行中
	if atomic.LoadInt32(&h.config.isRotating) > 0 {
		h.log("[%s] Rotation skipped: already in progress", source)
		return
	}

	// 1. 增加 ID
	newId := atomic.AddInt32(h.dataSessIdPtr, 1)

	// 2. 更新流量基准，防止 Timer 立即再次触发
	currentTotal := h.bridge.TotalTraffic
	atomic.StoreUint64(h.lastRotationTrafficPtr, currentTotal)

	h.log("[%s] Initiating PortRotate with ID %d, Network: %s", source, newId, network)

	// 3. 发送命令给对方 (携带 network 参数)
	h.ctrl.SendPortRotate(int(newId), network)

	// 4. 启动本地连接建立流程
	go func(id int) {
		h.InitiateRotation(id, network)
	}(int(newId))
}

// InitiateRotation 发起方逻辑：准备连接并等待ACK
func (h *rotateBusinessHandler) InitiateRotation(id int, network string) {
	// 修复 Race Condition: 检查 map 中是否已经存在 (由 Ack 提前创建)
	h.pendingMu.Lock()
	state, exists := h.pendingRotations[id]
	if !exists {
		state = &rotateState{}
		h.pendingRotations[id] = state
	}
	h.pendingMu.Unlock()

	// 如果开启了进度条，在开始建立连接（可能耗时）前设置为 false
	h.ncconfig.sessionReady = false

	// 1. 建立 P2P 连接（阻塞直到对方也调用 makeP2PDataSession）
	// 使用指定的 network
	newConn, err := makeP2PDataSession(h.config, id, network)
	if err != nil {
		h.log("Rotate Error: Initiator makeP2PDataSession failed: %v", err)
		// 失败回滚：恢复 ready 状态
		h.ncconfig.sessionReady = true

		// 如果指定了特定网络，失败后不重试
		if network != "" {
			return
		}

		// [新增逻辑] 失败后 30秒 自动重试
		// 使用 goroutine + timer + select 来处理生命周期和状态检查
		go func(failedID int) {
			h.log("Rotation failed. Scheduling auto-retry in 30 seconds...")

			// 创建定时器
			timer := time.NewTimer(30 * time.Second)
			defer timer.Stop()

			select {
			case <-h.ctrl.closeCh:
				// 模块已关闭，取消重试
				return
			case <-timer.C:
				// 定时器触发
			}

			// 检查 ID 是否发生变化（期间是否有其他触发成功或失败导致ID递增）
			currentID := int(atomic.LoadInt32(h.dataSessIdPtr))
			if currentID != failedID {
				h.log("Auto-retry skipped: ID changed from %d to %d", failedID, currentID)
				return
			}

			// 触发重试
			h.TriggerRotation("AutoRetry", "")
		}(id)
		return
	}

	// 2. 连接建立成功，检查是否收到 ACK (Ready)
	state.mu.Lock()
	state.conn = newConn
	received := state.ackReceived
	state.mu.Unlock()

	if received {
		// 如果已经收到 Ready 信号，则直接发送 Commit 并切换
		h.performInitiatorSwitch(id, newConn)
	} else {
		h.log("Initiator: Connection ready for ID %d, waiting for Peer Ready (ACK)...", id)
	}
}

// OnPortRotateAck 发起方收到 ACK (表示 Peer Ready)
func (h *rotateBusinessHandler) OnPortRotateAck(id int, errCode int) {
	h.log("Received PortRotateAck (Ready) for ID: %d, Code: %d", id, errCode)
	if errCode != 0 {
		// 收到错误码，回滚 ready 状态
		h.ncconfig.sessionReady = true
		return
	}

	h.pendingMu.Lock()
	state, exists := h.pendingRotations[id]
	if !exists {
		// 极罕见：先收到 ACK 后本地 Initiate 还没跑完第一步
		state = &rotateState{ackReceived: true}
		h.pendingRotations[id] = state
	}
	h.pendingMu.Unlock()

	state.mu.Lock()
	state.ackReceived = true
	conn := state.conn
	state.mu.Unlock()

	// 只有当本地连接也准备好了，才执行切换
	if conn != nil {
		h.performInitiatorSwitch(id, conn)
	}
}

func (h *rotateBusinessHandler) performInitiatorSwitch(id int, conn net.Conn) {
	// 1. 发送 Commit 给接收方，让它也切换
	h.ctrl.SendPortRotateCommit(id)

	// 2. 本地切换
	// 增加 "Switching..." 日志以便观察 SetForwarder 的耗时
	h.log("Initiator switching to session ID %d...", id)
	h.bridge.SetForwarder(conn)
	h.log("Rotate Success: Initiator switched to session ID %d (Sent Commit)", id)

	h.pendingMu.Lock()
	delete(h.pendingRotations, id)
	h.pendingMu.Unlock()

	// 切换完成，恢复 ready 状态
	h.ncconfig.sessionReady = true
}

// --- HTTP Management Server ---

/*
const nets = ["", "any", "tcp", "udp", "any4", "any6"];

	document.getElementById('network').innerHTML = nets.map(function(n) {
	    return '<option value="' + n + '">' + (n || 'Auto') + '</option>';
	}).join('');

	function fetchInfo() {
	    fetch('/info').then(res => res.json()).then(data => {
	        const container = document.getElementById('infoDisplay');
	        const rows = [
	            ["Session ID", data.current_id],
	            ["Traffic", (data.total_bytes/1048576).toFixed(2) + " MB"],
	            ["Period", data.config.period],
	            ["Limit", data.config.limit],
	            ["Forwarder", data.forwarder_addr],
	            ["Is Client", data.is_client]
	        ];
	        container.innerHTML = rows.map(function(r) {
	            return '<div class="bold">' + r[0] + ':</div><div>' + r[1] + '</div>';
	        }).join('');
	    });
	}

	function triggerRotate() {
	    const net = document.getElementById('network').value;
	    const logBox = document.getElementById('log');
	    logBox.style.display = 'block';
	    logBox.innerText = 'Processing...';

	    fetch('/rotate?network=' + net)
	        .then(function(res) {
	            return res.text().then(function(txt) {
	                logBox.innerText = "[" + res.status + "] " + txt;
	                if (res.ok) setTimeout(fetchInfo, 1000);
	            });
	        });
	}

fetchInfo();
setInterval(fetchInfo, 5000);
*/
const pr_Debug_IndexHTML = `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
body { font-family: monospace; max-width: 600px; margin: 20px; }
.card { border: 1px solid #000; padding: 10px; margin-bottom: 10px; }
.grid { display: grid; grid-template-columns: 120px 1fr; line-height: 1.6; }
#log { margin-top: 10px; border: 1px dashed #000; padding: 5px; display: none; font-size: 12px; }
</style>
</head>
<body>
<h3>PortRotate Management</h3>
<div class="card"><div id="infoDisplay" class="grid">Loading...</div></div>

<div class="card">
	<select id="network"></select>
	<button onclick="triggerRotate()">Rotate</button>
	<div id="log"></div>
</div>

<script>const nets=["","any","tcp","udp","any4","any6"];function fetchInfo(){fetch("/info").then(t=>t.json()).then(t=>{const n=document.getElementById("infoDisplay"),e=[["Session ID",t.current_id],["Traffic",(t.total_bytes/1048576).toFixed(2)+" MB"],["Period",t.config.period],["Limit",t.config.limit],["Forwarder",t.forwarder_addr],["Is Client",t.is_client]];n.innerHTML=e.map(function(t){return'<div class="bold">'+t[0]+":</div><div>"+t[1]+"</div>"}).join("")})}function triggerRotate(){var t=document.getElementById("network").value;const e=document.getElementById("log");e.style.display="block",e.innerText="Processing...",fetch("/rotate?network="+t).then(function(n){return n.text().then(function(t){e.innerText="["+n.status+"] "+t,n.ok&&setTimeout(fetchInfo,1e3)})})}document.getElementById("network").innerHTML=nets.map(function(t){return'<option value="'+t+'">'+(t||"Auto")+"</option>"}).join(""),fetchInfo(),setInterval(fetchInfo,5e3);
</script>
</body>
</html>
`

func (h *rotateBusinessHandler) StartHTTPServer(addr string) {
	mux := http.NewServeMux()
	// 1. 注册根路径指引
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 确保只处理精确的 "/" 路径，避免匹配到不存在的子路径
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, pr_Debug_IndexHTML)
	})
	mux.HandleFunc("/info", h.ServeHTTP_Info)
	mux.HandleFunc("/rotate", h.ServeHTTP_Rotate)

	// 保存实例以便关闭
	h.httpServer = &http.Server{Addr: addr, Handler: mux}

	h.log("Starting HTTP Management Server at http://%s", addr)
	// ListenAndServe 会阻塞，且正常关闭会返回 ErrServerClosed
	if err := h.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		h.log("HTTP Server Error: %v", err)
	}
}

// StopHTTPServer 关闭 HTTP 服务，释放端口
func (h *rotateBusinessHandler) StopHTTPServer() {
	if h.httpServer != nil {
		h.log("Stopping HTTP Server...")
		// Close 立即关闭监听器，释放端口
		h.httpServer.Close()
	}
}

func (h *rotateBusinessHandler) ServeHTTP_Info(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"is_client":         h.ctrl.isClient,
		"current_id":        atomic.LoadInt32(h.dataSessIdPtr),
		"total_bytes":       h.bridge.TotalTraffic,
		"last_rotate_bytes": atomic.LoadUint64(h.lastRotationTrafficPtr),
		"forwarder_addr":    h.bridge.GetForwarderInfo(),
		"config": map[string]interface{}{
			"period": h.config.Period,
			"limit":  formatBytes(atomic.LoadUint64(&h.config.RotationTrafficLimit)),
		},
	}
	json.NewEncoder(w).Encode(info)
}

func (h *rotateBusinessHandler) ServeHTTP_Rotate(w http.ResponseWriter, r *http.Request) {
	// 获取 URL 参数中的 network
	network := r.URL.Query().Get("network")

	// 简单的白名单校验，防止注入任意内容 (虽然 Easy_P2P_MP 内部也会校验)
	if network != "" {
		allowed := map[string]bool{
			"any": true, "any6": true, "any4": true,
			"tcp": true, "udp": true,
			"tcp6": true, "tcp4": true, "udp6": true, "udp4": true,
		}
		if !allowed[network] {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Invalid network type: %s\n", network)
			return
		}
	}

	if atomic.LoadInt32(&h.config.isRotating) > 0 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Rotation already in progress. Try again later.\n")
		return
	}

	// 手动触发，传递 network 参数
	h.TriggerRotation("HTTP", network)

	w.WriteHeader(http.StatusOK)
	if network != "" {
		fmt.Fprintf(w, "Rotation triggered with network='%s'. Check logs for details.\n", network)
	} else {
		fmt.Fprintf(w, "Rotation triggered (default network). Check logs for details.\n")
	}
}

func (h *rotateBusinessHandler) Clear() {
	// 清理 pendingRotations
	h.pendingMu.Lock()
	for id, state := range h.pendingRotations {
		if state.conn != nil {
			h.log("Closing pending rotation connection for ID: %d", id)
			state.conn.Close()
		}
		delete(h.pendingRotations, id)
	}
	h.pendingMu.Unlock()

	// 清理 receiverPending
	h.recvMu.Lock()
	for id, conn := range h.receiverPending {
		if conn != nil {
			h.log("Closing receiver pending connection for ID: %d", id)
			conn.Close()
		}
		delete(h.receiverPending, id)
	}
	h.recvMu.Unlock()

	h.log("All pending rotations and receiver connections have been cleared.")
}

// --- Utils ---

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
