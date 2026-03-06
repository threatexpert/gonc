package easyp2p

// ============================================================================
// LAN Probe - 在 STUN+MQTT 流程中自动探测内网直连可达性
//
// 目的:
//   当 CompareP2PAddresses 判定双方不在同一内网（sameNAT=false 或 similarLAN=false），
//   但双方都持有私有 IP 地址时，通过实际的 TCP 直连探测来验证是否可以走内网路径。
//   这覆盖了以下场景：
//     1) 多出口 IP 的企业网络（公网IP不同但内网互通）
//     2) 跨子网但有路由互通的私有网络（10.1.x vs 10.2.x）
//     3) 混合使用不同私有段但实际同一物理网络的场景
//
// 设计原则:
//   - 仅在 round==1（首轮打洞）时触发一次探测
//   - 与原有打洞逻辑完全并发，共享 ctx + commitOnce 竞争机制
//   - 探测成功：tryCommit 赢得竞争，cancel() 终止原有打洞
//   - 探测失败：静默退出，不影响原有逻辑
//   - 探测超时：1.5 秒，对内网来说绑绑有余
// ============================================================================

import (
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// LAN 探测的 TCP 连接超时时间
	lanProbeTimeout = 1500 * time.Millisecond
)

// shouldTryLANProbe 判断是否应该尝试 LAN 直连探测
// 条件：
//  1. 当前不被认为是同一内网 (inSameLAN == false)
//  2. 是首轮打洞 (round == 1)
//  3. 双方的 LAN 地址都是私有 IP
//  4. 双方的 LAN 地址和 NAT 地址不同（说明确实在 NAT 后面）
func shouldTryLANProbe(inSameLAN bool, round int, p2pInfo *P2PAddressInfo) bool {
	if inSameLAN {
		return false // 已经被认定为同内网，不需要额外探测
	}
	if round != 1 {
		return false // 仅首轮
	}

	localLANIP := extractIP(p2pInfo.LocalLAN)
	remoteLANIP := extractIP(p2pInfo.RemoteLAN)

	if localLANIP == "" || remoteLANIP == "" {
		return false
	}

	// 双方都必须有私有地址
	localParsed := net.ParseIP(localLANIP)
	remoteParsed := net.ParseIP(remoteLANIP)
	if localParsed == nil || remoteParsed == nil {
		return false
	}
	if !localParsed.IsPrivate() || !remoteParsed.IsPrivate() {
		return false
	}

	// 至少一方的 LAN 和 NAT 不同（说明确实在 NAT 后面，探测才有意义）
	// 如果双方 LAN==NAT，说明可能直接有公网 IP，不需要内网探测
	if p2pInfo.LocalLAN == p2pInfo.LocalNAT && p2pInfo.RemoteLAN == p2pInfo.RemoteNAT {
		return false
	}

	return true
}

// doLANProbe 执行 LAN 直连探测（TCP 版本）
// 这个函数设计为在一个独立的 goroutine 中运行，与原有打洞逻辑并发。
// 它使用调用者提供的 tryConnect 函数来尝试连接，tryConnect 内部会调用
// doHandshake + tryCommit，与原有打洞逻辑共享竞争机制。
//
// 参数:
//   - network: 网络类型，如 "tcp4"
//   - p2pInfo: P2P 地址信息
//   - isClient: 当前节点的角色
//   - logWriter: 日志输出
//   - tryConnectFn: 尝试连接的函数（复用 doPunching 中的 tryConnect）
//     签名: func(targetAddr string, localAddr *net.TCPAddr, reuseaddr bool, timeout_sec int, isClient bool, tag string) bool
//
// 注意: 此函数不需要返回值，成功与否完全通过 tryCommit 的竞争机制来体现。
// 调用者（doPunching）在启动此 goroutine 前需要 wg.Add(1) 和 workerChan <- struct{}{}
func doLANProbe(
	network string,
	p2pInfo *P2PAddressInfo,
	isClient bool,
	logWriter io.Writer,
	tryConnectFn func(targetAddr string, localAddr *net.TCPAddr, reuseaddr bool, timeout_sec int, isClient bool, tag string) bool,
) {
	// 连接对方的 LAN 地址（incPort 之后的，即 p2pInfo.RemoteLAN）
	remoteLANAddr := p2pInfo.RemoteLAN

	fmt.Fprintf(logWriter, "  ↑ LAN probe: trying direct connect to peer LAN address %s ...\n", remoteLANAddr)

	// 使用系统分配的随机端口，不与主打洞逻辑抢端口
	// reuseaddr=false，因为不需要端口复用
	// timeout 使用 lanProbeTimeout 对应的秒数（向上取整为 2 秒，因为 tryConnect 接受整数秒）
	timeoutSec := int((lanProbeTimeout + time.Second - 1) / time.Second) // 向上取整
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	success := tryConnectFn(remoteLANAddr, nil, false, timeoutSec, isClient, "lan-probe")

	if success {
		fmt.Fprintf(logWriter, "  ✓ LAN probe: direct LAN connection succeeded!\n")
	}
	// 失败则静默，tryConnect 内部会处理连接关闭
}
