package easyp2p

// ============================================================================
// LAN Probe - 在 STUN+MQTT 流程中自动探测内网直连可达性
//
// 场景：双方都在同一物理内网，但因多出口IP或跨子网等原因，
// CompareP2PAddresses 误判为不同网络。通过实际 TCP 直连探测来验证。
//
// 设计：
//   - 通过 exchangeAddressPayload.Caps 协商，新版对新版才启用
//   - Do_autoP2PEx2 筛选时保留最多一对 LANProbeOnly 地址对
//   - Auto_P2P_TCP_NAT_Traversal 中对 LANProbeOnly 地址对只做 LAN 探测
//
// 兼容性：
//   - 老版本不认识 Caps 字段，json.Unmarshal 自动忽略
//   - 新版收到老版消息时 Caps 为 nil，不启用 LAN 探测
//   - 不改变任何现有通信协议和打洞逻辑
// ============================================================================

import "net"

const (
	// CapLANProbe 能力标识，用于 exchangeAddressPayload.Caps 版本协商
	CapLANProbe = "lan-probe"
)

// bothPrivateLAN 检查两个地址（host:port 格式）是否都是私有 IP
func bothPrivateLAN(lanAddr1, lanAddr2 string) bool {
	ip1 := extractIP(lanAddr1)
	ip2 := extractIP(lanAddr2)
	if ip1 == "" || ip2 == "" {
		return false
	}
	parsed1 := net.ParseIP(ip1)
	parsed2 := net.ParseIP(ip2)
	if parsed1 == nil || parsed2 == nil {
		return false
	}
	return parsed1.IsPrivate() && parsed2.IsPrivate()
}

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
