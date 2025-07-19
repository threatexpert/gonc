package acl

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// ============================================================================
//  Radix Tree (基数树) - 用于高效的 IP/CIDR 查询
// ============================================================================

// radixNode 代表基数树中的一个节点。
type radixNode struct {
	// children[0] 代表比特 0, children[1] 代表比特 1。
	children [2]*radixNode
	// isLeaf 标记一个 CIDR 前缀是否在此节点结束。
	isLeaf bool
}

// radixTree 是一个为 IP 前缀设计的二叉基数树。
type radixTree struct {
	root *radixNode
}

// newRadixTree 创建一个新的空基数树。
func newRadixTree() *radixTree {
	return &radixTree{root: &radixNode{}}
}

// Insert 将一个 CIDR 前缀添加到树中。
func (t *radixTree) Insert(ipNet *net.IPNet) {
	node := t.root
	// 从掩码获取前缀长度
	prefixLen, _ := ipNet.Mask.Size()
	// 遍历网络 IP 地址的每一个比特位
	for i := 0; i < prefixLen; i++ {
		// 获取位置 i 的比特值 (0 or 1)
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		bit := (ipNet.IP[byteIndex] >> bitIndex) & 1

		// 如果子节点不存在，则创建它
		if node.children[bit] == nil {
			node.children[bit] = &radixNode{}
		}
		node = node.children[bit]
	}
	// 标记此前缀的结束
	node.isLeaf = true
}

// Contains 检查一个 IP 地址是否被树中的任何前缀所包含。
// 它的效率是 O(k)，k 是 IP 地址的位数。
func (t *radixTree) Contains(ip net.IP) bool {
	node := t.root
	// IP 地址的总位数 (IPv4 是 32, IPv6 是 128)
	totalBits := len(ip) * 8
	for i := 0; i < totalBits; i++ {
		// 如果当前节点是一个前缀的终点，意味着给定的 IP 属于该前缀范围。
		if node.isLeaf {
			return true
		}

		// 获取当前 IP 位的值
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		bit := (ip[byteIndex] >> bitIndex) & 1

		// 移动到下一个节点
		node = node.children[bit]
		if node == nil {
			// 如果路径中断，说明没有任何更长的前缀能匹配，因此 IP 不被包含。
			return false
		}
	}
	// 如果完整遍历了 IP 的所有位，最终还要检查最后一个节点是否是叶子节点。
	// (例如，查询的 IP 本身就是一个被拒绝的地址)
	return node.isLeaf
}

// ============================================================================
//  Domain Matcher (域名匹配器) - 用于高效的出站域名查询
// ============================================================================

// domainMatcher 持有用于出站域名匹配的规则。
type domainMatcher struct {
	fullWildcard    bool
	exactMatches    map[string]struct{} // 精确匹配
	prefixWildcards map[string]struct{} // 前缀通配符, 例如 "example.*"
	suffixWildcards map[string]struct{} // 后缀通配符, 例如 "*.example.com"
}

// newDomainMatcher 创建一个新的域名匹配器。
func newDomainMatcher() *domainMatcher {
	return &domainMatcher{
		exactMatches:    make(map[string]struct{}),
		prefixWildcards: make(map[string]struct{}),
		suffixWildcards: make(map[string]struct{}),
	}
}

// AddRule 将一条域名规则添加到匹配器中。
func (dm *domainMatcher) AddRule(rule string) {
	rule = strings.ToLower(strings.TrimSpace(rule))
	if rule == "*" {
		dm.fullWildcard = true
		return
	}
	if strings.HasPrefix(rule, "*.") {
		// 后缀通配符, e.g., "*.example.com" -> 存储 "example.com"
		dm.suffixWildcards[rule[2:]] = struct{}{}
		return
	}
	if strings.HasSuffix(rule, ".*") {
		// 前缀通配符, e.g., "example.*" -> 存储 "example"
		dm.prefixWildcards[rule[:len(rule)-2]] = struct{}{}
		return
	}
	// 精确匹配
	dm.exactMatches[rule] = struct{}{}
}

// Match 检查一个域名是否应该被拒绝。
// 它的效率是 O(L)，L 是域名中的标签数量，远好于 O(N)。
func (dm *domainMatcher) Match(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// 1. 检查全局通配符
	if dm.fullWildcard {
		return true
	}

	// 2. 检查精确匹配
	if _, ok := dm.exactMatches[domain]; ok {
		return true
	}

	parts := strings.Split(domain, ".")

	// 3. 检查前缀通配符 (例如 "evil.*" 匹配 "evil.com")
	if len(parts) > 0 {
		if _, ok := dm.prefixWildcards[parts[0]]; ok {
			return true
		}
	}

	// 4. 检查后缀通配符 (例如 "*.evil.com" 匹配 "sub.evil.com")
	// 需要检查所有可能的后缀。例如，对于 "a.b.c"，我们需要检查 "b.c" 和 "c"。
	for i := 1; i < len(parts); i++ {
		suffix := strings.Join(parts[i:], ".")
		if _, ok := dm.suffixWildcards[suffix]; ok {
			return true
		}
	}

	return false
}

// ============================================================================
//  ACL (访问控制列表) - 顶层结构
// ============================================================================

// ACL 持有已编译的访问控制列表规则。
type ACL struct {
	inboundIPv4  *radixTree
	inboundIPv6  *radixTree
	outboundIPv4 *radixTree
	outboundIPv6 *radixTree
	outbound     *domainMatcher
}

// ShouldDeny 检查对于给定的地址和方向，请求是否应该被拒绝。
func (a *ACL) ShouldDeny(address string, direction string) bool {
	direction = strings.ToLower(direction)
	if direction == "inbound" {
		ip := net.ParseIP(address)
		if ip == nil {
			return false // 无效的 IP 地址无法匹配，因此不拒绝
		}

		// 检查是否为 IPv4 地址 (net.IP 将其表示为 16 字节的 IPv6 地址)
		if ipv4 := ip.To4(); ipv4 != nil {
			return a.inboundIPv4.Contains(ipv4)
		}
		// 否则，它是一个 IPv6 地址
		return a.inboundIPv6.Contains(ip)

	} else if direction == "outbound" {
		// 首先，尝试将地址解析为 IP
		ip := net.ParseIP(address)
		if ip != nil {
			// 如果是有效的 IP 地址，则只根据出站 IP 规则进行检查
			if ipv4 := ip.To4(); ipv4 != nil {
				return a.outboundIPv4.Contains(ipv4)
			}
			return a.outboundIPv6.Contains(ip)
		}

		// 如果不是有效的 IP 地址，则假定为域名并根据域名规则进行检查
		return a.outbound.Match(address)
	}

	return false
}

// LoadACL 从给定路径加载并解析 ACL 配置文件。
func LoadACL(path string) (*ACL, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	acl := &ACL{
		inboundIPv4:  newRadixTree(),
		inboundIPv6:  newRadixTree(),
		outboundIPv4: newRadixTree(),
		outboundIPv6: newRadixTree(),
		outbound:     newDomainMatcher(),
	}

	scanner := bufio.NewScanner(file)
	var currentSection string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 跳过空行和注释
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}

		// 解析区域标记
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(line[1 : len(line)-1])
			continue
		}

		// parseIPNet 是一个辅助函数，用于解析 IP/CIDR
		parseIPNet := func(l string) (*net.IPNet, bool) {
			_, ipNet, err := net.ParseCIDR(l)
			if err == nil {
				return ipNet, true
			}
			ip := net.ParseIP(l)
			if ip == nil {
				return nil, false
			}
			var mask net.IPMask
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
			return &net.IPNet{IP: ip, Mask: mask}, true
		}

		switch currentSection {
		case "deny_inbound":
			if ipNet, ok := parseIPNet(line); ok {
				if ipv4 := ipNet.IP.To4(); ipv4 != nil {
					ipNet.IP = ipv4
					acl.inboundIPv4.Insert(ipNet)
				} else {
					ipNet.IP = ipNet.IP.To16()
					if ipNet.IP != nil {
						acl.inboundIPv6.Insert(ipNet)
					}
				}
			}

		case "deny_outbound":
			// 尝试将该行解析为 IP/CIDR
			if ipNet, ok := parseIPNet(line); ok {
				// 如果是 IP 或 CIDR, 添加到出站 IP 规则
				if ipv4 := ipNet.IP.To4(); ipv4 != nil {
					ipNet.IP = ipv4
					acl.outboundIPv4.Insert(ipNet)
				} else {
					ipNet.IP = ipNet.IP.To16()
					if ipNet.IP != nil {
						acl.outboundIPv6.Insert(ipNet)
					}
				}
			} else {
				// 如果不是 IP, 则作为域名处理
				acl.outbound.AddRule(line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return acl, nil
}

func ACL_inbound_allow(acl *ACL, remoteAddr net.Addr) bool {
	if acl == nil {
		return true // 没有设置访问控制，默认允许所有连接
	}
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return true // 如果解析失败，默认允许连接
	}
	if !acl.ShouldDeny(host, "inbound") {
		return true
	}
	return false
}

func ResolveAddrWithACL(ctx context.Context, acl *ACL, network, address string) (net.Addr, bool, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, false, fmt.Errorf("invalid address format: %w", err)
	}

	var resolvedIP net.IP

	// 尝试直接将主机部分解析为 IP 地址
	ip := net.ParseIP(host)
	if ip != nil {
		// 如果主机本身就是 IP，直接使用
		resolvedIP = ip
	} else {
		// 如果不是 IP，则它是一个域名。

		// 阶段一：检查域名本身是否在拒绝列表中
		if acl != nil && acl.ShouldDeny(host, "outbound") {
			return nil, true, fmt.Errorf("ACL rule denied access to domain: %s", host)
		}

		// 阶段二：执行 DNS 查询
		// 将 "tcp" 或 "udp" 相关的 network 类型映射为 "ip" 相关的类型
		var ipNetwork string
		switch network {
		case "tcp4", "udp4":
			ipNetwork = "ip4"
		case "tcp6", "udp6":
			ipNetwork = "ip6"
		default: // "tcp", "udp", and others fall back to "ip"
			ipNetwork = "ip"
		}

		ips, err := net.DefaultResolver.LookupIP(ctx, ipNetwork, host)
		if err != nil {
			return nil, false, fmt.Errorf("DNS lookup failed for '%s' on network '%s': %w", host, ipNetwork, err)
		}
		if len(ips) == 0 {
			return nil, false, fmt.Errorf("no IP address found for host '%s' on network '%s'", host, ipNetwork)
		}

		// 使用查询到的第一个 IP 地址，因为 resolver 已经完成了筛选
		resolvedIP = ips[0]
	}

	// 阶段三：对最终解析出的 IP 地址进行 ACL 规则检查
	ipStr := resolvedIP.String()
	if acl != nil && acl.ShouldDeny(ipStr, "outbound") {
		return nil, true, fmt.Errorf("ACL rule denied access to IP: %s (from %s)", ipStr, host)
	}

	// 所有检查通过，将端口字符串转换为整数
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, false, fmt.Errorf("invalid port number '%s': %w", portStr, err)
	}

	// 根据网络类型，构建并返回最终的 net.Addr 对象
	switch network {
	case "tcp", "tcp4", "tcp6":
		return &net.TCPAddr{IP: resolvedIP, Port: port}, false, nil
	case "udp", "udp4", "udp6":
		return &net.UDPAddr{IP: resolvedIP, Port: port}, false, nil
	default:
		return nil, false, net.UnknownNetworkError(network)
	}
}
