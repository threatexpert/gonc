package acl

import (
	"net"
	"os"
	"testing"
)

func writeTempACL(content string) (string, error) {
	f, err := os.CreateTemp("", "acltest-*.conf")
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return f.Name(), err
}

func TestACL_ShouldDeny(t *testing.T) {
	// 更新了配置文件，为 deny_outbound 添加了 IP 和 CIDR 规则，
	// 并移除了 '*' 以便能精确测试其他规则。
	conf := `
# 入站拒绝规则
[deny_inbound]
192.168.1.100
10.0.0.0/8
::1
::/0

# 出站拒绝规则 (包含域名和IP)
[deny_outbound]
8.8.8.8
172.16.0.0/12
2001:4860:4860::8888
2001:2222::/32
google.com
*.google-analytics.com
`

	path, err := writeTempACL(conf)
	if err != nil {
		t.Fatalf("write temp acl: %v", err)
	}
	defer os.Remove(path)

	acl, err := LoadACL(path)
	if err != nil {
		t.Fatalf("load acl: %v", err)
	}

	tests := []struct {
		address   string
		direction string
		expect    bool
	}{
		// --- 入站测试 (Inbound Tests) ---
		{"192.168.1.100", "inbound", true}, // 精确 IP 匹配
		{"10.1.2.3", "inbound", true},      // CIDR 匹配
		{"127.0.0.1", "inbound", false},    // 不在列表中的 IP
		{"::1", "inbound", true},           // 精确 IPv6 匹配
		{"2001:db8::1", "inbound", true},   // IPv6 CIDR 匹配 (::/0)

		// --- 出站测试 (Outbound Tests) ---
		// 按域名拒绝
		{"google.com", "outbound", true},               // 精确域名匹配
		{"www.google-analytics.com", "outbound", true}, // 后缀通配符匹配
		// 按 IP/CIDR 拒绝
		{"8.8.8.8", "outbound", true},              // 精确 IP 匹配
		{"172.20.1.1", "outbound", true},           // IPv4 CIDR 匹配 (172.16.0.0/12)
		{"2001:4860:4860::8888", "outbound", true}, // 精确 IPv6 匹配
		{"2001:2222:4860::8888", "outbound", true}, // IPv6 CIDR 匹配

		// 允许的出站请求
		{"microsoft.com", "outbound", false}, // 不在列表中的域名
		{"analytics.com", "outbound", false}, // 未匹配后缀通配符
		{"8.8.4.4", "outbound", false},       // 不在列表中的 IP
		{"172.32.0.1", "outbound", false},    // 在 CIDR 范围之外的 IP
		{"2001:db8::2", "outbound", false},   // 不在列表中的 IPv6

		// 交叉方向测试 (确保规则不会混淆)
		{"8.8.8.8", "inbound", false},     // 出站规则不影响入站
		{"trusted.com", "inbound", false}, // 域名对入站方向无效
	}

	for _, tt := range tests {
		t.Run(tt.address+"_"+tt.direction, func(t *testing.T) {
			denied := acl.ShouldDeny(tt.address, tt.direction)
			if denied != tt.expect {
				t.Errorf("ShouldDeny(%q, %q) = %v; want %v", tt.address, tt.direction, denied, tt.expect)
			}
		})
	}

	tests2 := []struct {
		address   string
		network   string
		direction string
		expect    bool
	}{

		// --- 出站测试 (Outbound Tests) ---
		// 按域名拒绝
		{"turn.cloudflare.com:80", "tcp", "outbound", false},         //
		{"icanhazip.com:80", "tcp6", "outbound", false},              //
		{"2001-2222-1234--8888.nip.io:80", "tcp6", "outbound", true}, //
		{"172.16.1.1.sslip.io:80", "tcp4", "outbound", true},         //
		{"google.com:80", "tcp6", "outbound", true},                  //
		{"8.8.8.8.sslip.io:53", "tcp", "outbound", true},             //

		// 允许的出站请求
		{"microsoft.com:443", "tcp4", "outbound", false}, // 不在列表中的域名
	}

	defaultResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true, //规避windows下，没有ipv6环境解析ipv6的报错：getaddrinfow: The requested name is valid, but no data of the requested type was found.
	}
	defer func() {
		net.DefaultResolver = defaultResolver
	}()
	for _, tt := range tests2 {
		t.Run(tt.address+"_"+tt.direction, func(t *testing.T) {
			addrStr := ""
			_, rAddr, denied, err := ResolveAddrWithACL(t.Context(), acl, tt.network, nil, tt.address)
			if rAddr != nil {
				addrStr = rAddr.String()
			}
			if denied != tt.expect {
				t.Errorf("ResolveAddrWithACL(%q, %q) = %v(%s); want %v, err=%v", tt.address, tt.direction, denied, addrStr, tt.expect, err)
			}
			addrStr = ""
			_, rAddr2, denied2, _ := ResolveAddrWithACL(t.Context(), nil, tt.network, nil, tt.address)
			if rAddr2 != nil {
				addrStr = rAddr2.String()
			}
			if denied2 {
				t.Errorf("ResolveAddrWithACL(%q, %q) = %v(%s); want %v", tt.address, tt.direction, denied2, addrStr, false)
			}
		})
	}

}
