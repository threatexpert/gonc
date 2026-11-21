package netx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// LocalBinding describes the endpoint or physical interface requested by -local.
type LocalBinding struct {
	Endpoint string
	Device   string
}

// ParseLocalBinding preserves legacy host:port parsing. A bare name must
// identify an interface; it is never resolved as a hostname.
func ParseLocalBinding(value string) (LocalBinding, error) {
	if value == "" {
		return LocalBinding{}, nil
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		return LocalBinding{Endpoint: value}, nil
	}
	if _, err := net.InterfaceByName(value); err != nil {
		return LocalBinding{}, fmt.Errorf("invalid -local %q: expected host:port or an existing interface: %w", value, err)
	}
	return LocalBinding{Device: value}, nil
}

func (b LocalBinding) Source() string {
	if b.Device != "" {
		return b.Device
	}
	host, _, _ := net.SplitHostPort(b.Endpoint)
	return host
}

// InterfaceIP selects a concrete candidate to advertise for one STUN family.
func InterfaceIP(name string, ipv4 bool) (net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	var fallback net.IP
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && (ip.To4() != nil) == ipv4 && (ip.IsGlobalUnicast() || ip.IsLoopback()) {
			// Prefer a globally routable IPv6 candidate over a ULA when both exist.
			if !ipv4 && ip.IsPrivate() {
				if fallback == nil {
					fallback = ip
				}
				continue
			}
			return ip, nil
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	family := "IPv6"
	if ipv4 {
		family = "IPv4"
	}
	return nil, fmt.Errorf("no usable %s address on %s", family, name)
}

// InterfaceListenHost chooses a concrete listener address on the requested
// device. An explicit address can be any address assigned to that device.
func InterfaceListenHost(name, network, host string) (string, error) {
	family := strings.TrimPrefix(strings.TrimPrefix(network, "tcp"), "udp")
	if host != "" {
		addr, err := net.ResolveIPAddr("ip"+family, host)
		if err != nil {
			return "", err
		}
		if !addr.IP.IsUnspecified() {
			if _, err := localInterfaceIndex(addr.IP, name); err != nil {
				return "", err
			}
			if addr.IP.IsLinkLocalUnicast() && addr.IP.To4() == nil {
				addr.Zone = name
			}
			return addr.String(), nil
		}
		if addr.IP.To4() == nil {
			family = "6"
		}
	}
	ip, err := InterfaceIP(name, family != "6")
	if err != nil && family == "" {
		ip, err = InterfaceIP(name, false)
	}
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

// InterfaceAddr carries an interface constraint through the same first-hop
// configuration that otherwise carries a concrete TCP or UDP source address.
type InterfaceAddr string

func (a InterfaceAddr) Network() string { return "interface" }
func (a InterfaceAddr) String() string  { return string(a) }

func (b LocalBinding) DialAddr(network string) (net.Addr, error) {
	if b.Device != "" {
		return InterfaceAddr(b.Device), nil
	}
	if b.Endpoint == "" {
		return nil, nil
	}
	if strings.HasPrefix(network, "udp") {
		return net.ResolveUDPAddr(network, b.Endpoint)
	}
	return net.ResolveTCPAddr(network, b.Endpoint)
}

// SourceAddr gives auxiliary sockets an ephemeral port of their own.
func SourceAddr(network, source string) (net.Addr, error) {
	if source == "" {
		return nil, nil
	}
	host, zone, _ := strings.Cut(source, "%")
	if ip := net.ParseIP(host); ip != nil {
		if strings.HasPrefix(network, "udp") {
			return &net.UDPAddr{IP: ip, Zone: zone}, nil
		}
		return &net.TCPAddr{IP: ip, Zone: zone}, nil
	}
	if _, err := net.InterfaceByName(source); err != nil {
		return nil, fmt.Errorf("invalid local source %q: %w", source, err)
	}
	return InterfaceAddr(source), nil
}

func BoundDialer(local net.Addr, previous socketControl) *net.Dialer {
	if dev, ok := local.(InterfaceAddr); ok {
		return &net.Dialer{Control: deviceControl(string(dev), previous, "")}
	}
	return &net.Dialer{LocalAddr: local, Control: LocalAddrControl(local, previous)}
}

func InterfaceControl(name string, previous socketControl) socketControl {
	return deviceControl(name, previous, "")
}

func deviceControl(name string, previous socketControl, dns string) socketControl {
	if name == "" {
		return previous
	}
	return func(network, address string, c syscall.RawConn) error {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return err
		}
		if err = bindNamedInterface(c, iface, network, dns); err != nil {
			return fmt.Errorf("bind %s socket to %s: %w", network, name, err)
		}
		if previous != nil {
			return previous(network, address, c)
		}
		return nil
	}
}

func ListenInterfaceUDP(ctx context.Context, network string, local *net.UDPAddr, device string) (*net.UDPConn, error) {
	if device == "" {
		return net.ListenUDP(network, local)
	}
	lc := net.ListenConfig{Control: InterfaceControl(device, nil)}
	conn, err := lc.ListenPacket(ctx, network, local.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}
