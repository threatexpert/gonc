package nearby

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

const (
	// MulticastGroup is shared with gonc LAN discovery; MulticastPort is not,
	// so the device list keeps working while a passphrase session binds 19730.
	MulticastGroup = "239.255.255.250"
	MulticastPort  = 19731

	advertMagic     = "GONC-NEARBY"
	maxAdvertPacket = 1024
)

// advert is the multicast advertisement. It carries no stable identifier:
// Tag is a resolvable value that only paired devices can recognize. A packet
// with Q set asks visible devices to announce themselves; a bare query has no
// tag and reveals nothing about the sender beyond its address.
type advert struct {
	M    string `json:"m"`
	V    int    `json:"v"`
	Tag  []byte `json:"tag,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	Port int    `json:"port,omitempty"`
	Q    bool   `json:"q,omitempty"`
	// QR is set when the device accepts files from unpaired devices.
	QR bool `json:"qr,omitempty"`
}

type packet struct {
	data []byte
	src  net.Addr
}

// discovery owns one UDP socket bound to the discovery port. It both sends
// and receives, exactly like gonc LAN mode: Windows Firewall admits a peer's
// multicast and unicast answers only on a socket that has itself sent to the
// group, so sending from a separate socket leaves a firewalled device deaf.
type discovery struct {
	group  *net.UDPAddr
	logger *log.Logger

	raw  net.PacketConn
	conn *ipv4.PacketConn

	mu     sync.Mutex
	joined map[int]bool
	ifaces []net.Interface
	warned map[string]bool

	// sink, when set, receives every outgoing packet instead of the
	// network. Tests use it.
	sink func(data []byte, dst net.Addr)
}

func openDiscovery(port int, logger *log.Logger) (*discovery, error) {
	group := &net.UDPAddr{IP: net.ParseIP(MulticastGroup), Port: port}
	lc := net.ListenConfig{Control: reuseControl}
	raw, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, fmt.Errorf("nearby: bind discovery port %d: %w", port, err)
	}
	d := &discovery{
		group:  group,
		logger: logger,
		raw:    raw,
		conn:   ipv4.NewPacketConn(raw),
		joined: map[int]bool{},
		warned: map[string]bool{},
	}
	_ = d.conn.SetMulticastLoopback(true)
	_ = d.conn.SetMulticastTTL(1)
	if err := d.refreshInterfaces(); err != nil {
		d.close()
		return nil, err
	}
	return d, nil
}

// refreshInterfaces joins the group on interfaces that appeared since the
// last call, such as after Wi-Fi reconnects.
func (d *discovery) refreshInterfaces() error {
	ifaces, err := net.Interfaces()
	d.mu.Lock()
	defer d.mu.Unlock()
	var usable []net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 || !hasIPv4(iface) {
			continue
		}
		usable = append(usable, iface)
		if d.joined[iface.Index] {
			continue
		}
		if jerr := d.conn.JoinGroup(&iface, &net.UDPAddr{IP: d.group.IP}); jerr == nil {
			d.joined[iface.Index] = true
		} else {
			d.warnLocked("join:"+iface.Name, "nearby: join multicast on %s: %v", iface.Name, jerr)
		}
	}
	d.ifaces = usable
	if len(d.joined) == 0 {
		if jerr := d.conn.JoinGroup(nil, &net.UDPAddr{IP: d.group.IP}); jerr != nil {
			if err != nil {
				return fmt.Errorf("nearby: list interfaces: %v; join multicast: %w", err, jerr)
			}
			return fmt.Errorf("nearby: join multicast group: %w", jerr)
		}
		d.joined[0] = true
	}
	return nil
}

func hasIPv4(iface net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			return true
		}
	}
	return false
}

func (d *discovery) warnLocked(key, format string, args ...any) {
	if d.logger == nil || d.warned[key] {
		return
	}
	d.warned[key] = true
	d.logger.Printf(format, args...)
}

// multicast sends data on every usable interface.
func (d *discovery) multicast(data []byte) {
	if d.sink != nil {
		d.sink(data, d.group)
		return
	}
	d.mu.Lock()
	ifaces := append([]net.Interface(nil), d.ifaces...)
	d.mu.Unlock()
	sent := false
	for i := range ifaces {
		if err := d.conn.SetMulticastInterface(&ifaces[i]); err != nil {
			continue
		}
		if _, err := d.conn.WriteTo(data, nil, d.group); err == nil {
			sent = true
		}
	}
	if !sent {
		_, _ = d.raw.WriteTo(data, d.group)
	}
}

func (d *discovery) unicast(data []byte, dst net.Addr) {
	if d.sink != nil {
		d.sink(data, dst)
		return
	}
	_, _ = d.raw.WriteTo(data, dst)
}

// readLoop delivers packets from one socket until it is closed.
func (d *discovery) readLoop(conn net.PacketConn, out chan<- packet, done <-chan struct{}) {
	buf := make([]byte, maxAdvertPacket+1)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-done:
				return
			default:
				continue
			}
		}
		if n > maxAdvertPacket {
			continue
		}
		data := append([]byte(nil), buf[:n]...)
		select {
		case out <- packet{data, src}:
		case <-done:
			return
		default: // drop under load rather than block the socket
		}
	}
}

func (d *discovery) close() {
	_ = d.raw.Close()
}

func parseAdvert(data []byte) (*advert, bool) {
	var a advert
	if err := json.Unmarshal(data, &a); err != nil || a.M != advertMagic || a.V != ProtocolVersion {
		return nil, false
	}
	if len(a.Tag) == 0 {
		return &a, a.Q
	}
	if len(a.Tag) != tagBytes || a.Port <= 0 || a.Port > 65535 {
		return nil, false
	}
	return &a, true
}
