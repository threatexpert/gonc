//go:build darwin || windows || (linux && !android)

package netx

import (
	"context"
	"net"
	"syscall"
	"testing"
)

// Exercise kernel options without changing routes or contacting external hosts.
// VPN-on packet capture is a separate acceptance check.
func TestLocalInterfaceSocketOptions(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	tested := 0
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			ipnet, ok := address.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsUnspecified() {
				continue
			}
			ip := ipnet.IP
			tcpNetwork, udpNetwork, zone := "tcp6", "udp6", iface.Name
			if ip.To4() != nil {
				tcpNetwork, udpNetwork, zone = "tcp4", "udp4", ""
			}
			local := &net.TCPAddr{IP: ip, Zone: zone}
			lc := net.ListenConfig{Control: LocalAddrControl(local, ControlTCP)}
			listener, err := lc.Listen(context.Background(), tcpNetwork, local.String())
			if err != nil {
				t.Fatalf("TCP %s: %v", address, err)
			}
			raw, err := listener.(syscall.Conn).SyscallConn()
			if err == nil {
				err = checkLocalSocketInterface(raw, ip, iface)
			}
			listener.Close()
			if err != nil {
				t.Fatalf("TCP %s: %v", address, err)
			}
			conn, err := ListenUDP(udpNetwork, &net.UDPAddr{IP: ip, Zone: zone})
			if err != nil {
				t.Fatalf("UDP %s: %v", address, err)
			}
			raw, err = conn.SyscallConn()
			if err == nil {
				err = checkLocalSocketInterface(raw, ip, iface)
			}
			if err != nil {
				conn.Close()
				t.Fatalf("UDP %s: %v", address, err)
			}
			wrapped := NewBoundUDPConn(conn, "", false)
			wrapped.SetRebuildListener(ListenUDP)
			rebuilt, err := wrapped.Rebuild()
			if err == nil {
				raw, err = rebuilt.SyscallConn()
				if err == nil {
					err = checkLocalSocketInterface(raw, ip, iface)
				}
			}
			wrapped.Close()
			if err != nil {
				t.Fatalf("rebuilt UDP %s: %v", address, err)
			}
			t.Logf("verified TCP/UDP interface binding: %s %s", iface.Name, ip)
			tested++
		}
	}
	if tested == 0 {
		t.Skip("no active non-loopback IP addresses")
	}
}

func TestNamedInterfaceDialerBindsBothFamilies(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		binding, err := ParseLocalBinding(iface.Name)
		if err != nil {
			t.Fatal(err)
		}
		local, err := binding.DialAddr("udp")
		if err != nil {
			t.Fatal(err)
		}
		dialer := BoundDialer(local, nil)
		if dialer.LocalAddr != nil {
			t.Fatalf("device name restricted the source address to %v", dialer.LocalAddr)
		}
		for _, host := range []string{"127.0.0.1", "::1"} {
			conn, err := dialer.Dial("udp", net.JoinHostPort(host, "53"))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := conn.(syscall.Conn).SyscallConn()
			if err == nil {
				err = checkLocalSocketInterface(raw, net.ParseIP(host), iface)
			}
			conn.Close()
			if err != nil {
				t.Fatalf("%s on %s: %v", host, iface.Name, err)
			}
		}
		return
	}
	t.Skip("no active loopback interface")
}
