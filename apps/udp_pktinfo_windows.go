//go:build windows

package apps

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windows_IP_PKTINFO = 19
)

// wsaCmsghdr 对应 Windows WSACMSGHDR
// Windows 的 syscall 包没有 Cmsghdr，必须自定义
type wsaCmsghdr struct {
	Len   uintptr // SIZE_T: 64-bit=8bytes, 32-bit=4bytes
	Level int32
	Type  int32
}

func enablePktInfo(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("SyscallConn: %w", err)
	}
	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows_IP_PKTINFO, 1)
	})
	if err != nil {
		return err
	}
	return sockErr
}

// parseDstIPFromOOB 解析 ReadMsgUDP 的 OOB 数据
// Windows IN_PKTINFO: { IN_ADDR ipi_addr(4); ULONG ipi_ifindex(4); }
// dst IP 在 data 偏移 0
func parseDstIPFromOOB(oob []byte) (net.IP, error) {
	hdrSize := int(unsafe.Sizeof(wsaCmsghdr{}))

	for len(oob) >= hdrSize {
		hdr := (*wsaCmsghdr)(unsafe.Pointer(&oob[0]))
		cmsgLen := int(hdr.Len)
		if cmsgLen < hdrSize || cmsgLen > len(oob) {
			break
		}

		if hdr.Level == windows.IPPROTO_IP && hdr.Type == windows_IP_PKTINFO {
			dataStart := cmsgAlignOf(hdrSize)
			if dataStart+8 > cmsgLen {
				break
			}
			data := oob[dataStart:]
			if len(data) >= 8 {
				ip := make(net.IP, 4)
				copy(ip, data[0:4])
				return ip, nil
			}
		}

		next := cmsgAlignOf(cmsgLen)
		if next <= 0 || next > len(oob) {
			break
		}
		oob = oob[next:]
	}

	return nil, fmt.Errorf("IP_PKTINFO not found in OOB data")
}

func cmsgAlignOf(n int) int {
	sizeofPtr := int(unsafe.Sizeof(uintptr(0)))
	return (n + sizeofPtr - 1) & ^(sizeofPtr - 1)
}
