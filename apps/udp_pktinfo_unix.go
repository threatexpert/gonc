//go:build !windows

package apps

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// enablePktInfo 在 UDP socket 上启用 IP_PKTINFO (Linux)
func enablePktInfo(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("SyscallConn: %w", err)
	}

	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
	})
	if err != nil {
		return err
	}
	return sockErr
}

// parseDstIPFromOOB 从 ReadMsgUDP 返回的 OOB 数据中解析目的 IP (Linux)
//
// Linux in_pktinfo 结构体:
//
//	struct in_pktinfo {
//	    unsigned int   ipi_ifindex;  // 4 bytes
//	    struct in_addr ipi_spec_dst; // 4 bytes
//	    struct in_addr ipi_addr;     // 4 bytes ← 目的 IP
//	};
//
// cmsghdr 结构体:
//
//	struct cmsghdr {
//	    size_t cmsg_len;   // 64-bit: 8 bytes, 32-bit: 4 bytes
//	    int    cmsg_level; // 4 bytes
//	    int    cmsg_type;  // 4 bytes
//	};
func parseDstIPFromOOB(oob []byte) (net.IP, error) {
	cmsghdrSize := int(unsafe.Sizeof(syscall.Cmsghdr{}))

	for len(oob) >= cmsghdrSize {
		hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))

		cmsgLen := int(hdr.Len)
		if cmsgLen < cmsghdrSize || cmsgLen > len(oob) {
			break
		}

		if hdr.Level == syscall.IPPROTO_IP && hdr.Type == syscall.IP_PKTINFO {
			dataStart := cmsgAlignOf(cmsghdrSize)
			if dataStart+12 > cmsgLen {
				break
			}
			data := oob[dataStart:]
			// in_pktinfo: ifindex(4) + spec_dst(4) + addr(4)
			// ipi_addr 在偏移 8
			if len(data) >= 12 {
				ip := make(net.IP, 4)
				copy(ip, data[8:12])
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

// cmsgAlignOf 按平台指针大小对齐
func cmsgAlignOf(n int) int {
	sizeofPtr := int(unsafe.Sizeof(uintptr(0)))
	return (n + sizeofPtr - 1) & ^(sizeofPtr - 1)
}
