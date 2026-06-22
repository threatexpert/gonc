//go:build android

package mobilegonc

import (
	"fmt"
	"strings"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/engine"
	"golang.org/x/sys/unix"
)

var (
	tun2socksMu      sync.Mutex
	tun2socksStarted bool
)

// StartTun2Socks starts tun2socks on an Android VPN file descriptor.
//
// Android's detachFd() leaves a non-zero fdsan ownership tag on the TUN fd.
// If tun2socks later closes that fd via a raw syscall, the kernel recycles the
// fd number and Android's strict fdsan (API 36) detects a conflict when the
// GPU or BLASTBufferQueue tries to claim the recycled number, crashing the
// RenderThread or Binder threads with "wrong owner" / "double-close" errors.
//
// We apply three mitigations in sequence:
//  1. clearFdsanTag: clears the detachFd PFD ownership tag while keeping the
//     fd open, so any subsequent raw close is fdsan-safe.
//  2. F_DUPFD_CLOEXEC >= 512: dups the fd to a high-numbered slot. GPU and
//     BLASTBufferQueue fence fds are almost always < 300; using fd >= 512
//     makes fd-number recycling conflicts with FrameHistory very unlikely.
//  3. The caller (Java) must close the original low-numbered fd via bionic
//     (adoptFd/close) after this function returns, clearing any remaining
//     fdsan state and giving bionic a chance to properly update its tables.
func StartTun2Socks(fd int, proxyURL string, deviceName string, mtu int, logLevel string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic starting tun2socks: %v", r)
		}
	}()
	if fd < 0 {
		return fmt.Errorf("invalid TUN fd: %d", fd)
	}
	if strings.TrimSpace(proxyURL) == "" {
		return fmt.Errorf("proxy URL is required")
	}
	if mtu <= 0 {
		mtu = 1400
	}
	if strings.TrimSpace(logLevel) == "" {
		logLevel = "warn"
	}

	// Step 1: clear the fdsan tag left by detachFd().
	clearFdsanTag(fd)

	// Step 2: dup to fd >= 512 to avoid GPU/BLASTBufferQueue FrameHistory
	// conflicts. Falls back to plain dup if high-fd allocation fails.
	const highFdMin = 512
	highFd, fcntlErr := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, highFdMin)
	if fcntlErr != nil {
		highFd, fcntlErr = unix.Dup(fd)
		if fcntlErr != nil {
			return fmt.Errorf("dup TUN fd: %w", fcntlErr)
		}
	}
	defer func() {
		if err != nil {
			unix.Close(highFd)
		}
	}()

	tun2socksMu.Lock()
	defer tun2socksMu.Unlock()
	if tun2socksStarted {
		engine.Stop()
		tun2socksStarted = false
	}
	engine.Insert(&engine.Key{
		Device:   fmt.Sprintf("fd://%d", highFd),
		Proxy:    proxyURL,
		LogLevel: logLevel,
		MTU:      mtu,
	})
	engine.Start()
	tun2socksStarted = true
	return nil
}

// StopTun2Socks stops the tun2socks engine.
func StopTun2Socks() {
	tun2socksMu.Lock()
	defer tun2socksMu.Unlock()
	if !tun2socksStarted {
		return
	}
	engine.Stop()
	tun2socksStarted = false
}
