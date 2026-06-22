package mobilegonc

import (
	"fmt"
	"strings"
)

// StartP2PTunnel starts gonc in link mode and exposes a local SOCKS5 endpoint.
func StartP2PTunnel(password string, useUDP bool, localSocksPort int, extraArgs string, cb Callback) (session *Session, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic starting tunnel: %v", r)
			if cb != nil {
				cb.Error(err.Error())
			}
		}
	}()
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("password is required")
	}
	if localSocksPort <= 0 || localSocksPort > 65535 {
		return nil, fmt.Errorf("invalid SOCKS5 port: %d", localSocksPort)
	}
	args := []string{"-p2p", password}
	if useUDP {
		args = append(args, "-u")
	}
	linkConfig := fmt.Sprintf("x://127.0.0.1:%d;none", localSocksPort)
	args = append(args, "-link", linkConfig)
	if strings.TrimSpace(extraArgs) != "" {
		args = append(args, splitExtraArgs(extraArgs)...)
	}
	if cb != nil {
		udpArg := ""
		if useUDP {
			udpArg = " -u"
		}
		cb.Event("info", fmt.Sprintf("Starting gonc tunnel with args: -p2p ***%s -link %s", udpArg, linkConfig))
	}
	return start(args, cb, "tunnel"), nil
}

func splitExtraArgs(extraArgs string) []string {
	fields := strings.Fields(extraArgs)
	if len(fields) == 0 {
		return nil
	}
	return fields
}
