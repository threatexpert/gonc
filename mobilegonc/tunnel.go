package mobilegonc

import (
	"fmt"
	"strings"
)

// StartP2PTunnel starts gonc in link mode and exposes a linkConfig.
func StartP2PTunnel(password string, useUDP bool, linkConfig string, extraArgs string, cb Callback) (session *Session, err error) {
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

	args := []string{"-p2p", password}
	if useUDP {
		args = append(args, "-u")
	}
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

// StartP2PLinkAgent starts gonc in linkagent (dual proxy service) mode. This is
// the passive VPN server side: it waits for one or more link clients to connect
// over P2P and proxies their traffic out through this device. No local endpoint
// is exposed, so it behaves like the file-share side and just runs until stopped.
func StartP2PLinkAgent(password string, useUDP bool, cb Callback) (session *Session, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic starting linkagent: %v", r)
			if cb != nil {
				cb.Error(err.Error())
			}
		}
	}()
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("password is required")
	}
	args := []string{"-p2p", password}
	if useUDP {
		args = append(args, "-u")
	}
	args = append(args, "-linkagent")
	if cb != nil {
		udpArg := ""
		if useUDP {
			udpArg = " -u"
		}
		cb.Event("info", fmt.Sprintf("Starting gonc linkagent with args: -p2p ***%s -linkagent", udpArg))
	}
	return start(args, cb, "linkagent"), nil
}

func splitExtraArgs(extraArgs string) []string {
	fields := strings.Fields(extraArgs)
	if len(fields) == 0 {
		return nil
	}
	return fields
}
