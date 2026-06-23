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
func StartP2PLinkAgent(password string, useUDP bool, extraArgs string, cb Callback) (session *Session, err error) {
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
	if strings.TrimSpace(extraArgs) != "" {
		args = append(args, splitExtraArgs(extraArgs)...)
	}
	if cb != nil {
		udpArg := ""
		if useUDP {
			udpArg = " -u"
		}
		cb.Event("info", fmt.Sprintf("Starting gonc linkagent with args: -p2p ***%s -linkagent", udpArg))
	}
	return start(args, cb, "linkagent"), nil
}

// splitExtraArgs tokenizes a command-line string shell-style: whitespace
// separates tokens, but single or double quotes group a run (including spaces)
// into one argument, with the quote characters removed. Adjacent quoted and
// unquoted runs join (a"b c"d -> "ab cd"). Backslash escaping is not supported;
// use quotes for values that contain spaces, e.g. -x "aaa bbb ccc".
func splitExtraArgs(extraArgs string) []string {
	var args []string
	var current strings.Builder
	inToken := false
	var quote rune // 0 when not inside quotes, otherwise '\'' or '"'
	for _, r := range extraArgs {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inToken = true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if inToken {
				args = append(args, current.String())
				current.Reset()
				inToken = false
			}
		default:
			current.WriteRune(r)
			inToken = true
		}
	}
	if inToken {
		args = append(args, current.String())
	}
	return args
}
