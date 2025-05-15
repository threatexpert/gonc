package misc

import (
	"crypto/rand"
	"fmt"
	"io"
)

// 伪设备实现
type PseudoDevice struct {
	name string
}

func NewPseudoDevice(name string) (*PseudoDevice, error) {
	validDevices := map[string]bool{
		"/dev/zero":    true,
		"/dev/urandom": true,
		"/dev/null":    true,
	}
	if !validDevices[name] {
		return nil, fmt.Errorf("unknown device name")
	}
	return &PseudoDevice{name: name}, nil
}

func (d *PseudoDevice) Read(p []byte) (n int, err error) {
	switch d.name {
	case "/dev/zero":
		for i := range p {
			p[i] = 0
		}
		return len(p), nil
	case "/dev/urandom":
		return rand.Read(p)
	default:
		return 0, io.EOF
	}
}

func (d *PseudoDevice) Write(p []byte) (n int, err error) {
	if d.name == "/dev/null" {
		return len(p), nil
	}
	return 0, fmt.Errorf("device not writable")
}

func (d *PseudoDevice) Close() error {
	return nil
}
