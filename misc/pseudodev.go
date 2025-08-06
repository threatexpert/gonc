package misc

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"time"
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

///

type DummyAddr string

func (d DummyAddr) Network() string { return string(d) }
func (d DummyAddr) String() string  { return string(d) }

type ConsoleIO struct{}

func (s *ConsoleIO) Read(p []byte) (int, error)         { return os.Stdin.Read(p) }
func (s *ConsoleIO) Write(p []byte) (int, error)        { return os.Stdout.Write(p) }
func (s *ConsoleIO) Close() error                       { return nil }
func (s *ConsoleIO) LocalAddr() net.Addr                { return DummyAddr("stdio") }
func (s *ConsoleIO) RemoteAddr() net.Addr               { return DummyAddr("stdio") }
func (s *ConsoleIO) SetDeadline(t time.Time) error      { return nil }
func (s *ConsoleIO) SetReadDeadline(t time.Time) error  { return nil }
func (s *ConsoleIO) SetWriteDeadline(t time.Time) error { return nil }
