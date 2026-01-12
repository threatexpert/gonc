//go:build !windows
// +build !windows

package misc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
)

func PtyStart(name string, args ...string) (PtyProcess, io.ReadWriteCloser, error) {
	c := exec.Command(name, args...)

	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	c.SysProcAttr.Setsid = true
	c.SysProcAttr.Setctty = true

	var err2 error
	pty, tty, err := pty.Open()
	if err != nil {
		pty, tty, err2 = fallbackPtyOpen()
		if err2 != nil {
			return nil, nil, err
		}
	}

	defer func() { _ = tty.Close() }() // Best effort.

	if c.Stdout == nil {
		c.Stdout = tty
	}
	if c.Stderr == nil {
		c.Stderr = tty
	}
	if c.Stdin == nil {
		c.Stdin = tty
	}

	if err = c.Start(); err != nil {
		_ = pty.Close() // Best effort.
		return nil, nil, err
	}

	return &StdProcess{Cmd: c}, pty, nil
}

// fallbackPtyOpen tries to find an available legacy /dev/ptyXY pseudoterminal
func fallbackPtyOpen() (pty, tty *os.File, err error) {
	const (
		ptyMajors = "pqrstuvwxyzabcdefghijklmnoABCDEFGHIJKLMNOPQRSTUVWXYZ"
		ptyMinors = "0123456789abcdef"
	)
	numMinors := len(ptyMinors)
	numPtys := len(ptyMajors) * numMinors

	for i := 0; i < numPtys; i++ {
		major := ptyMajors[i/numMinors]
		minor := ptyMinors[i%numMinors]
		ptyName := fmt.Sprintf("/dev/pty%c%c", major, minor)
		ttyName := fmt.Sprintf("/dev/tty%c%c", major, minor)

		pfd, err := os.OpenFile(ptyName, os.O_RDWR|syscall.O_NOCTTY, 0)
		if err != nil {
			// try SCO naming
			ptyName = fmt.Sprintf("/dev/ptyp%d", i)
			ttyName = fmt.Sprintf("/dev/ttyp%d", i)
			pfd, err = os.OpenFile(ptyName, os.O_RDWR|syscall.O_NOCTTY, 0)
			if err != nil {
				continue
			}
		}

		tfd, err := os.OpenFile(ttyName, os.O_RDWR|syscall.O_NOCTTY, 0)
		if err != nil {
			_ = pfd.Close()
			continue
		}

		return pfd, tfd, nil
	}
	return nil, nil, errors.New("no available /dev/ptyXY devices")
}

func EnableVirtualTerminal() {

}
