//go:build linux
// +build linux

package pty

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// open allocates a new pseudo-terminal pair and returns the master and slave file.
func open() (pty, tty *os.File, err error) {
	p, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err == nil {
		// In case of error after this point, make sure we close the ptmx fd.
		defer func() {
			if err != nil {
				_ = p.Close() // Best effort.
			}
		}()

		sname, err := ptsname(p)
		if err != nil {
			return fallbackOpen()
		}

		if err := unlockpt(p); err != nil {
			return fallbackOpen()
		}

		t, err := os.OpenFile(sname, os.O_RDWR|syscall.O_NOCTTY, 0)
		if err != nil {
			return fallbackOpen()
		}
		return p, t, nil
	}

	// fallback to old-style /dev/ptyXY
	return fallbackOpen()
}

// ptsname gets the name of the slave pseudoterminal device corresponding to the master pty.
func ptsname(f *os.File) (string, error) {
	var n _C_uint
	err := ioctl(f, syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n)))
	if err != nil {
		return "", err
	}
	return "/dev/pts/" + strconv.Itoa(int(n)), nil
}

// unlockpt unlocks the slave pseudoterminal device corresponding to the master.
func unlockpt(f *os.File) error {
	var u _C_int
	return ioctl(f, syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&u)))
}

// fallbackOpen tries to find an available legacy /dev/ptyXY pseudoterminal
func fallbackOpen() (pty, tty *os.File, err error) {
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
