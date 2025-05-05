//go:build zos
// +build zos

package pty

import (
	"os"
	"testing"
)

func getNonBlockingFile(t *testing.T, file *os.File, path string) *os.File {
	t.Helper()
	// z/OS doesn't open a pollable FD - fix that here
	if _, err := fcntl(uintptr(file.Fd()), F_SETFL, O_NONBLOCK); err != nil {
		t.Fatalf("Error: zos-nonblock: %s.\n", err)
	}
	nf := os.NewFile(file.Fd(), path)
	t.Cleanup(func() { _ = nf.Close() })
	return nf
}
