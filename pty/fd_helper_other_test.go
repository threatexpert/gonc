//go:build !zos
// +build !zos

package pty

import (
	"os"
	"testing"
)

func getNonBlockingFile(t *testing.T, file *os.File, path string) *os.File {
	t.Helper()
	return file
}
