//go:build windows
// +build windows

package misc

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
)

func PtyStart(c *exec.Cmd) (*os.File, error) {
	return pty.Start(c)
}
