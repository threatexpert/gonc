//go:build !linux && !darwin

package httpfileshare

import (
	"io/fs"
	"os"
)

func chmodReceived(root *os.Root, rel string, mode fs.FileMode) error { return root.Chmod(rel, mode) }
