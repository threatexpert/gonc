//go:build !windows

package httpfileshare

import "os"

func createReceiverSymlink(target, name string, directory bool) error {
	return os.Symlink(target, name)
}
