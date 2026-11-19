package httpfileshare

import (
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func chmodReceived(root *os.Root, rel string, mode fs.FileMode) error {
	parent, err := root.Open(filepath.Dir(rel))
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := unix.Fchmodat(int(parent.Fd()), filepath.Base(rel), uint32(mode), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "chmod", Path: rel, Err: err}
	}
	return nil
}
