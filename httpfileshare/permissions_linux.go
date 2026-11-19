package httpfileshare

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// Pin the entry even when its current mode is 000. Never follow a final
// symlink, including one substituted between comparison and chmod.
func chmodReceived(root *os.Root, rel string, mode fs.FileMode) error {
	parent, err := root.OpenFile(filepath.Dir(rel), unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(rel), unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "openat", Path: rel, Err: err}
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFREG, unix.S_IFDIR:
	default:
		return &os.PathError{Op: "chmod", Path: rel, Err: unix.EINVAL}
	}
	err = unix.Fchmodat(fd, "", uint32(mode), unix.AT_EMPTY_PATH)
	if err == unix.EOPNOTSUPP || err == unix.ENOSYS || err == unix.EINVAL {
		// Before fchmodat2, procfs is the chmod handle for an O_PATH fd.
		err = unix.Chmod("/proc/self/fd/"+strconv.Itoa(fd), uint32(mode))
	}
	if err != nil {
		return &os.PathError{Op: "chmod", Path: rel, Err: err}
	}
	return nil
}
