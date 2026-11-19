package httpfileshare

import (
	"golang.org/x/sys/windows"
	"os"
)

// Windows SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE.
const symbolicLinkAllowUnprivilegedCreate = 0x2

func createReceiverSymlink(target, name string, directory bool) error {
	old, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	newName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	flags := uint32(symbolicLinkAllowUnprivilegedCreate)
	if directory {
		flags |= windows.SYMBOLIC_LINK_FLAG_DIRECTORY
	}
	err = windows.CreateSymbolicLink(newName, old, flags)
	if err == windows.ERROR_INVALID_PARAMETER {
		err = windows.CreateSymbolicLink(newName, old, flags&^symbolicLinkAllowUnprivilegedCreate)
	}
	if err != nil {
		return &os.LinkError{Op: "symlink", Old: target, New: name, Err: err}
	}
	return nil
}
