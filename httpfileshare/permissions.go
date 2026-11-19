package httpfileshare

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// PermissionsDiffer compares the permission bits representable on the destination.
func PermissionsDiffer(mode *uint32, local fs.FileMode) bool {
	if mode == nil {
		return false
	}
	mask := uint32(0777)
	if runtime.GOOS == "windows" {
		// Windows chmod controls only the read-only attribute of ordinary files.
		if local.IsDir() {
			return false
		}
		mask = 0200
	}
	return (*mode^uint32(local.Perm()))&mask != 0
}

// ApplyPermissions handles materialized files/directories only; the receiving
// root itself and preserved links have no permissions to restore.
func ApplyPermissions(root, full string, mode *uint32, directory bool) error {
	if mode == nil {
		return nil
	}
	rel, err := filepath.Rel(root, full)
	if err != nil {
		return err
	}
	if rel == "." || !filepath.IsLocal(rel) {
		return fmt.Errorf("invalid destination for permissions: %s", full)
	}
	info, err := os.Lstat(full)
	if err != nil {
		return err
	}
	if info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("destination type changed: %s", full)
	}
	if !PermissionsDiffer(mode, info.Mode()) {
		return nil
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	return chmodReceived(r, rel, fs.FileMode(*mode).Perm())
}
