package httpfileshare

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

func (s *OSFileSource) Lstat(name string) (fs.FileInfo, error) {
	full, virtual, err := s.resolvePath(name)
	if err != nil {
		return nil, err
	}
	if virtual {
		return s.Stat(name)
	}
	return os.Lstat(full)
}

// Resolve parent links, retaining the final entry so chains need not be flattened.
func canonicalEntry(name string) string {
	parent, err := filepath.EvalSymlinks(filepath.Dir(name))
	if err != nil {
		return filepath.Clean(name)
	}
	return filepath.Join(parent, filepath.Base(name))
}
func sameSourcePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
func virtualRelative(from, to string) string {
	rel, err := filepath.Rel(filepath.FromSlash(path.Dir(from)), filepath.FromSlash(to))
	if err != nil {
		return ""
	}
	return filepath.ToSlash(rel)
}
func (s *OSFileSource) Readlink(name string) (string, error) {
	full, virtual, err := s.resolvePath(name)
	if err != nil {
		return "", err
	}
	if virtual {
		return "", fs.ErrInvalid
	}
	raw, err := os.Readlink(full)
	if err != nil {
		return "", err
	}
	physical := raw
	if !filepath.IsAbs(raw) {
		// Do not clean .. before resolving intermediate symlinks: a/../b may
		// differ from b when a itself is a directory link.
		physical = filepath.Dir(canonicalEntry(full)) + string(filepath.Separator) + raw
	}
	if resolved, err := filepath.EvalSymlinks(physical); err == nil {
		physical = resolved
	} else {
		physical = canonicalEntry(physical)
	}
	// Keep original relative spelling if the exported mapping is already correct.
	if candidate, ok := relativeLinkPath(name, filepath.ToSlash(raw)); ok {
		mapped, virtual, err := s.resolvePath(candidate)
		if err == nil && !virtual {
			// The target is already canonical. An identical mapped path needs no
			// second walk through the filesystem to resolve the same components.
			if sameSourcePath(filepath.Clean(mapped), physical) {
				return virtualRelative(name, candidate), nil
			}
			if resolved, err := filepath.EvalSymlinks(mapped); err == nil {
				mapped = resolved
			} else {
				mapped = canonicalEntry(mapped)
			}
			if sameSourcePath(mapped, physical) {
				return virtualRelative(name, candidate), nil
			}
		}
	}
	mounts := s.mounts
	if s.singleRoot != "" {
		alias := ""
		if s.singleRootIsFile {
			alias = s.singleRootAlias
		}
		mounts = []virtualMount{{Alias: alias, RealPath: s.singleRoot}}
	}
	// Rebase targets through exported roots, including duplicate-name aliases.
	for _, mount := range mounts {
		root := canonicalEntry(mount.RealPath)
		if sameSourcePath(root, physical) {
			return virtualRelative(name, "/"+mount.Alias), nil
		}
		info, err := os.Lstat(mount.RealPath)
		if err != nil || !info.IsDir() {
			continue
		}
		root, err = filepath.EvalSymlinks(mount.RealPath)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(root, physical)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			continue
		}
		return virtualRelative(name, path.Join("/", mount.Alias, filepath.ToSlash(rel))), nil
	}
	// Absolute external targets select content reception instead of link creation.
	return filepath.ToSlash(physical), nil
}

// ValidateDirectory prevents revisiting an actual directory along an expanded
// path, even when each link uses different text to form the cycle.
func (s *OSFileSource) ValidateDirectory(name string) error {
	full, virtual, err := s.resolvePath(name)
	if err != nil || virtual {
		return err
	}
	current := filepath.VolumeName(full) + string(filepath.Separator)
	var ancestors []fs.FileInfo
	if info, err := os.Stat(current); err == nil {
		ancestors = append(ancestors, info)
	}
	for _, part := range strings.Split(strings.TrimPrefix(full, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Stat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fs.ErrInvalid
		}
		for _, ancestor := range ancestors {
			if os.SameFile(ancestor, info) {
				return fmt.Errorf("directory link cycle at %s", name)
			}
		}
		ancestors = append(ancestors, info)
	}
	return nil
}
func (s *OSFileSource) walkRequestedRoot(full, name string, fn func(string, fs.FileInfo, error) error) error {
	info, err := os.Stat(full)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := s.ValidateDirectory(name); err != nil {
			return err
		}
		full, err = filepath.EvalSymlinks(full)
		if err != nil {
			return err
		}
	}
	return s.walkDiskRoot(full, name, fn)
}
func portableRelativeLink(target string) bool {
	return target != "" && !strings.HasPrefix(target, "/") && !strings.ContainsAny(target, "\\:\x00")
}
