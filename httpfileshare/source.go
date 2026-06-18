package httpfileshare

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// ErrDirectoryTraversal is returned when a virtual path tries to leave the
// configured file source root.
var ErrDirectoryTraversal = errors.New("directory traversal attempt")

// FileSource abstracts the backing storage used by the HTTP file server.
//
// Paths passed to the methods are virtual URL paths such as "/" or "/dir/file".
// Implementations may back those paths with local files, mobile content URIs,
// or any other readable file tree.
type FileSource interface {
	Description() string
	Stat(name string) (fs.FileInfo, error)
	Open(name string) (fs.File, error)
	ReadDir(name string) ([]fs.FileInfo, error)
	Walk(name string, fn func(sourcePath string, info fs.FileInfo, err error) error) error
}

// OSFileSource adapts local filesystem paths to FileSource. It preserves the
// server's existing single-root and multi-root virtual mount behavior.
type OSFileSource struct {
	mounts           []virtualMount
	singleRoot       string
	singleRootIsFile bool
	singleRootAlias  string
}

// NewOSFileSource creates a FileSource backed by one or more local filesystem
// roots.
func NewOSFileSource(rootPaths []string) (*OSFileSource, error) {
	if len(rootPaths) == 0 {
		return nil, fmt.Errorf("at least one root path must be provided")
	}

	var absPaths []string
	for _, p := range rootPaths {
		if len(p) == 2 && p[1] == ':' {
			p = p + string(os.PathSeparator)
		}

		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("invalid root path %s: %w", p, err)
		}
		absPaths = append(absPaths, abs)
	}

	src := &OSFileSource{}
	if len(absPaths) == 1 {
		src.singleRoot = absPaths[0]
		if stat, err := os.Stat(absPaths[0]); err == nil && !stat.IsDir() {
			src.singleRootIsFile = true
			src.singleRootAlias = filepath.Base(absPaths[0])
		}
		return src, nil
	}

	seenAliases := make(map[string]int)
	for _, p := range absPaths {
		baseName := filepath.Base(p)
		if baseName == string(os.PathSeparator) || baseName == "." {
			vol := filepath.VolumeName(p)
			if vol != "" {
				baseName = strings.TrimRight(vol, ":")
			} else {
				baseName = "ROOT"
			}
		}

		alias := baseName
		if count, exists := seenAliases[alias]; exists {
			seenAliases[baseName]++
			alias = fmt.Sprintf("%s-%d", baseName, count+1)
		} else {
			seenAliases[alias] = 1
		}

		src.mounts = append(src.mounts, virtualMount{
			Alias:    alias,
			RealPath: p,
		})
	}
	return src, nil
}

func (s *OSFileSource) Description() string {
	if s.singleRoot != "" {
		return fmt.Sprintf("serving from %s", s.singleRoot)
	}
	return fmt.Sprintf("serving %d virtual roots", len(s.mounts))
}

func (s *OSFileSource) Stat(name string) (fs.FileInfo, error) {
	fullPath, isVirtualRoot, err := s.resolvePath(name)
	if err != nil {
		return nil, err
	}
	if isVirtualRoot {
		if s.singleRootIsFile {
			return sourceDirInfo{name: "/", modTime: singleRootModTime(s.singleRoot)}, nil
		}
		return sourceDirInfo{name: "/", modTime: latestMountModTime(s.mounts)}, nil
	}
	return os.Stat(fullPath)
}

func (s *OSFileSource) Open(name string) (fs.File, error) {
	fullPath, isVirtualRoot, err := s.resolvePath(name)
	if err != nil {
		return nil, err
	}
	if isVirtualRoot {
		return nil, fs.ErrInvalid
	}
	return os.Open(fullPath)
}

func (s *OSFileSource) ReadDir(name string) ([]fs.FileInfo, error) {
	fullPath, isVirtualRoot, err := s.resolvePath(name)
	if err != nil {
		return nil, err
	}
	if isVirtualRoot {
		if s.singleRootIsFile {
			stat, err := os.Stat(s.singleRoot)
			if err != nil {
				return nil, err
			}
			return []fs.FileInfo{virtualFileInfo{FileInfo: stat, name: s.singleRootAlias}}, nil
		}
		var entries []fs.FileInfo
		for _, m := range s.mounts {
			stat, err := os.Stat(m.RealPath)
			if err != nil {
				continue
			}
			entries = append(entries, virtualFileInfo{FileInfo: stat, name: m.Alias})
		}
		return entries, nil
	}

	f, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dirEntries, readErr := f.ReadDir(-1)
	entries := make([]fs.FileInfo, 0, len(dirEntries))
	for _, de := range dirEntries {
		info, err := de.Info()
		if err != nil {
			continue
		}
		entries = append(entries, info)
	}
	return entries, readErr
}

func (s *OSFileSource) Walk(name string, fn func(sourcePath string, info fs.FileInfo, err error) error) error {
	requestedPath, err := cleanSourcePath(name)
	if err != nil {
		return err
	}

	if s.singleRoot != "" {
		if s.singleRootIsFile {
			return s.walkSingleFileRoot(requestedPath, fn)
		}
		fullPath, _, err := s.resolvePath(requestedPath)
		if err != nil {
			return err
		}
		if _, err := os.Stat(fullPath); err != nil {
			return err
		}
		return s.walkDiskRoot(fullPath, requestedPath, fn)
	}

	if requestedPath == "/" {
		for _, m := range s.mounts {
			if err := s.walkDiskRoot(m.RealPath, "/"+m.Alias, fn); err != nil {
				return err
			}
		}
		return nil
	}

	fullPath, _, err := s.resolvePath(requestedPath)
	if err != nil {
		return err
	}
	return s.walkDiskRoot(fullPath, requestedPath, fn)
}

func (s *OSFileSource) walkDiskRoot(rootDiskPath string, virtualPrefix string, fn func(sourcePath string, info fs.FileInfo, err error) error) error {
	return filepath.WalkDir(rootDiskPath, func(currentPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return fn("", nil, err)
		}

		relPath, err := filepath.Rel(rootDiskPath, currentPath)
		if err != nil {
			return fn("", nil, err)
		}

		fullVirtualPath := path.Join(virtualPrefix, filepath.ToSlash(relPath))
		if !strings.HasPrefix(fullVirtualPath, "/") {
			fullVirtualPath = "/" + fullVirtualPath
		}

		info, err := d.Info()
		if err != nil {
			return fn(fullVirtualPath, nil, err)
		}
		return fn(fullVirtualPath, info, nil)
	})
}

func (s *OSFileSource) walkSingleFileRoot(requestedPath string, fn func(sourcePath string, info fs.FileInfo, err error) error) error {
	stat, err := os.Stat(s.singleRoot)
	if err != nil {
		return err
	}
	filePath := "/" + s.singleRootAlias
	if requestedPath == "/" {
		if err := fn("/", sourceDirInfo{name: "/", modTime: stat.ModTime()}, nil); err != nil {
			return err
		}
		return fn(filePath, virtualFileInfo{FileInfo: stat, name: s.singleRootAlias}, nil)
	}
	if requestedPath == filePath {
		return fn(filePath, virtualFileInfo{FileInfo: stat, name: s.singleRootAlias}, nil)
	}
	return os.ErrNotExist
}

func (s *OSFileSource) resolvePath(name string) (fullPath string, isVirtualRoot bool, err error) {
	name, err = cleanSourcePath(name)
	if err != nil {
		return "", false, err
	}

	if s.singleRoot != "" {
		if s.singleRootIsFile {
			if name == "/" {
				return "", true, nil
			}
			if strings.TrimPrefix(name, "/") == s.singleRootAlias {
				return s.singleRoot, false, nil
			}
			return "", false, os.ErrNotExist
		}
		return filepath.Join(s.singleRoot, sourceLocalRel(name)), false, nil
	}

	if name == "/" {
		return "", true, nil
	}

	parts := strings.SplitN(strings.TrimPrefix(name, "/"), "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", false, os.ErrNotExist
	}

	alias := parts[0]
	remainder := ""
	if len(parts) > 1 {
		remainder = parts[1]
	}

	for _, m := range s.mounts {
		if m.Alias == alias {
			return filepath.Join(m.RealPath, filepath.FromSlash(remainder)), false, nil
		}
	}
	return "", false, os.ErrNotExist
}

func cleanSourcePath(name string) (string, error) {
	clean := path.Clean(name)
	if clean == "." {
		clean = "/"
	}
	if strings.HasPrefix(clean, "..") {
		return "", ErrDirectoryTraversal
	}
	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}
	return clean, nil
}

func sourceLocalRel(name string) string {
	rel := strings.TrimPrefix(name, "/")
	if rel == "" {
		return "."
	}
	return filepath.FromSlash(rel)
}

func latestMountModTime(mounts []virtualMount) time.Time {
	var latest time.Time
	for _, m := range mounts {
		stat, err := os.Stat(m.RealPath)
		if err == nil && stat.ModTime().After(latest) {
			latest = stat.ModTime()
		}
	}
	return latest
}

func singleRootModTime(root string) time.Time {
	stat, err := os.Stat(root)
	if err != nil {
		return time.Time{}
	}
	return stat.ModTime()
}

type sourceDirInfo struct {
	name    string
	modTime time.Time
}

func (i sourceDirInfo) Name() string       { return i.name }
func (i sourceDirInfo) Size() int64        { return 0 }
func (i sourceDirInfo) Mode() fs.FileMode  { return fs.ModeDir | 0755 }
func (i sourceDirInfo) ModTime() time.Time { return i.modTime }
func (i sourceDirInfo) IsDir() bool        { return true }
func (i sourceDirInfo) Sys() any           { return nil }
