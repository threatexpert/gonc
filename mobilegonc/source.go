package mobilegonc

import (
	"encoding/json"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/threatexpert/gonc/v2/httpfileshare"
)

// AndroidFileSource is implemented by the Android layer. It is deliberately
// primitive because gomobile has a narrow Java interop surface.
type AndroidFileSource interface {
	Description() string
	Stat(name string) string
	ReadDir(name string) string
	Open(name string) int64
	Read(handle int64, maxBytes int) []byte
	Close(handle int64)
}

func newMobileFileSource(source AndroidFileSource) httpfileshare.FileSource {
	return &mobileFileSource{source: source}
}

type mobileFileSource struct {
	source AndroidFileSource
}

type mobileFileInfoJSON struct {
	Name          string `json:"name"`
	IsDir         bool   `json:"isDir"`
	Size          int64  `json:"size"`
	ModTimeMillis int64  `json:"modTimeMillis"`
}

type mobileFileInfo struct {
	name    string
	isDir   bool
	size    int64
	modTime time.Time
}

func (s *mobileFileSource) Description() string {
	if s.source == nil {
		return "mobile file source"
	}
	if desc := strings.TrimSpace(s.source.Description()); desc != "" {
		return desc
	}
	return "mobile file source"
}

func (s *mobileFileSource) Stat(name string) (fs.FileInfo, error) {
	if clean, err := cleanMobilePath(name); err != nil {
		return nil, err
	} else {
		name = clean
	}
	raw := s.source.Stat(name)
	if strings.TrimSpace(raw) == "" {
		return nil, fs.ErrNotExist
	}
	return parseMobileFileInfo(raw)
}

func (s *mobileFileSource) Open(name string) (fs.File, error) {
	info, err := s.Stat(name)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fs.ErrInvalid
	}
	handle := s.source.Open(name)
	if handle == 0 {
		return nil, fs.ErrPermission
	}
	return &mobileFile{source: s.source, handle: handle, info: info}, nil
}

func (s *mobileFileSource) ReadDir(name string) ([]fs.FileInfo, error) {
	if clean, err := cleanMobilePath(name); err != nil {
		return nil, err
	} else {
		name = clean
	}
	raw := s.source.ReadDir(name)
	if strings.TrimSpace(raw) == "" {
		return nil, fs.ErrNotExist
	}
	var values []mobileFileInfoJSON
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, err
	}
	out := make([]fs.FileInfo, 0, len(values))
	for _, value := range values {
		out = append(out, value.fileInfo())
	}
	return out, nil
}

func (s *mobileFileSource) Walk(name string, fn func(sourcePath string, info fs.FileInfo, err error) error) error {
	if clean, err := cleanMobilePath(name); err != nil {
		return err
	} else {
		name = clean
	}
	info, err := s.Stat(name)
	if err != nil {
		return err
	}
	return s.walk(name, info, fn)
}

func (s *mobileFileSource) walk(name string, info fs.FileInfo, fn func(sourcePath string, info fs.FileInfo, err error) error) error {
	if err := fn(name, info, nil); err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	children, err := s.ReadDir(name)
	if err != nil {
		return fn(name, nil, err)
	}
	for _, child := range children {
		childPath := path.Join(name, child.Name())
		if !strings.HasPrefix(childPath, "/") {
			childPath = "/" + childPath
		}
		if err := s.walk(childPath, child, fn); err != nil {
			return err
		}
	}
	return nil
}

func parseMobileFileInfo(raw string) (fs.FileInfo, error) {
	var value mobileFileInfoJSON
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, err
	}
	return value.fileInfo(), nil
}

func (v mobileFileInfoJSON) fileInfo() fs.FileInfo {
	name := strings.TrimSpace(v.Name)
	if name == "" {
		name = "shared-file"
	}
	modTime := time.Time{}
	if v.ModTimeMillis > 0 {
		modTime = time.UnixMilli(v.ModTimeMillis)
	}
	size := v.Size
	if v.IsDir {
		size = 0
	}
	return mobileFileInfo{name: name, isDir: v.IsDir, size: size, modTime: modTime}
}

func cleanMobilePath(name string) (string, error) {
	clean := path.Clean(name)
	if clean == "." {
		clean = "/"
	}
	if strings.HasPrefix(clean, "..") {
		return "", httpfileshare.ErrDirectoryTraversal
	}
	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}
	return clean, nil
}

func (i mobileFileInfo) Name() string { return i.name }
func (i mobileFileInfo) Size() int64  { return i.size }
func (i mobileFileInfo) Mode() fs.FileMode {
	if i.isDir {
		return fs.ModeDir | 0755
	}
	return 0644
}
func (i mobileFileInfo) ModTime() time.Time { return i.modTime }
func (i mobileFileInfo) IsDir() bool        { return i.isDir }
func (i mobileFileInfo) Sys() any           { return nil }

type mobileFile struct {
	source AndroidFileSource
	handle int64
	info   fs.FileInfo
	closed bool
}

func (f *mobileFile) Stat() (fs.FileInfo, error) {
	return f.info, nil
}

func (f *mobileFile) Read(p []byte) (int, error) {
	if f.closed {
		return 0, fs.ErrClosed
	}
	chunk := f.source.Read(f.handle, len(p))
	if len(chunk) == 0 {
		return 0, io.EOF
	}
	return copy(p, chunk), nil
}

func (f *mobileFile) Close() error {
	if !f.closed {
		f.closed = true
		f.source.Close(f.handle)
	}
	return nil
}
