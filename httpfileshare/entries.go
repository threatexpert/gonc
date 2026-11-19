package httpfileshare

import (
	"io/fs"
	"time"
)

// LinkFileSource is optional. Readlink returns a relative target in the exported
// tree, or an absolute target when content must be received instead.
type LinkFileSource interface {
	Lstat(string) (fs.FileInfo, error)
	Readlink(string) (string, error)
}

func (s *Server) describeEntry(name string, info fs.FileInfo) (FileInfo, bool, error) {
	file := FileInfo{Name: info.Name(), Path: name, IsDir: info.IsDir(), Size: info.Size(), ModTime: info.ModTime()}
	if info.Mode()&fs.ModeSymlink != 0 {
		if source, ok := s.source.(LinkFileSource); ok {
			target, err := source.Readlink(name)
			if err != nil {
				return file, false, err
			}
			file.LinkTarget = target
		}
		target, err := s.source.Stat(name)
		if err != nil {
			// Keep broken links visible; their content request will report the failure.
			file.Size, file.ModTime = -1, time.Time{}
			return file, true, nil
		}
		info = target
		file.IsDir, file.Size, file.ModTime = info.IsDir(), info.Size(), info.ModTime()
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		s.logger.Printf("Skipping special file %s", name)
		return file, false, nil
	}
	// Virtual roots and document providers can expose synthetic modes without
	// filesystem attributes. Leave those permissions unspecified on the wire.
	if (name != "/" || !info.IsDir()) && info.Sys() != nil {
		mode := uint32(info.Mode().Perm())
		file.Mode = &mode
	}
	return file, true, nil
}
