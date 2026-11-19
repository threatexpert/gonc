package httpfileshare

import (
	"fmt"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

type ReceiveAction string

const (
	ReceiveContent   ReceiveAction = "content"
	ReceiveDirectory ReceiveAction = "directory"
	ReceiveLink      ReceiveAction = "link"
)

type ReceiveEntry struct {
	File   FileInfo
	Action ReceiveAction
}

// PlanReceive uses the complete listing before user selection. Paths must map
// unchanged beneath the receiving root. Root aliases are already in LinkTarget.
func PlanReceive(files []FileInfo) ([]ReceiveEntry, error) {
	planner, err := newReceivePlanner(files)
	if err != nil {
		return nil, err
	}
	plan := make([]ReceiveEntry, 0, len(files))
	planner.visitFrom(0, func(file FileInfo, action ReceiveAction) {
		plan = append(plan, ReceiveEntry{File: file, Action: action})
	})
	return plan, nil
}

// One index is retained while directory links are expanded. Store positions,
// rather than another copy of every FileInfo. requiredDirs includes inferred
// parents, so a later batch cannot introduce a file at an existing parent path.
type receivePlanner struct {
	files        []FileInfo
	index        map[string]int
	requiredDirs map[string]bool
	rejected     map[string]bool
	logSkip      func(string, ...any)
}

func newReceivePlanner(files []FileInfo) (*receivePlanner, error) {
	return buildReceivePlanner(files, nil)
}

func buildReceivePlanner(files []FileInfo, logSkip func(string, ...any)) (*receivePlanner, error) {
	p := &receivePlanner{logSkip: logSkip, files: files, index: make(map[string]int, len(files)), requiredDirs: make(map[string]bool)}
	if err := p.indexFrom(0); err != nil {
		return nil, err
	}
	return p, nil
}
func (p *receivePlanner) add(files []FileInfo) error {
	first := len(p.files)
	p.files = append(p.files, files...)
	return p.indexFrom(first)
}

// The downloader logs conflicting entries and omits their entire subtree.
func (p *receivePlanner) reject(name string, err error) error {
	if p.logSkip == nil {
		return err
	}
	if p.rejected == nil {
		p.rejected = make(map[string]bool)
	}
	if !p.rejected[name] {
		p.logSkip("Skipping %q: %v", name, err)
		p.rejected[name] = true
	}
	return nil
}

func (p *receivePlanner) omitted(name string) bool {
	if len(p.rejected) == 0 {
		return false
	}
	if p.rejected[name] {
		return true
	}
	if !validVirtualPath(name) {
		return true
	}
	for name != "/" {
		name = path.Dir(name)
		if p.rejected[name] {
			return true
		}
	}
	return false
}
func (p *receivePlanner) indexFrom(first int) error {
	for i := first; i < len(p.files); i++ {
		file := p.files[i]
		if !validVirtualPath(file.Path) {
			if err := p.reject(file.Path, fmt.Errorf("invalid list path %q", file.Path)); err != nil {
				return err
			}
			continue
		}
		if _, exists := p.index[file.Path]; exists {
			if err := p.reject(file.Path, fmt.Errorf("duplicate list path %q", file.Path)); err != nil {
				return err
			}
			continue
		}
		if p.requiredDirs[file.Path] && !file.IsDir {
			if err := p.reject(file.Path, fmt.Errorf("non-directory parent %q", file.Path)); err != nil {
				return err
			}
			continue
		}
		p.index[file.Path] = i
	}
	for _, file := range p.files[first:] {
		if p.omitted(file.Path) {
			continue
		}
		for parent := path.Dir(file.Path); parent != "/"; parent = path.Dir(parent) {
			if p.requiredDirs[parent] {
				break
			}
			if i, exists := p.index[parent]; exists && !p.files[i].IsDir {
				if err := p.reject(parent, fmt.Errorf("non-directory parent %q", parent)); err != nil {
					return err
				}
				break
			}
			p.requiredDirs[parent] = true
		}
	}
	return nil
}

type linkResolution struct {
	internal bool
	hops     int
}

func (p *receivePlanner) visitFrom(first int, visit func(FileInfo, ReceiveAction)) {
	// Memoize shared suffixes only within this batch. A later expansion can add
	// previously missing targets, but must not change actions already selected.
	memo := make(map[string]linkResolution)
	visiting := make(map[string]bool)
	var resolve func(string, int) (linkResolution, bool)
	resolve = func(name string, remaining int) (linkResolution, bool) {
		if remaining == 0 {
			return linkResolution{}, false
		}
		if result, ok := memo[name]; ok {
			return result, true
		}
		i, exists := p.index[name]
		if !exists || visiting[name] || p.omitted(name) {
			return linkResolution{}, true
		}
		entry := p.files[i]
		if entry.LinkTarget == "" {
			return linkResolution{internal: true}, true
		}
		target, ok := relativeLinkPath(name, entry.LinkTarget)
		if !ok {
			memo[name] = linkResolution{}
			return linkResolution{}, true
		}
		visiting[name] = true
		result, complete := resolve(target, remaining-1)
		delete(visiting, name)
		if result.internal {
			result.hops++
		}
		// A depth-limited attempt cannot classify the suffix: it might be short
		// enough when reached from another root. Only complete results are reusable.
		if complete {
			memo[name] = result
		}
		return result, complete
	}
	for _, file := range p.files[first:] {
		if p.omitted(file.Path) {
			continue
		}
		action := ReceiveContent
		if file.IsDir {
			action = ReceiveDirectory
		}
		if file.LinkTarget != "" {
			if result, _ := resolve(file.Path, 64); result.internal && result.hops < 64 {
				action = ReceiveLink
			}
		}
		visit(file, action)
	}
}

func relativeLinkPath(name, target string) (string, bool) {
	if !portableRelativeLink(target) {
		return "", false
	}
	joined := path.Clean(path.Join(strings.TrimPrefix(path.Dir(name), "/"), target))
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return "", false
	}
	return path.Clean("/" + joined), true
}
func validVirtualPath(name string) bool {
	if !strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.IndexByte(name, 0) >= 0 {
		return false
	}
	if name == "/" {
		return true
	}
	if runtime.GOOS == "windows" && strings.ContainsAny(name, `<>:"|?*\`) {
		return false
	}
	_, err := filepath.Localize(name[1:])
	return err == nil
}
