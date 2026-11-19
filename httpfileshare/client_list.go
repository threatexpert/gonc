package httpfileshare

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
)

// A truncated response cannot supply a usable listing, including when the
// request was made to expand a directory link.
type listReadError struct{ cause error }

func (e *listReadError) Error() string { return e.cause.Error() }
func (e *listReadError) Unwrap() error { return e.cause }

func (c *Client) fetchListing(ctx context.Context, name string) ([]FileInfo, error) {
	base, err := url.Parse(c.config.ServerURL)
	if err != nil {
		return nil, err
	}
	ref, err := url.Parse(encodePathSegmentPreservingSlashes(name))
	if err != nil {
		return nil, err
	}
	u := base.ResolveReference(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	c.setAcceptEncodingForCompress(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("file list %s: %s", name, resp.Status)
	}
	reader, closeReader, err := c.decodedResponseReader(resp, "file list", true)
	if err != nil {
		return nil, err
	}
	defer closeReader()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	var files []FileInfo
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var file FileInfo
		if err := json.Unmarshal(scanner.Bytes(), &file); err != nil {
			c.logError("Skipping invalid file list record in %s: %v", name, err)
			continue
		}
		files = append(files, file)
	}
	if err := scanner.Err(); err != nil {
		return nil, &listReadError{err}
	}
	return files, nil
}

// Cache ancestry from the immutable action snapshot, not filesystem state.
func (c *Client) preservedLinkLookup() func(string) bool {
	cache := make(map[string]bool)
	var contains func(string) bool
	contains = func(dir string) bool {
		if result, ok := cache[dir]; ok {
			return result
		}
		result := c.receiveActions[dir] == ReceiveLink
		if !result && dir != "/" {
			result = contains(path.Dir(dir))
		}
		cache[dir] = result
		return result
	}
	return func(name string) bool { return name != "/" && contains(path.Dir(name)) }
}

// The initial listing is complete before selection. Expand directory links in
// batches, indexing and planning only new entries. Earlier decisions stay fixed.
func (c *Client) fetchFileList(ctx context.Context) ([]FileInfo, error) {
	u, err := url.Parse(c.config.ServerURL)
	if err != nil {
		return nil, err
	}
	name := path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
	files, err := c.fetchListing(ctx, name)
	if err != nil {
		return nil, err
	}
	planner, err := buildReceivePlanner(files, c.logError)
	if err != nil {
		return nil, err
	}
	c.receiveActions = make(map[string]ReceiveAction, len(files))
	depth := make(map[string]int) // only directory links need expansion-depth tracking
	first := 0
	for {
		planner.visitFrom(first, func(file FileInfo, action ReceiveAction) {
			if action == ReceiveLink && !c.linkCreationAvailable {
				action = ReceiveContent
				if file.IsDir {
					action = ReceiveDirectory
				}
				c.logRepair("Cannot create links at destination; receiving contents of %s", file.Path)
			}
			c.receiveActions[file.Path] = action
		})
		beneathLink := c.preservedLinkLookup()
		var pending []FileInfo
		for _, file := range planner.files[first:] {
			if file.IsDir && file.LinkTarget != "" && c.receiveActions[file.Path] == ReceiveDirectory && !beneathLink(file.Path) && !c.shouldExclude(file.Path) {
				pending = append(pending, file)
			}
		}
		if len(pending) == 0 {
			break
		}
		first = len(planner.files)
		for _, file := range pending {
			if planner.omitted(file.Path) {
				continue
			}
			var descendants []FileInfo
			var err error
			if depth[file.Path] >= 64 {
				err = fmt.Errorf("directory link expansion too deep")
			} else {
				descendants, err = c.fetchDirectoryLink(ctx, file.Path)
			}
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				var readErr *listReadError
				if file.Path == name || errors.As(err, &readErr) {
					return nil, err
				}
				if err := planner.reject(file.Path, err); err != nil {
					return nil, err
				}
				continue
			}
			for _, child := range descendants {
				if child.IsDir && child.LinkTarget != "" {
					depth[child.Path] = depth[file.Path] + 1
				}
			}
			if err := planner.add(descendants); err != nil {
				return nil, err
			}
		}
	}
	selected := make([]bool, len(planner.files))
	parentSelected := make(map[string]bool)
	beneathLink := c.preservedLinkLookup()
	for i, file := range planner.files {
		if planner.omitted(file.Path) || beneathLink(file.Path) || !c.shouldInclude(file.Path) || c.shouldExclude(file.Path) {
			continue
		}
		selected[i] = true
		// Check each distinct parent chain once, including inferred parents absent
		// from the list. Selecting a link never selects the link's target.
		for parent := path.Dir(file.Path); parent != "/"; parent = path.Dir(parent) {
			if parentSelected[parent] {
				break
			}
			parentSelected[parent] = true
			if c.receiveActions[parent] == ReceiveDirectory {
				selected[planner.index[parent]] = true
			}
		}
	}
	// Compact our owned listing instead of copying every selected FileInfo again.
	result := planner.files[:0]
	var totalBytes int64
	for i, file := range planner.files {
		if !selected[i] {
			continue
		}
		result = append(result, file)
		if c.receiveActions[file.Path] == ReceiveContent && file.Size > 0 {
			totalBytes += file.Size
		}
	}
	clear(planner.files[len(result):])
	c.progressTracker.totalFiles.Add(int64(len(result)))
	c.progressTracker.AddTotalBytes(totalBytes)
	return result, nil
}

func (c *Client) fetchDirectoryLink(ctx context.Context, name string) ([]FileInfo, error) {
	children, err := c.fetchListing(ctx, name)
	if err != nil {
		return nil, err
	}
	foundRoot := false
	prefix := name + "/"
	descendants := children[:0]
	for _, child := range children {
		if child.Path == name {
			if foundRoot || !child.IsDir || child.LinkTarget != "" {
				return nil, fmt.Errorf("invalid expanded directory root %s", name)
			}
			foundRoot = true
			continue
		}
		if !strings.HasPrefix(child.Path, prefix) {
			return nil, fmt.Errorf("expanded path escaped %s", name)
		}
		descendants = append(descendants, child)
	}
	if !foundRoot {
		return nil, fmt.Errorf("directory link listing missing root %s", name)
	}
	return descendants, nil
}

type receiveDirectory struct{ index, depth int }

// Only directories need parent-before-child ordering. Sort small index records;
// files and links retain their listing order and never participate in the sort.
func orderedReceiveDirectories(files []FileInfo, actions map[string]ReceiveAction) []receiveDirectory {
	var dirs []receiveDirectory
	for i, file := range files {
		if file.IsDir && actions[file.Path] == ReceiveDirectory {
			dirs = append(dirs, receiveDirectory{index: i, depth: strings.Count(file.Path, "/")})
		}
	}
	if len(dirs) > 1 {
		sort.SliceStable(dirs, func(i, j int) bool { return dirs[i].depth < dirs[j].depth })
	}
	return dirs
}
