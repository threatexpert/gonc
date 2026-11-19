package httpfileshare

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

func probeSymlinkCreation(root string) bool {
	dir, err := os.MkdirTemp(root, ".gonc-link-probe-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)
	return createReceiverSymlink("missing-file", filepath.Join(dir, "file-link"), false) == nil && createReceiverSymlink("missing-dir", filepath.Join(dir, "dir-link"), true) == nil
}

// Replace the link entry, never truncate or repair the file it points to.
func (c *Client) receiveContentOverLink(ctx context.Context, client *http.Client, file FileInfo, full string) error {
	if !c.config.Resume && !c.config.Overwrite {
		c.logInfo("Skipping existing link: %s", file.Path)
		return nil
	}
	if c.config.DryRun {
		c.logInfo("Dry run: Would replace link with contents: %s", file.Path)
		return nil
	}
	base, err := url.Parse(c.config.ServerURL)
	if err != nil {
		return err
	}
	ref, err := url.Parse(encodePathSegmentPreservingSlashes(file.Path))
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(full), ".gonc-content-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := c.downloadFullFile(ctx, client, base.ResolveReference(ref).String(), tmpName, file); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.checkReceiveParents(full); err != nil {
		return err
	}
	return os.Rename(tmpName, full)
}

// Do not write through links already present at the destination, including
// directory links created by another item. Expanded remote directories are materialized before writing their children.
func (c *Client) checkReceiveParents(full string) error {
	parent := filepath.Dir(full)
	if full == c.absLocalDownloadRoot {
		parent = full
	}
	for {
		info, err := os.Lstat(parent)
		if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return fmt.Errorf("linked or non-directory parent: %s", parent)
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if parent == c.absLocalDownloadRoot {
			return nil
		}
		next := filepath.Dir(parent)
		if next == parent {
			return fmt.Errorf("receiving path outside root")
		}
		parent = next
	}
}

func (c *Client) receiveLink(ctx context.Context, client *http.Client, file FileInfo, full string) error {
	info, err := os.Lstat(full)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			current, err := os.Readlink(full)
			if err != nil {
				return err
			}
			if filepath.ToSlash(current) == file.LinkTarget {
				c.logVerbose("Link already matches: %s", file.Path)
				return nil
			}
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("directory or special-file conflict at %s", file.Path)
		}
		if !c.config.Overwrite && !c.config.Resume {
			c.logInfo("Skipping existing path (use -o to overwrite): %s", file.Path)
			return nil
		}
	}
	if c.config.DryRun {
		c.logInfo("Dry run: Would create link %s -> %s", file.Path, file.LinkTarget)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		return err
	}
	// Prepare a link beside the destination before replacing any existing file.
	tmp, err := os.CreateTemp(filepath.Dir(full), ".gonc-link-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Remove(tmpName); err != nil {
		return err
	}
	defer os.Remove(tmpName)
	isDir := file.IsDir
	if err := createReceiverSymlink(filepath.FromSlash(file.LinkTarget), tmpName, isDir); err != nil {
		if file.IsDir {
			return fmt.Errorf("cannot create directory link %s: %w", file.Path, err)
		}
		c.logRepair("Cannot create link %s; receiving contents: %v", file.Path, err)
		c.receiveActions[file.Path] = ReceiveContent
		if file.Size > 0 {
			c.progressTracker.AddTotalBytes(file.Size)
		}
		return c.downloadFile(ctx, client, file)

	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.checkReceiveParents(full); err != nil {
		return err
	}
	return os.Rename(tmpName, full)
}
