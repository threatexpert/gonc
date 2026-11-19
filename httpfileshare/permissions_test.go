package httpfileshare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestPermissionWireCompatibility(t *testing.T) {
	for _, mode := range []uint32{0, 0755} {
		wire, err := json.Marshal(FileInfo{Path: "/build.sh", Mode: &mode})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(wire, &fields); err != nil || fields["mode"] != float64(mode) {
			t.Fatalf("wire %s: %v", wire, err)
		}
		// The previous receiver used the standard JSON decoder with this field absent.
		var old struct {
			Path string
			Size int64
		}
		if err := json.Unmarshal(wire, &old); err != nil || old.Path != "/build.sh" {
			t.Fatalf("legacy decode: %+v, %v", old, err)
		}
		var current FileInfo
		if err := json.Unmarshal(wire, &current); err != nil || current.Mode == nil || *current.Mode != mode {
			t.Fatalf("decode: %+v, %v", current, err)
		}
	}
	var old FileInfo
	if err := json.Unmarshal([]byte(`{"path":"/build.sh","size":1}`), &old); err != nil || old.Mode != nil {
		t.Fatalf("legacy list: %+v %v", old, err)
	}
}

func TestReceivePermissionsWithoutDownloadingAgain(t *testing.T) {
	ctx := context.Background()
	src, dst := t.TempDir(), t.TempDir()
	dir := filepath.Join(src, "scripts")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "build.sh")
	if err := os.WriteFile(name, []byte("abc"), 0644); err != nil {
		t.Fatal(err)
	}
	want := os.FileMode(0550)
	if runtime.GOOS == "windows" {
		want = 0444
	}
	if err := os.Chmod(name, want); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	destDir := filepath.Join(dst, "scripts")
	dest := filepath.Join(destDir, "build.sh")
	t.Cleanup(func() { os.Chmod(dir, 0755); os.Chmod(name, 0600); os.Chmod(destDir, 0755); os.Chmod(dest, 0600) })
	s, err := NewServer(ServerConfig{RootPaths: []string{src}, LoggerOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	var gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/scripts/build.sh" {
			gets.Add(1)
		}
		s.serveFilesFromSource(w, r)
	}))
	defer server.Close()
	run := func() {
		t.Helper()
		c, err := newTestClient(server.URL, dst)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	run()
	check := func() {
		t.Helper()
		for _, pair := range [][2]string{{name, dest}, {dir, destDir}} {
			a, err := os.Stat(pair[0])
			if err != nil {
				t.Fatal(err)
			}
			b, err := os.Stat(pair[1])
			if err != nil {
				t.Fatal(err)
			}
			want := uint32(a.Mode().Perm())
			if PermissionsDiffer(&want, b.Mode()) {
				t.Fatalf("%s: got %o want %o", pair[1], b.Mode().Perm(), a.Mode().Perm())
			}
		}
	}
	check()
	if n := gets.Swap(0); n != 1 {
		t.Fatalf("initial content requests: %d", n)
	}
	if err := os.Chmod(dest, 0600); err != nil {
		t.Fatal(err)
	}
	run()
	check()
	if n := gets.Load(); n != 0 {
		t.Fatalf("permission-only run made %d file requests", n)
	}
}

func TestApplyPermissionsZeroAndLink(t *testing.T) {
	root := t.TempDir()
	full := filepath.Join(root, "data")
	if err := os.WriteFile(full, nil, 0600); err != nil {
		t.Fatal(err)
	}
	zero := uint32(0)
	if err := ApplyPermissions(root, full, &zero, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(full)
	if err != nil || PermissionsDiffer(&zero, info.Mode()) {
		t.Fatalf("zero mode: %v, %v", info, err)
	}
	write := uint32(0600)
	if err := ApplyPermissions(root, full, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := ApplyPermissions(root, full, &write, false); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(full, link); err != nil {
		t.Skipf("cannot create test link: %v", err)
	}
	if err := ApplyPermissions(root, link, &zero, false); err == nil {
		t.Fatal("accepted chmod of link")
	}
	info, err = os.Stat(full)
	if err != nil || PermissionsDiffer(&write, info.Mode()) {
		t.Fatalf("link target mode: %v, %v", info, err)
	}
}
