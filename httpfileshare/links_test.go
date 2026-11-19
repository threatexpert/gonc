package httpfileshare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func linkFixture(t *testing.T) (string, *Server) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{".bin", "pkg"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(root, "pkg", "cli.js")
	if err := os.WriteFile(target, []byte("target file contents, not the link text"), 0644); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1700001000, 123456700)
	if err := os.Chtimes(target, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := createReceiverSymlink(filepath.FromSlash("../pkg/cli.js"), filepath.Join(root, ".bin", "cli"), false); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := createReceiverSymlink("pkg", filepath.Join(root, "pkg-link"), true); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{RootPaths: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	return root, server
}
func readTestList(t *testing.T, server *Server) map[string]FileInfo {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	server.serveFilesFromSource(rr, req)
	if rr.Code != 200 {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	for key := range rr.Header() {
		if strings.Contains(strings.ToLower(key), "features") {
			t.Fatalf("unexpected capability header %s", key)
		}
	}
	entries := make(map[string]FileInfo)
	decoder := json.NewDecoder(rr.Body)
	for {
		var file FileInfo
		if err := decoder.Decode(&file); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		entries[file.Path] = file
	}
	return entries
}
func TestLinkListIncludesTargetPermissions(t *testing.T) {
	root, server := linkFixture(t)
	entries := readTestList(t, server)
	actual, err := os.Stat(filepath.Join(root, "pkg", "cli.js"))
	if err != nil {
		t.Fatal(err)
	}
	link := entries["/.bin/cli"]
	if link.LinkTarget != "../pkg/cli.js" || link.IsDir || link.Size != actual.Size() || !link.ModTime.Equal(actual.ModTime()) {
		t.Fatalf("link=%+v", link)
	}
	if !entries["/pkg-link"].IsDir || entries["/pkg-link"].LinkTarget != "pkg" {
		t.Fatal("missing directory link")
	}
	if _, ok := entries["/pkg-link/cli.js"]; ok {
		t.Fatal("directory link expanded eagerly")
	}
	for _, name := range []string{"/pkg/cli.js", "/.bin/cli", "/pkg-link"} {
		body, err := json.Marshal(entries[name])
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatal(err)
		}
		want := 6
		if entries[name].Mode == nil {
			t.Fatalf("missing target mode: %s", body)
		}
		if entries[name].LinkTarget != "" {
			want++
		}
		if len(fields) != want {
			t.Fatalf("unexpected fields: %s", body)
		}
	}
}
func TestAutoReceiveLinksAndRepeatWithoutContentRequests(t *testing.T) {
	_, source := linkFixture(t)
	var contents, manifests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key := range r.Header {
			if strings.Contains(strings.ToLower(key), "features") {
				t.Errorf("capability header %s", key)
			}
		}
		if r.URL.Query().Get("manifest") != "" {
			manifests.Add(1)
		}
		if r.Header.Get("Accept") != "application/json" {
			contents.Add(1)
		}
		source.serveFilesFromSource(w, r)
	}))
	defer server.Close()
	dest := t.TempDir()
	for pass := 0; pass < 2; pass++ {
		client, err := newTestClient(server.URL, dest)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		link, err := os.Readlink(filepath.Join(dest, ".bin", "cli"))
		if err != nil || filepath.ToSlash(link) != "../pkg/cli.js" {
			t.Fatalf("link %s %v", link, err)
		}
		info, err := os.Stat(filepath.Join(dest, "pkg-link"))
		if err != nil || !info.IsDir() {
			t.Fatalf("directory link %v %v", info, err)
		}
		if contents.Load() != 1 || manifests.Load() != 0 {
			t.Fatalf("pass %d downloads=%d manifests=%d", pass, contents.Load(), manifests.Load())
		}
	}
}
func TestAutoReceiveKeepsLinkWhenTargetExcluded(t *testing.T) {
	_, source := linkFixture(t)
	server := httptest.NewServer(http.HandlerFunc(source.serveFilesFromSource))
	defer server.Close()
	dest := t.TempDir()
	client, err := newTestClient(server.URL, dest)
	if err != nil {
		t.Fatal(err)
	}
	client.config.Include = []string{"/.bin/*"}
	if err := client.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Readlink(filepath.Join(dest, ".bin", "cli")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "pkg", "cli.js")); !os.IsNotExist(err) {
		t.Fatalf("excluded target downloaded: %v", err)
	}
}
func TestAutoReceiveExternalDirectoryAndNestedLinks(t *testing.T) {
	root, source := linkFixture(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "data"), []byte("external contents"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := createReceiverSymlink("data", filepath.Join(outside, "copy"), false); err != nil {
		t.Fatal(err)
	}
	if err := createReceiverSymlink(outside, filepath.Join(root, "external"), true); err != nil {
		t.Fatal(err)
	}
	var expanded, contents, manifests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/external" && r.Header.Get("Accept") == "application/json" {
			expanded.Add(1)
		}
		if r.URL.Query().Get("manifest") != "" {
			manifests.Add(1)
		}
		if r.Header.Get("Accept") != "application/json" {
			contents.Add(1)
		}
		source.serveFilesFromSource(w, r)
	}))
	defer server.Close()
	dest := t.TempDir()
	for pass := 0; pass < 2; pass++ {
		client, err := newTestClient(server.URL, dest)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(filepath.Join(dest, "external"))
		if err != nil || !info.IsDir() {
			t.Fatalf("external directory %v %v", info, err)
		}
		body, err := os.ReadFile(filepath.Join(dest, "external", "data"))
		if err != nil || string(body) != "external contents" {
			t.Fatalf("contents %q %v", body, err)
		}
		link, err := os.Readlink(filepath.Join(dest, "external", "copy"))
		if err != nil || link != "data" {
			t.Fatalf("nested link %s %v", link, err)
		}
		if contents.Load() != 2 || manifests.Load() != 0 {
			t.Fatalf("repeat downloaded=%d manifests=%d", contents.Load(), manifests.Load())
		}
	}
	if expanded.Load() != 2 {
		t.Fatalf("expansions=%d", expanded.Load())
	}
}
func TestMultiRootAliasesRebaseLinkTarget(t *testing.T) {
	base := t.TempDir()
	app := filepath.Join(base, "work", "app")
	lib := filepath.Join(base, "work", "lib")
	other := filepath.Join(base, "backup", "lib")
	for _, dir := range []string{app, lib, other} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(lib, "tool"), []byte("correct"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "tool"), []byte("wrong"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := createReceiverSymlink(filepath.FromSlash("../lib/tool"), filepath.Join(app, "start"), false); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	source, err := NewServer(ServerConfig{RootPaths: []string{app, other, lib}})
	if err != nil {
		t.Fatal(err)
	}
	entries := readTestList(t, source)
	if entries["/app/start"].LinkTarget != "../lib-2/tool" {
		t.Fatalf("mapped link %+v", entries["/app/start"])
	}
	original, err := os.Readlink(filepath.Join(app, "start"))
	if err != nil || filepath.ToSlash(original) != "../lib/tool" {
		t.Fatal("source link changed")
	}
	server := httptest.NewServer(http.HandlerFunc(source.serveFilesFromSource))
	defer server.Close()
	dest := t.TempDir()
	client, err := newTestClient(server.URL, dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dest, "app", "start"))
	if err != nil || string(body) != "correct" {
		t.Fatalf("wrong target %q %v", body, err)
	}
}
func TestExternalFileLinkReceivesContents(t *testing.T) {
	root, source := linkFixture(t)
	outside := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(outside, []byte("external"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := createReceiverSymlink(outside, filepath.Join(root, "absolute"), false); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(source.serveFilesFromSource))
	defer server.Close()
	dest := t.TempDir()
	client, err := newTestClient(server.URL, dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(dest, "absolute"))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("fallback %v %v", info, err)
	}
	body, err := os.ReadFile(filepath.Join(dest, "absolute"))
	if err != nil || string(body) != "external" {
		t.Fatalf("contents %q %v", body, err)
	}
}
func TestNewReceiverWithOldList(t *testing.T) {
	root := t.TempDir()
	stamp := time.Unix(1700001000, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "application/json" {
			_ = json.NewEncoder(w).Encode(FileInfo{Path: "/file", Name: "file", Size: 3, ModTime: stamp})
			return
		}
		_, _ = io.WriteString(w, "old")
	}))
	defer server.Close()
	client, err := newTestClient(server.URL, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, "file"))
	if err != nil || string(body) != "old" {
		t.Fatalf("legacy %q %v", body, err)
	}
}
func TestDirectoryLinkCycleAndBrokenLinkDoNotStopOtherFiles(t *testing.T) {
	for _, kind := range []string{"cycle", "broken"} {
		t.Run(kind, func(t *testing.T) {
			root, source := linkFixture(t)
			if kind == "cycle" {
				a, b := t.TempDir(), t.TempDir()
				if err := createReceiverSymlink(b, filepath.Join(a, "b"), true); err != nil {
					t.Fatal(err)
				}
				if err := createReceiverSymlink(a, filepath.Join(b, "a"), true); err != nil {
					t.Fatal(err)
				}
				if err := createReceiverSymlink(a, filepath.Join(root, "external"), true); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := createReceiverSymlink("missing", filepath.Join(root, "broken"), false); err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(source.serveFilesFromSource))
			defer server.Close()
			client, err := newTestClient(server.URL, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = client.Start(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(client.config.LocalDir, "pkg", "cli.js")); err != nil {
				t.Fatal(err)
			}
			skipped := "broken"
			if kind == "cycle" {
				skipped = filepath.Join("external", "b", "a")
			}
			if _, err := os.Lstat(filepath.Join(client.config.LocalDir, skipped)); !os.IsNotExist(err) {
				t.Fatalf("expected %s to be skipped: %v", skipped, err)
			}
		})
	}
}
func TestReceiverWithoutLinkSupportExpandsDirectoryLinks(t *testing.T) {
	_, source := linkFixture(t)
	server := httptest.NewServer(http.HandlerFunc(source.serveFilesFromSource))
	defer server.Close()
	dest := t.TempDir()
	client, err := newTestClient(server.URL, dest)
	if err != nil {
		t.Fatal(err)
	}
	client.linkCreationAvailable = false
	files, err := client.fetchFileList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if err := client.downloadFile(context.Background(), server.Client(), file); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(".bin", "cli"), filepath.Join("pkg-link", "cli.js")} {
		info, err := os.Lstat(filepath.Join(dest, name))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("content %s %v %v", name, info, err)
		}
	}
}
func TestPlanReceiveDoesNotUseSelectionOrCreateEscapingLinks(t *testing.T) {
	files := []FileInfo{{Path: "/pkg/file"}, {Path: "/bin/link", LinkTarget: "../pkg/file"}, {Path: "/escape", LinkTarget: "../pkg/file"}, {Path: "/outside", IsDir: true, LinkTarget: "/other"}}
	plan, err := PlanReceive(files)
	if err != nil {
		t.Fatal(err)
	}
	if plan[1].Action != ReceiveLink || plan[2].Action != ReceiveContent || plan[3].Action != ReceiveDirectory {
		t.Fatalf("plan %+v", plan)
	}
}
func TestSelectedRootDirectoryLinkExpands(t *testing.T) {
	parent := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "file"), []byte("root link contents"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "selected")
	if err := createReceiverSymlink(outside, link, true); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	source, err := NewServer(ServerConfig{RootPaths: []string{link}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(source.serveFilesFromSource))
	defer server.Close()
	dest := t.TempDir()
	client, err := newTestClient(server.URL, dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dest, "selected", "file"))
	if err != nil || string(body) != "root link contents" {
		t.Fatalf("root contents %q %v", body, err)
	}
}

func TestDirectoryMaterializationDoesNotWriteThroughExistingLink(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	dest := t.TempDir()
	localOutside := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "file"), []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localOutside, "file"), []byte("untouched"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := createReceiverSymlink(external, filepath.Join(root, "dir"), true); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := createReceiverSymlink(localOutside, filepath.Join(dest, "dir"), true); err != nil {
		t.Fatal(err)
	}
	source, err := NewServer(ServerConfig{RootPaths: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(source.serveFilesFromSource))
	defer server.Close()
	client, err := newTestClient(server.URL, dest)
	if err != nil {
		t.Fatal(err)
	}
	client.config.Include = []string{"/dir/file"}
	if err := client.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(localOutside, "file"))
	if err != nil || string(body) != "untouched" {
		t.Fatalf("wrote through directory link %q %v", body, err)
	}
	body, err = os.ReadFile(filepath.Join(dest, "dir", "file"))
	if err != nil || string(body) != "new" {
		t.Fatalf("received %q %v", body, err)
	}
}

func TestRootAliasesRemainUniqueAgainstLiteralSuffix(t *testing.T) {
	base := t.TempDir()
	roots := []string{filepath.Join(base, "a", "lib"), filepath.Join(base, "b", "lib-2"), filepath.Join(base, "c", "lib")}
	for _, root := range roots {
		if err := os.MkdirAll(root, 0755); err != nil {
			t.Fatal(err)
		}
	}
	source, err := NewOSFileSource(roots)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, mount := range source.mounts {
		if seen[mount.Alias] {
			t.Fatalf("duplicate alias %s", mount.Alias)
		}
		seen[mount.Alias] = true
	}
}
