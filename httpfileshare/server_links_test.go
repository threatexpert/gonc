package httpfileshare

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserDirectoryLinks(t *testing.T) {
	root, server := linkFixture(t)
	if err := createReceiverSymlink("missing", filepath.Join(root, "broken"), false); err != nil {
		t.Fatal(err)
	}
	target, err := os.Stat(filepath.Join(root, "pkg", "cli.js"))
	if err != nil {
		t.Fatal(err)
	}
	get := func(url string) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		server.serveFilesFromSource(rr, httptest.NewRequest(http.MethodGet, url, nil))
		return rr
	}
	row := func(body, href string) string {
		t.Helper()
		for _, part := range strings.Split(body, "<tr>") {
			if strings.Contains(part, `href="`+href+`"`) {
				result, _, _ := strings.Cut(part, "</tr>")
				return result
			}
		}
		t.Fatalf("missing href %q in %s", href, body)
		return ""
	}
	t.Run("file link uses target attributes and downloads content", func(t *testing.T) {
		rr := get("/.bin/")
		if rr.Code != http.StatusOK {
			t.Fatalf("listing: %d %s", rr.Code, rr.Body.String())
		}
		entry := row(rr.Body.String(), "cli")
		for _, want := range []string{"(link)", formatBytes(target.Size()), target.ModTime().Format("2006-01-02 15:04:05")} {
			if !strings.Contains(entry, want) {
				t.Fatalf("missing %q in %s", want, entry)
			}
		}
		rr = get("/.bin/cli")
		content, err := os.ReadFile(filepath.Join(root, "pkg", "cli.js"))
		if err != nil {
			t.Fatal(err)
		}
		if rr.Code != http.StatusOK || rr.Body.String() != string(content) {
			t.Fatalf("download: %d %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("directory link navigates and precedes files", func(t *testing.T) {
		rr := get("/")
		entry := row(rr.Body.String(), "pkg-link/")
		for _, want := range []string{`class="dir-entry"`, "(link)", "&lt;DIR&gt;"} {
			if !strings.Contains(entry, want) {
				t.Fatalf("missing %q in %s", want, entry)
			}
		}
		if strings.Index(rr.Body.String(), `href="pkg-link/"`) > strings.Index(rr.Body.String(), `href="broken"`) {
			t.Fatal("directory link sorted after file")
		}
		rr = get("/pkg-link/")
		if rr.Code != http.StatusOK {
			t.Fatalf("directory link: %d %s", rr.Code, rr.Body.String())
		}
		entry = row(rr.Body.String(), "cli.js")
		if strings.Contains(entry, "(link)") || !strings.Contains(entry, formatBytes(target.Size())) {
			t.Fatalf("ordinary child file: %s", entry)
		}
	})
	t.Run("broken link is marked unavailable without a fabricated timestamp", func(t *testing.T) {
		rr := get("/")
		entry := row(rr.Body.String(), "broken")
		if !strings.Contains(entry, "(link)") || !strings.Contains(entry, "Target unavailable") || strings.Contains(entry, "0001-01-01") {
			t.Fatalf("broken link: %s", entry)
		}
	})
}
