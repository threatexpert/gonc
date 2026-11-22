package apps

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testShellSession(t *testing.T) (*shellClientConn, <-chan [2]int) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	sid, sidHex, err := newPtyshSID()
	if err != nil {
		t.Fatal(err)
	}
	resizes := make(chan [2]int, 8)
	server := newShellServerConn(a, sid, func(rows, cols int) { resizes <- [2]int{rows, cols} }, nil)
	t.Cleanup(func() { server.Close() })
	go func() {
		defer server.Close()
		server.Write(append(encodeShellSessionCaps(sidHex), []byte("pre-upgrade-prompt>")...))
		// Echo the shell bytes; file and control bytes must never appear here.
		io.Copy(server, server)
	}()
	var notices bytes.Buffer
	client, err := newShellClientConn(b, &notices)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if client.session == nil || client.api == nil {
		t.Fatalf("missing session/API: %s", &notices)
	}
	// Strip the retained capability message exactly as the normal client does.
	initial := make([]byte, len(encodeShellSessionCaps(sidHex)))
	if _, err := io.ReadFull(client, initial); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(initial, encodeShellSessionCaps(sidHex)) {
		t.Fatal("capabilities changed")
	}
	prompt := make([]byte, len("pre-upgrade-prompt>"))
	if _, err := io.ReadFull(client, prompt); err != nil || string(prompt) != "pre-upgrade-prompt>" {
		t.Fatalf("lost output before upgrade ACK: %q %v", prompt, err)
	}
	if _, err := client.ctrl.Write(encodePtyshResize(sid, 31, 109)); err != nil {
		t.Fatal(err)
	}
	return client, resizes
}

func testFileURL(base, path string) string {
	return base + "file?" + url.Values{"path": {path}}.Encode()
}

func TestShellSessionFilesAndTerminal(t *testing.T) {
	c, resizes := testShellSession(t)
	select {
	case size := <-resizes:
		if size != [2]int{31, 109} {
			t.Fatal(size)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("resize lost")
	}
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	hc := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	base := c.api.baseURL
	path := filepath.Join(t.TempDir(), "文件 & #+%.bin")
	payload := bytes.Repeat([]byte{0, 255, 255, 'g', 'r', 1, '\x1b', '\r', '\n', 3, 254}, 200000)
	// Hold an upload open and prove that shell I/O still completes.
	pr, pw := io.Pipe()
	request, _ := http.NewRequest(http.MethodPut, testFileURL(base, path), pr)
	uploaded := make(chan error, 1)
	go func() {
		resp, err := hc.Do(request)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				err = fmt.Errorf("upload: %d %s", resp.StatusCode, body)
			}
			digest := sha256.Sum256(payload)
			if !bytes.Contains(body, []byte(hex.EncodeToString(digest[:]))) {
				err = fmt.Errorf("missing upload checksum: %s", body)
			}
		}
		uploaded <- err
	}()
	if _, err := pw.Write(payload[:65536]); err != nil {
		t.Fatal(err)
	}
	shellData := append([]byte("echo still-alive\r\n"), payload[:100]...)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(shellData); err != nil {
		t.Fatal(err)
	}
	gotShell := make([]byte, len(shellData))
	if _, err := io.ReadFull(c, gotShell); err != nil {
		t.Fatalf("terminal stalled during upload: %v", err)
	}
	c.SetReadDeadline(time.Time{})
	if !bytes.Equal(gotShell, shellData) {
		t.Fatal("file/control bytes leaked into terminal")
	}
	if _, err := pw.Write(payload[65536:]); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if err := <-uploaded; err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Get(testFileURL(base, path))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || !bytes.Equal(got, payload) {
		t.Fatalf("download mismatch: status=%d bytes=%d err=%v", resp.StatusCode, len(got), err)
	}
	for _, tc := range []struct {
		suffix string
		status int
	}{{"", 409}, {"&overwrite=1", 201}} {
		req, _ := http.NewRequest(http.MethodPut, testFileURL(base, path)+tc.suffix, strings.NewReader("replacement"))
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("overwrite status=%d, want %d", resp.StatusCode, tc.status)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "replacement" {
		t.Fatalf("replacement=%q err=%v", data, err)
	}
	resp, err = hc.Get(base + "info")
	if err != nil {
		t.Fatal(err)
	}
	info, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(info, []byte(`"protocol":2`)) {
		t.Fatalf("info=%s", info)
	}
	for _, tc := range []struct{ url, host, origin string }{
		{strings.Replace(base, "/v1/", "-wrong/v1/", 1) + "info", "", ""},
		{base + "info", "attacker.invalid", ""},
		{base + "info", "", "https://attacker.invalid"},
	} {
		req, _ := http.NewRequest(http.MethodGet, tc.url, nil)
		if tc.host != "" {
			req.Host = tc.host
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("unauthorized request accepted: %d", resp.StatusCode)
		}
	}
	c.Close()
	if resp, err := hc.Get(base + "info"); err == nil {
		resp.Body.Close()
		t.Fatal("file listener survived session close")
	}
}

func TestShellSessionNewClientOldServer(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	caps, _ := encodePtyshCaps("0102030405060708")
	got := make(chan string, 1)
	go func() {
		a.Write(append(caps, []byte("old-prompt>")...))
		buf := make([]byte, 5)
		io.ReadFull(a, buf)
		got <- string(buf)
	}()
	var notices bytes.Buffer
	c, err := newShellClientConn(b, &notices)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.session != nil || c.api != nil {
		t.Fatal("upgraded a legacy server")
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case input := <-got:
		if input != "hello" {
			t.Fatalf("upgrade probe leaked to old server: %q", input)
		}
	case <-time.After(time.Second):
		t.Fatal("old shell input stalled")
	}
	buf := make([]byte, len(caps)+len("old-prompt>"))
	io.ReadFull(c, buf)
	var output bytes.Buffer
	w := newPtyshCapsOutputWriter(&output, nil)
	w.Write(buf)
	if output.String() != "old-prompt>" {
		t.Fatalf("legacy output=%q", output.String())
	}
}

func TestShellSessionOldClientNewServer(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	resize := make(chan [2]int, 1)
	s := newShellServerConn(a, sid, func(r, c int) { resize <- [2]int{r, c} }, nil)
	defer s.Close()
	go func() { s.Write(encodeShellSessionCaps(hex.EncodeToString(sid))); io.Copy(s, s) }()
	caps := make([]byte, len(encodeShellSessionCaps(hex.EncodeToString(sid))))
	io.ReadFull(b, caps)
	var output bytes.Buffer
	var gotSID []byte
	w := newPtyshCapsOutputWriter(&output, func(v []byte) { gotSID = v })
	w.Write(caps)
	if output.Len() != 0 || !bytes.Equal(gotSID, sid) {
		t.Fatal("old capability parser rejected new server")
	}
	input := append(encodePtyshResize(sid, 20, 90), []byte("old-client\r\n")...)
	b.Write(input)
	buf := make([]byte, len("old-client\r\n"))
	b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(b, buf); err != nil || string(buf) != "old-client\r\n" {
		t.Fatalf("old shell failed: %q %v", buf, err)
	}
	select {
	case <-resize:
	case <-time.After(time.Second):
		t.Fatal("legacy resize failed")
	}
	s.mu.Lock()
	upgraded := s.session != nil
	s.mu.Unlock()
	if upgraded {
		t.Fatal("server forced old client into mux")
	}
}

func TestShellSessionUpgradePreservesBufferedTail(t *testing.T) {
	sid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	input := append([]byte("before"), encodePtyshResize(sid, 0, 0)...)
	input = append(input, []byte("framed-tail")...)
	r := newPtyshResizeInputReader(bytes.NewReader(input), sid, nil)
	r.onUpgrade = func(tail io.Reader) (io.Reader, error) { return tail, nil }
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "beforeframed-tail" {
		t.Fatalf("switch lost buffered bytes: %q %v", got, err)
	}
}

func TestShellSessionUpgradeFailureClosesConnection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	request := make(chan []byte, 1)
	go func() {
		a.Write(encodeShellSessionCaps(hex.EncodeToString(sid)))
		frame := make([]byte, ptyshResizeFrameN)
		io.ReadFull(a, frame)
		request <- frame
		a.Write([]byte("invalid acknowledgement"))
		a.Close()
	}()
	c, err := newShellClientConn(b, io.Discard)
	if err == nil || c != nil {
		t.Fatal("failed handshake fell back to raw shell")
	}
	if !bytes.Equal(<-request, encodePtyshResize(sid, 0, 0)) {
		t.Fatal("invalid upgrade request")
	}
	if _, err := b.Write([]byte("must not reach shell")); err == nil {
		t.Fatal("failed handshake left connection writable")
	}
}

func TestShellSessionRemoteDisconnectClosesAPIWithoutTerminalRead(t *testing.T) {
	c, _ := testShellSession(t)
	base := c.api.baseURL
	// Simulate a lost transport while the user is not consuming shell output.
	c.Conn.Close()
	hc := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := hc.Get(base + "info")
		if err != nil {
			return
		}
		resp.Body.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("API survived transport disconnect without a shell read")
}
