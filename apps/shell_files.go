package apps

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/xtaci/smux"
)

type shellFileListener struct{ session *smux.Session }

func (l shellFileListener) Accept() (net.Conn, error) { return l.session.AcceptStream() }
func (l shellFileListener) Close() error              { return l.session.Close() }
func (l shellFileListener) Addr() net.Addr            { return l.session.LocalAddr() }

func serveShellFiles(session *smux.Session, recorder *shellRecorder) {
	server := &http.Server{
		Handler:           shellFileHandler(recorder),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	defer server.Close()
	_ = server.Serve(shellFileListener{session})
}

func shellJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func shellFileError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, os.ErrNotExist):
		status = http.StatusNotFound
	case errors.Is(err, os.ErrExist):
		status = http.StatusConflict
	case errors.Is(err, os.ErrPermission):
		status = http.StatusForbidden
	}
	shellJSON(w, status, map[string]any{"error": err.Error()})
}

func shellFileHandler(recorder *shellRecorder) http.Handler {
	// Bound concurrent disk operations and their flow-control buffers.
	slots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/v1/info" && r.Method == http.MethodGet {
			cwd, _ := os.Getwd()
			shellJSON(w, http.StatusOK, map[string]any{
				"protocol": 2, "os": runtime.GOOS, "cwd": cwd,
				"capabilities": []string{"shell", "file.put", "file.get"},
				"paths":        "absolute remote paths; independent of shell cd", "overwrite_default": false,
			})
			return
		}
		if r.URL.Path != "/v1/file" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPut && r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET, PUT")
			shellJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET or PUT"})
			return
		}
		path := r.URL.Query().Get("path")
		if !filepath.IsAbs(path) {
			shellJSON(w, http.StatusBadRequest, map[string]string{"error": "path must be an absolute path on the remote machine"})
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			shellJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many file transfers"})
			return
		}
		if r.Method == http.MethodPut {
			shellFilePut(w, r, path, recorder)
		} else {
			shellFileGet(w, r, path, recorder)
		}
	})
}

func shellFilePut(w http.ResponseWriter, r *http.Request, path string, recorder *shellRecorder) {
	overwrite := r.URL.Query().Get("overwrite")
	if overwrite != "" && overwrite != "0" && overwrite != "1" {
		shellJSON(w, http.StatusBadRequest, map[string]string{"error": "overwrite must be 0 or 1"})
		return
	}
	// Fail early for an existing destination; the final link also checks it
	// atomically, so concurrent uploads cannot silently overwrite each other.
	mode := os.FileMode(0600)
	if st, err := os.Lstat(path); err == nil {
		if overwrite != "1" {
			shellFileError(w, os.ErrExist)
			return
		}
		if !st.Mode().IsRegular() {
			shellJSON(w, http.StatusBadRequest, map[string]string{"error": "destination is not a regular file"})
			return
		}
		mode = st.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		shellFileError(w, err)
		return
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".gonc-upload-*")
	if err != nil {
		shellFileError(w, err)
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), r.Body)
	if err != nil {
		shellJSON(w, http.StatusBadRequest, map[string]string{"error": "incomplete upload: " + err.Error()})
		return
	}
	if err := r.Context().Err(); err != nil {
		return
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if expected := r.Header.Get("X-Content-SHA256"); expected != "" && !strings.EqualFold(expected, digest) {
		shellJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "SHA256 mismatch"})
		return
	}
	if err = f.Chmod(mode); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if r.Context().Err() != nil {
		return
	}
	if err == nil {
		if overwrite == "1" {
			err = os.Rename(f.Name(), path)
		} else {
			err = os.Link(f.Name(), path)
		}
	}
	if err != nil {
		shellFileError(w, err)
		return
	}
	recorder.add("FILE", []byte(fmt.Sprintf("put path=%q bytes=%d sha256=%s", path, n, digest)))
	shellJSON(w, http.StatusCreated, map[string]any{"path": path, "bytes": n, "sha256": digest})
}

func shellFileGet(w http.ResponseWriter, r *http.Request, path string, recorder *shellRecorder) {
	// Do not block opening a FIFO/device when the API only supports files.
	st, err := os.Stat(path)
	if err != nil {
		shellFileError(w, err)
		return
	}
	if !st.Mode().IsRegular() {
		shellJSON(w, http.StatusBadRequest, map[string]string{"error": "source is not a regular file"})
		return
	}
	f, err := os.Open(path)
	if err != nil {
		shellFileError(w, err)
		return
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil {
		shellFileError(w, err)
		return
	}
	if !st.Mode().IsRegular() {
		shellJSON(w, http.StatusBadRequest, map[string]string{"error": "source is not a regular file"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(path)}))
	http.ServeContent(w, r, st.Name(), st.ModTime(), f)
	recorder.add("FILE", []byte(fmt.Sprintf("get path=%q size=%d", path, st.Size())))
}

type shellLocalAPI struct {
	baseURL   string
	server    *http.Server
	transport *http.Transport
}

func (a *shellLocalAPI) Close() {
	a.server.Close()
	a.transport.CloseIdleConnections()
}

func startShellLocalAPI(session *smux.Session) (*shellLocalAPI, error) {
	var token [24]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	prefix := "/" + hex.EncodeToString(token[:])
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return session.OpenStream()
		},
		DisableKeepAlives:     true,
		MaxConnsPerHost:       4,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "shell"
			pr.Out.URL.Path = strings.TrimPrefix(pr.In.URL.Path, prefix)
			pr.Out.URL.RawPath = ""
			pr.Out.Host = "shell"
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			shellJSON(w, http.StatusBadGateway, map[string]string{"error": "remote file request failed: " + err.Error()})
		},
	}
	address := listener.Addr().String()
	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No CORS or browser-origin access. Bind Host as well as the listener
			// to loopback, and require the unguessable per-session URL token.
			if r.Host != address || r.Header.Get("Origin") != "" || !strings.HasPrefix(r.URL.Path, prefix+"/v1/") {
				http.NotFound(w, r)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
	}
	api := &shellLocalAPI{baseURL: "http://" + address + prefix + "/v1/", server: server, transport: transport}
	go func() { _ = server.Serve(listener) }()
	return api, nil
}

func printShellFileHints(w io.Writer, baseURL string) {
	curl := "curl"
	if runtime.GOOS == "windows" {
		curl = "curl.exe"
	}
	fmt.Fprintf(w, `
Shell connected. File transfer API is available.

Base URL: %s

Usage:
- Keep this shell session running during file transfers.
- Run file-transfer commands in a separate LOCAL tool invocation,
  not inside the remote shell.
- This is a standard HTTP API. curl is optional;
  Python urllib.request or another HTTP client can be used.

Endpoints:
GET  info
     Returns JSON describing the remote OS, capabilities and path rules.

PUT  file?path=<URL-encoded remote absolute path>
     Request body: raw file bytes, not JSON, Base64 or multipart.
     Success: HTTP 201, JSON containing path, bytes and sha256.
     Existing files are rejected with HTTP 409.
     Add &overwrite=1 to explicitly replace an existing file.
     Optional header: X-Content-SHA256, verified before saving.

GET  file?path=<URL-encoded remote absolute path>
     Success: HTTP 200 with raw file bytes.
     Supports Range requests, returning HTTP 206.

Paths:
- Use absolute paths on the REMOTE machine.
- Paths are independent of the interactive shell's current directory.
- Parent directories must already exist.
- Each request transfers one file.
- URL-encode query values, including spaces, Chinese and special characters.

Errors:
JSON response: {"error":"..."}
400 invalid request       403 permission denied
404 not found             409 destination already exists
422 checksum mismatch     429 too many active transfers
500 server error          502 remote request failed

Lifecycle:
- Exiting the shell or losing the connection interrupts active transfers
  and closes this local API.
- Incomplete uploads are not published to the destination.
- Interrupted downloads may leave a partial local file.
- If an upload response is lost, verify the remote file before retrying.

curl examples (compatible with older curl versions):

Info:
%s -f "%sinfo"

Upload:
%s -f -T "<local-file>" "%sfile?path=<URL-encoded-remote-absolute-path>"

Download:
%s -f -o "<local-file>" "%sfile?path=<URL-encoded-remote-absolute-path>"

To overwrite an existing remote file, append &overwrite=1 to the URL.
-f returns a nonzero exit code for HTTP errors and suppresses the error body.
To inspect JSON errors, omit -f and check the HTTP response status.

`, baseURL, curl, baseURL, curl, baseURL, curl, baseURL)
}
