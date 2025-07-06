package httpfileshare

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// FileInfo represents a file or directory for JSON listing.
type FileInfo struct {
	Name    string    `json:"name"`
	IsDir   bool      `json:"is_dir"`
	ModTime time.Time `json:"mod_time"`
	Size    int64     `json:"size"` // Size in bytes, 0 for directories
	Path    string    `json:"path"` // Full relative path from the root
}

// ServerConfig holds the server configuration.
type ServerConfig struct {
	ListenAddr    string
	RootDirectory string
	LoggerOutput  io.Writer
	EnableZstd    bool
	Listener      net.Listener
}

// Server represents our HTTP static file server.
type Server struct {
	config ServerConfig
	fs     http.FileSystem
	logger *log.Logger
}

// NewServer creates a new Server instance.
func NewServer(cfg ServerConfig) (*Server, error) {
	absRoot, err := filepath.Abs(cfg.RootDirectory)
	if err != nil {
		return nil, fmt.Errorf("invalid root directory path: %w", err)
	}
	cfg.RootDirectory = absRoot

	if cfg.LoggerOutput == nil {
		cfg.LoggerOutput = io.Discard
	}

	serverLogger := log.New(cfg.LoggerOutput, "[HTTP_SERVER] ", log.Ldate|log.Ltime)

	fileSystem := http.Dir(cfg.RootDirectory)

	s := &Server{
		config: cfg,
		fs:     fileSystem,
		logger: serverLogger,
	}
	return s, nil
}

// zstdWriter wraps http.ResponseWriter to provide Zstandard compression.
type zstdWriter struct {
	http.ResponseWriter
	Writer *zstd.Encoder
}

func (z *zstdWriter) Write(data []byte) (int, error) {
	return z.Writer.Write(data)
}

func (z *zstdWriter) WriteHeader(status int) {
	z.Header().Del("Content-Length")
	z.ResponseWriter.WriteHeader(status)
}

// zstdMiddleware applies Zstandard compression if the client accepts it.
func (s *Server) zstdMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do not compress if the client doesn't accept zstd
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "zstd") {
			next.ServeHTTP(w, r)
			return
		}

		// Clean the path to get the actual file name/extension
		requestedFilePath := path.Clean(r.URL.Path)

		// If it's a directory, or the root path (which leads to listing), compress the listing.
		// If it's a specific file, check its extension.
		if strings.HasSuffix(requestedFilePath, "/") || requestedFilePath == "." || requestedFilePath == "/" {
			// It's a directory or the root, so compress the HTML/JSON listing
		} else if isAlreadyCompressed(requestedFilePath) {
			s.logger.Printf("Skipping Zstd for %s (known compressed type)", requestedFilePath)
			next.ServeHTTP(w, r) // Serve uncompressed
			return
		}

		// If it reaches here, we should attempt compression
		w.Header().Set("Content-Encoding", "zstd")
		w.Header().Set("Vary", "Accept-Encoding")

		encoder, err := zstd.NewWriter(w)
		if err != nil {
			s.logger.Printf("Error creating Zstd encoder: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer encoder.Close()

		zwr := &zstdWriter{ResponseWriter: w, Writer: encoder}
		next.ServeHTTP(zwr, r)
	})
}

// Start runs the HTTP server.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	var handler http.Handler = http.HandlerFunc(s.serveFiles)
	if s.config.EnableZstd {
		s.logger.Println("Zstd compression enabled. Will skip already-compressed file types.")
		handler = s.zstdMiddleware(handler)
	} else {
		s.logger.Println("Zstd compression disabled.")
	}
	mux.Handle("/", handler)
	mux.HandleFunc("/favicon.ico", serveFavicon)

	// Determine the listener to use
	var ln net.Listener
	var err error

	if s.config.Listener != nil {
		// Use the provided custom listener
		ln = s.config.Listener
		s.logger.Printf("Starting HTTP server on custom listener, serving from %s", s.config.RootDirectory)
	} else {
		// Fallback to standard TCP listener if no custom listener is provided
		if s.config.ListenAddr == "" {
			return fmt.Errorf("ListenAddr cannot be empty if no custom Listener is provided")
		}
		ln, err = net.Listen("tcp", s.config.ListenAddr)
		if err != nil {
			return fmt.Errorf("failed to create standard TCP listener on %s: %w", s.config.ListenAddr, err)
		}
		s.logger.Printf("Starting HTTP server on standard TCP listener at %s, serving from %s", ln.Addr(), s.config.RootDirectory)
	}

	// Always defer closing the listener that was opened/provided
	defer ln.Close()

	server := &http.Server{
		// Addr is not needed here if we explicitly pass a Listener to Serve()
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // Timeout for reading entire request headers
		WriteTimeout:      0,                // No timeout for writes after headers are sent (for large files)
		// Or if you want a large but finite timeout: WriteTimeout: 2000 * time.Second,
		IdleTimeout: 30 * time.Second, // Timeout for keep-alive connections
	}

	return server.Serve(ln) // Use server.Serve with the determined listener
}

var faviconData = []byte{
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x10, 0x00, 0x01, 0x00,
	0x04, 0x00, 0x28, 0x01, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00,
	0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0xD6, 0xED, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x01, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x10, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x01, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x10, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x01, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x10, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01,
	0x00, 0x00, 0x81, 0xFF, 0x00, 0x00, 0xC3, 0xFF, 0x00, 0x00, 0xFF, 0xFF,
	0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
}

// knownCompressedExtensions is a list of file extensions that typically indicate
// that the file is already compressed.
var knownCompressedExtensions = map[string]struct{}{
	".zip": {}, ".rar": {}, ".7z": {},
	".gz": {}, ".tgz": {}, ".bz2": {}, ".tbz2": {}, ".xz": {}, ".txz": {},
	".jpg": {}, ".jpeg": {}, ".png": {}, ".gif": {}, ".tiff": {},
	".mp3": {}, ".mp4": {}, ".ogg": {}, ".webm": {}, ".flac": {}, ".aac": {},
	".avi": {}, ".mov": {}, ".wmv": {}, ".mkv": {},
	".pdf": {}, ".docx": {}, ".pptx": {}, ".xlsx": {}, // Office files are often internally compressed
}

// isAlreadyCompressed checks if a file path has a known compressed extension.
func isAlreadyCompressed(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	_, ok := knownCompressedExtensions[ext]
	return ok
}

// serveFavicon handles requests for /favicon.ico
func serveFavicon(w http.ResponseWriter, r *http.Request) {
	// Set the Content-Type header to image/x-icon
	w.Header().Set("Content-Type", "image/x-icon")
	// Set Content-Length for proper transfer
	w.Header().Set("Content-Length", strconv.Itoa(len(faviconData)))

	// Write the binary data to the response writer
	w.Write(faviconData)
}

// serveFiles handles all requests to the root path.
func (s *Server) serveFiles(w http.ResponseWriter, r *http.Request) {
	requestedPath := path.Clean(r.URL.Path)
	if strings.HasPrefix(requestedPath, "..") {
		http.Error(w, "Access Denied", http.StatusForbidden)
		s.logger.Printf("Access denied: Directory traversal attempt for path '%s' from %s", r.URL.Path, r.RemoteAddr)
		return
	}

	fullPathOnDisk := filepath.Join(s.config.RootDirectory, requestedPath)

	prefersJSONRecursive := strings.Contains(r.Header.Get("Accept"), "application/json")

	if prefersJSONRecursive {
		s.serveRecursiveList(w, r, s.config.RootDirectory)
		return
	}

	f, err := s.fs.Open(requestedPath)
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			http.NotFound(w, r)
			s.logger.Printf("Not found: Path '%s' requested from %s", r.URL.Path, r.RemoteAddr)
		} else {
			s.logger.Printf("Error opening file/directory %s: %v (requested by %s from %s)", fullPathOnDisk, err, r.URL.Path, r.RemoteAddr)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		s.logger.Printf("Error stating file/directory %s: %v (requested by %s from %s)", fullPathOnDisk, err, r.URL.Path, r.RemoteAddr)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if stat.IsDir() {
		httpFile, ok := f.(*os.File) // *os.File implements http.File
		if !ok {
			s.logger.Printf("Error: Opened directory %s is not an *os.File for readdir purposes", fullPathOnDisk)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
			s.logger.Printf("Redirected: %s to %s/ (from %s)", r.URL.Path, r.URL.Path, r.RemoteAddr)
			return
		}
		s.serveHTMLDirectoryListing(w, r, httpFile, requestedPath)
		return
	}

	s.logger.Printf("Serving file '%s' (size %s) to %s", r.URL.Path, formatBytes(stat.Size()), r.RemoteAddr)
	s.handleFileDownload(w, r, f, stat)
	s.logger.Printf("Served file '%s' (size %s) to %s", r.URL.Path, formatBytes(stat.Size()), r.RemoteAddr)
}

// serveHTMLDirectoryListing serves an HTML page for directory listing (for browsers).
// This version generates HTML by concatenating strings instead of using html/template.
func (s *Server) serveHTMLDirectoryListing(w http.ResponseWriter, r *http.Request, file *os.File, requestedPath string) {
	entries, err := file.Readdir(-1) // Readdir works on *os.File
	if err != nil {
		s.logger.Printf("Error reading directory %s for HTML listing: %v (requested by %s from %s)", requestedPath, err, r.URL.Path, r.RemoteAddr)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Use a strings.Builder for efficient string concatenation
	var sb strings.Builder

	// Write HTML header
	sb.WriteString(`<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Directory Listing</title>
    <style>
        body { font-family: sans-serif; margin: 2em; background-color: #f4f4f4; color: #333; }
        h1 { color: #0056b3; }
        table { width: 100%; border-collapse: collapse; margin-top: 1em; }
        th, td { padding: 0.8em; border: 1px solid #ddd; text-align: left; }
        th { background-color: #e2e2e2; }
        td a { text-decoration: none; color: #007bff; }
        td a:hover { text-decoration: underline; }
        .dir-entry { font-weight: bold; }
        .size-col { width: 15%; white-space: nowrap; }
        .time-col { width: 25%; white-space: nowrap; }
    </style>
</head>
<body>
    <h1>Directory Listing for `)
	sb.WriteString(htmlEscape(r.URL.Path)) // Escape path to prevent XSS
	sb.WriteString(`</h1>

    <table>
        <thead>
            <tr>
                <th>Filename</th>
                <th class="size-col">Size</th>
                <th class="time-col">Last Modified</th>
            </tr>
        </thead>
        <tbody>`)

	// Parent Directory Link
	if r.URL.Path != "/" {
		sb.WriteString(`
            <tr>
                <td><a href="../">.. (Parent Directory)</a></td>
                <td>&lt;DIR&gt;</td>
                <td></td>
            </tr>`)
	}

	// File and Directory Entries
	for _, entry := range entries {
		suffix := ""
		if entry.IsDir() {
			suffix = "/"
		}

		// HTML Escape filename to prevent XSS
		escapedName := htmlEscape(entry.Name())

		sb.WriteString(`
            <tr>
                <td><a href="`)
		sb.WriteString(encodePathSegmentPreservingSlashes(filepath.ToSlash(entry.Name())) + suffix) // URL escape name for href
		sb.WriteString(`" class="`)
		if entry.IsDir() {
			sb.WriteString(`dir-entry`)
		}
		sb.WriteString(`">`)
		sb.WriteString(escapedName)
		sb.WriteString(`</a></td>
                <td>`)
		if entry.IsDir() {
			sb.WriteString(`&lt;DIR&gt;`)
		} else {
			sb.WriteString(formatBytes(entry.Size()))
		}
		sb.WriteString(`</td>
                <td>`)
		sb.WriteString(entry.ModTime().Format("2006-01-02 15:04:05"))
		sb.WriteString(`</td>
            </tr>`)
	}

	// Write HTML footer
	sb.WriteString(`
        </tbody>
    </table>
</body>
</html>`)

	_, err = w.Write([]byte(sb.String()))
	if err != nil {
		s.logger.Printf("Error writing HTML directory listing for '%s': %v (requested by %s from %s)", requestedPath, err, r.URL.Path, r.RemoteAddr)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	} else {
		s.logger.Printf("served directory listing for '%s' to %s", r.URL.Path, r.RemoteAddr)
	}
}

// New helper function to HTML escape strings for display
func htmlEscape(s string) string {
	// This is a simplified escape. For full robustness, use html.EscapeString from html package.
	// However, to avoid html package dependency as well:
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, `'`, "&#x27;")
	return s
}

// serveRecursiveList walks the given base path recursively and streams FileInfo objects as NDJSON.
func (s *Server) serveRecursiveList(w http.ResponseWriter, r *http.Request, basePath string) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Transfer-Encoding", "chunked")

	requestedPath := path.Clean(r.URL.Path)
	startWalkPath := filepath.Join(s.config.RootDirectory, requestedPath)

	s.logger.Printf("Starting recursive NDJSON list from '%s' (requested path '%s') for %s", startWalkPath, r.URL.Path, r.RemoteAddr)

	err := filepath.WalkDir(startWalkPath, func(currentPath string, d fs.DirEntry, err error) error {
		if err != nil {
			s.logger.Printf("Error walking path %s: %v (during recursive list for %s)", currentPath, err, r.RemoteAddr)
			return nil
		}

		relativePath, err := filepath.Rel(s.config.RootDirectory, currentPath)
		if err != nil {
			s.logger.Printf("Error getting relative path for %s: %v (during recursive list for %s)", currentPath, err, r.RemoteAddr)
			return nil
		}

		if relativePath == "." {
			relativePath = "/"
		} else {
			relativePath = "/" + strings.ReplaceAll(relativePath, "\\", "/")
		}

		info, err := d.Info()
		if err != nil {
			s.logger.Printf("Error getting file info for %s: %v (during recursive list for %s)", currentPath, err, r.RemoteAddr)
			return nil
		}

		fileInfo := FileInfo{
			Name:    d.Name(),
			IsDir:   d.IsDir(),
			ModTime: info.ModTime(),
			Size:    info.Size(),
			Path:    relativePath,
		}

		encoder := json.NewEncoder(w)
		if err := encoder.Encode(fileInfo); err != nil {
			s.logger.Printf("Error encoding FileInfo for %s: %v (during recursive list for %s)", currentPath, err, r.RemoteAddr)
			return fmt.Errorf("client write error: %w", err)
		}

		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		return nil
	})

	if err != nil {
		if strings.Contains(err.Error(), "client write error") {
			s.logger.Printf("Recursive list from '%s' stopped due to client disconnect.", startWalkPath)
		} else {
			s.logger.Printf("Failed to complete recursive walk from %s: %v", startWalkPath, err)
		}
	} else {
		s.logger.Printf("Completed recursive NDJSON list from '%s' for %s", startWalkPath, r.RemoteAddr)
	}
}

// handleFileDownload serves a single file.
func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request, file fs.File, stat fs.FileInfo) {
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, stat.Name()))
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), file.(io.ReadSeeker))
}

// formatBytes formats bytes into human-readable string.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
