package httpfileshare

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/threatexpert/gonc/v2/misc"
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
	ListenAddr   string
	RootPaths    []string // Changed from RootDirectory string to support multiple paths
	FileSource   FileSource
	LoggerOutput io.Writer
	EnableZstd   bool
	Listener     net.Listener
	WebMode      bool
}

// virtualMount represents a mapped path in multi-root mode.
type virtualMount struct {
	Alias    string // The name shown in the virtual root (e.g., "movies")
	RealPath string // The absolute path on disk
}

// Server represents our HTTP static file server.
type Server struct {
	config ServerConfig
	logger *log.Logger
	source FileSource
}

// NewServer creates a new Server instance.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.LoggerOutput == nil {
		cfg.LoggerOutput = io.Discard
	}
	serverLogger := misc.NewLog(cfg.LoggerOutput, "[HTTPSRV] ", log.LstdFlags|log.Lmsgprefix)

	source := cfg.FileSource
	if source == nil {
		var err error
		source, err = NewOSFileSource(cfg.RootPaths)
		if err != nil {
			return nil, err
		}
	}

	s := &Server{
		config: cfg,
		logger: serverLogger,
		source: source,
	}
	s.logger.Printf("Server initialized: %s", source.Description())
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

type responseStatsWriter struct {
	http.ResponseWriter
	status       int
	bytesWritten int64
}

func (w *responseStatsWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *responseStatsWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytesWritten += int64(n)
	return n, err
}

func (w *responseStatsWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
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
	var handler http.Handler = http.HandlerFunc(s.serveFilesFromSource)
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

	servingMsg := s.source.Description()

	if s.config.Listener != nil {
		// Use the provided custom listener
		ln = s.config.Listener
		s.logger.Printf("Starting HTTP server on custom listener, %s", servingMsg)
	} else {
		// Fallback to standard TCP listener if no custom listener is provided
		if s.config.ListenAddr == "" {
			return fmt.Errorf("ListenAddr cannot be empty if no custom Listener is provided")
		}
		ln, err = net.Listen("tcp", s.config.ListenAddr)
		if err != nil {
			return fmt.Errorf("failed to create standard TCP listener on %s: %w", s.config.ListenAddr, err)
		}
		s.logger.Printf("Starting HTTP server on standard TCP listener at %s, %s", ln.Addr(), servingMsg)
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

// virtualFileInfo wraps fs.FileInfo to override the Name() method.
type virtualFileInfo struct {
	fs.FileInfo
	name string
}

func (v virtualFileInfo) Name() string {
	return v.name
}

func (s *Server) serveFilesFromSource(w http.ResponseWriter, r *http.Request) {
	requestedPath := path.Clean(r.URL.Path)

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		if r.URL.Query().Get("manifest") == blake3ManifestAlgo {
			s.serveBlake3ManifestFromSource(w, r, requestedPath)
			return
		}
		recursive := r.URL.Query().Get("recursive") != "0"
		s.serveNDJSONListFromSource(w, r, recursive)
		return
	}

	stat, err := s.source.Stat(requestedPath)
	if err != nil {
		s.serveSourceError(w, r, requestedPath, err)
		return
	}

	if stat.IsDir() {
		s.serveDirectoryFromSource(w, r, requestedPath)
		return
	}

	f, err := s.source.Open(requestedPath)
	if err != nil {
		s.serveSourceError(w, r, requestedPath, err)
		return
	}
	defer f.Close()

	s.logger.Printf("Serving file '%s' (size %s) to %s", r.URL.Path, formatBytes(stat.Size()), r.RemoteAddr)
	statsWriter := &responseStatsWriter{ResponseWriter: w}
	s.handleFileDownload(statsWriter, r, f, stat)
	s.logger.Printf("Served file '%s' status=%d full_size=%s served=%s range=%q content_range=%q encoding=%q to %s",
		r.URL.Path,
		statsWriter.Status(),
		formatBytes(stat.Size()),
		formatBytes(statsWriter.bytesWritten),
		r.Header.Get("Range"),
		statsWriter.Header().Get("Content-Range"),
		statsWriter.Header().Get("Content-Encoding"),
		r.RemoteAddr,
	)
}

func (s *Server) serveDirectoryFromSource(w http.ResponseWriter, r *http.Request, requestedPath string) {
	if !strings.HasSuffix(r.URL.Path, "/") {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
		s.logger.Printf("Redirected: %s to %s/ (from %s)", r.URL.Path, r.URL.Path, r.RemoteAddr)
		return
	}

	if s.config.WebMode {
		for _, indexName := range []string{"index.html", "index.htm"} {
			indexPath := path.Join(requestedPath, indexName)
			idxStat, err := s.source.Stat(indexPath)
			if err != nil || idxStat.IsDir() {
				continue
			}
			fIndex, err := s.source.Open(indexPath)
			if err != nil {
				continue
			}
			defer fIndex.Close()
			s.logger.Printf("WebMode: Serving %s for directory %s", indexName, r.URL.Path)
			s.handleFileDownload(w, r, fIndex, idxStat)
			return
		}
	}

	entries, err := s.source.ReadDir(requestedPath)
	if err != nil {
		s.logger.Printf("Warning: Error reading directory listing for %s (showing partial results): %v", requestedPath, err)
	}
	s.serveHTMLDirectoryListing(w, r, entries, r.URL.Path)
}

func (s *Server) serveSourceError(w http.ResponseWriter, r *http.Request, requestedPath string, err error) {
	if errors.Is(err, ErrDirectoryTraversal) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		s.logger.Printf("Access denied: %v for path '%s' from %s", err, r.URL.Path, r.RemoteAddr)
		return
	}
	if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
		http.NotFound(w, r)
		s.logger.Printf("Not found: Path '%s' requested from %s", r.URL.Path, r.RemoteAddr)
		return
	}
	s.logger.Printf("Error resolving path '%s' (%s): %v", r.URL.Path, requestedPath, err)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

// serveHTMLDirectoryListing serves an HTML page for directory listing (for browsers).
// Refactored to accept []fs.FileInfo instead of reading the file itself.
func (s *Server) serveHTMLDirectoryListing(w http.ResponseWriter, r *http.Request, entries []fs.FileInfo, displayPath string) {
	// Sort entries: directories first, then by name
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir() // Directories first
		}
		return entries[i].Name() < entries[j].Name()
	})

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
	sb.WriteString(htmlEscape(displayPath)) // Escape path to prevent XSS
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
	if displayPath != "/" {
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

	_, err := w.Write([]byte(sb.String()))
	if err != nil {
		s.logger.Printf("Error writing HTML directory listing for '%s': %v (requested by %s from %s)", displayPath, err, r.URL.Path, r.RemoteAddr)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	} else {
		s.logger.Printf("served directory listing for '%s' to %s", displayPath, r.RemoteAddr)
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

func (s *Server) serveRecursiveListFromSource(w http.ResponseWriter, r *http.Request) {
	s.serveNDJSONListFromSource(w, r, true)
}

func (s *Server) serveBlake3ManifestFromSource(w http.ResponseWriter, r *http.Request, requestedPath string) {
	stat, err := s.source.Stat(requestedPath)
	if err != nil {
		s.serveSourceError(w, r, requestedPath, err)
		return
	}
	if stat.IsDir() {
		http.Error(w, "manifest is only available for files", http.StatusBadRequest)
		return
	}

	blockSize := defaultManifestBlockSize
	if rawBlockSize := r.URL.Query().Get("block_size"); rawBlockSize != "" {
		parsedBlockSize, err := strconv.ParseInt(rawBlockSize, 10, 64)
		if err != nil {
			http.Error(w, "invalid block_size", http.StatusBadRequest)
			return
		}
		blockSize = normalizeManifestBlockSize(parsedBlockSize)
	}
	var limitSize int64
	if rawLimitSize := r.URL.Query().Get("limit_size"); rawLimitSize != "" {
		parsedLimitSize, err := strconv.ParseInt(rawLimitSize, 10, 64)
		if err != nil || parsedLimitSize < 0 {
			http.Error(w, "invalid limit_size", http.StatusBadRequest)
			return
		}
		limitSize = parsedLimitSize
	}
	hashSize := manifestHashSize(stat.Size(), blockSize, limitSize)

	f, err := s.source.Open(requestedPath)
	if err != nil {
		s.serveSourceError(w, r, requestedPath, err)
		return
	}
	defer f.Close()

	blocks, err := blake3BlockHashes(f, hashSize, blockSize)
	if err != nil {
		s.logger.Printf("Error computing BLAKE3 manifest for %s: %v", requestedPath, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Transfer-Encoding", "chunked")

	encoder := json.NewEncoder(w)
	header := blake3ManifestFileRecord{
		Type:      "file",
		Path:      requestedPath,
		Size:      stat.Size(),
		ModTime:   stat.ModTime().Format(time.RFC3339Nano),
		Algo:      blake3ManifestAlgo,
		BlockSize: blockSize,
	}
	if hashSize != stat.Size() {
		header.ManifestSize = hashSize
		header.LimitSize = limitSize
	}
	if err := encoder.Encode(header); err != nil {
		s.logger.Printf("Error encoding BLAKE3 manifest header for %s: %v", requestedPath, err)
		return
	}
	for _, block := range blocks {
		if err := encoder.Encode(block); err != nil {
			s.logger.Printf("Error encoding BLAKE3 manifest block for %s: %v", requestedPath, err)
			return
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
}

func (s *Server) serveNDJSONListFromSource(w http.ResponseWriter, r *http.Request, recursive bool) {
	requestedPath := path.Clean(r.URL.Path)
	stat, err := s.source.Stat(requestedPath)
	if err != nil {
		s.serveSourceError(w, r, requestedPath, err)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Transfer-Encoding", "chunked")

	encoder := json.NewEncoder(w)

	writeInfo := func(sourcePath string, info fs.FileInfo) error {
		if info == nil {
			return nil
		}
		fileInfo := FileInfo{
			Name:    info.Name(),
			IsDir:   info.IsDir(),
			ModTime: info.ModTime(),
			Size:    info.Size(),
			Path:    sourcePath,
		}
		if err := encoder.Encode(fileInfo); err != nil {
			s.logger.Printf("Error encoding FileInfo for %s: %v", sourcePath, err)
			return fmt.Errorf("client write error: %w", err)
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		return nil
	}

	if !recursive {
		if !stat.IsDir() {
			if err := writeInfo(requestedPath, stat); err != nil {
				if strings.Contains(err.Error(), "client write error") {
					s.logger.Printf("NDJSON list stopped due to client disconnect.")
					return
				}
				s.logger.Printf("NDJSON list failed for %s: %v", requestedPath, err)
			}
			return
		}

		entries, err := s.source.ReadDir(requestedPath)
		if err != nil {
			s.serveSourceError(w, r, requestedPath, err)
			return
		}
		for _, entry := range entries {
			entryPath := path.Join(requestedPath, filepath.ToSlash(entry.Name()))
			if !strings.HasPrefix(entryPath, "/") {
				entryPath = "/" + entryPath
			}
			if err := writeInfo(entryPath, entry); err != nil {
				if strings.Contains(err.Error(), "client write error") {
					s.logger.Printf("NDJSON list stopped due to client disconnect.")
					return
				}
				s.logger.Printf("NDJSON list failed for %s: %v", requestedPath, err)
				return
			}
		}
		return
	}

	err = s.source.Walk(requestedPath, func(sourcePath string, info fs.FileInfo, walkErr error) error {
		if walkErr != nil {
			s.logger.Printf("Error walking path %s: %v", sourcePath, walkErr)
			return nil
		}
		return writeInfo(sourcePath, info)
	})
	if err != nil {
		if strings.Contains(err.Error(), "client write error") {
			s.logger.Printf("NDJSON list stopped due to client disconnect.")
			return
		}
		s.logger.Printf("NDJSON list failed for %s: %v", requestedPath, err)
	}
}

// handleFileDownload serves a single file.
func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request, file fs.File, stat fs.FileInfo) {
	if !s.config.WebMode {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, stat.Name()))
	}
	if content, ok := file.(io.ReadSeeker); ok && canServeContent(content) {
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), content)
		return
	}
	s.serveStreamingContent(w, r, file, stat)
}

func canServeContent(content io.ReadSeeker) bool {
	if _, err := content.Seek(0, io.SeekEnd); err != nil {
		return false
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return false
	}
	return true
}

func (s *Server) serveStreamingContent(w http.ResponseWriter, r *http.Request, file fs.File, stat fs.FileInfo) {
	w.Header().Set("Accept-Ranges", "none")
	if stat.Size() >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/octet-stream")
	}

	if r.Header.Get("Range") != "" {
		s.logger.Printf("Ignoring Range request for non-seekable file '%s' from %s", r.URL.Path, r.RemoteAddr)
	}

	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, file); err != nil {
		s.logger.Printf("Error streaming non-seekable file '%s' to %s: %v", r.URL.Path, r.RemoteAddr, err)
	}
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
