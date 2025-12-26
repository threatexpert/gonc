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
	// Internal state for path resolution
	mounts     []virtualMount // Used for multi-path mode to map /alias -> /abs/path
	singleRoot string         // Used for backward compatibility (single path mode)
}

// NewServer creates a new Server instance.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.RootPaths) == 0 {
		return nil, fmt.Errorf("at least one root path must be provided")
	}

	if cfg.LoggerOutput == nil {
		cfg.LoggerOutput = io.Discard
	}
	serverLogger := misc.NewLog(cfg.LoggerOutput, "[HTTPSRV] ", log.LstdFlags|log.Lmsgprefix)

	s := &Server{
		config: cfg,
		logger: serverLogger,
	}

	// Process paths to ensure they are absolute
	var absPaths []string
	for _, p := range cfg.RootPaths {
		// [修复 1] Windows下，如果路径是 "d:" 或 "D:" (长度为2且以冒号结尾)，
		// 意味着用户想要的是该盘符的根目录，而不是该盘符的"当前工作目录"。
		// 我们手动追加一个路径分隔符，将其强制转为绝对根路径 "d:\"。
		if len(p) == 2 && p[1] == ':' {
			p = p + string(os.PathSeparator)
		}

		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("invalid root path %s: %w", p, err)
		}
		absPaths = append(absPaths, abs)
	}

	if len(absPaths) == 1 {
		// Single path mode: behaves exactly like the original version
		s.singleRoot = absPaths[0]
		s.logger.Printf("Server initialized in Single-Root mode: %s", s.singleRoot)
	} else {
		// Multi path mode: generate virtual mounts
		seenAliases := make(map[string]int)
		for _, p := range absPaths {
			// [修复 2] 获取显示的名称
			baseName := filepath.Base(p)

			// Windows 下，filepath.Base("D:\") 返回的是 "\"
			// 如果检测到是根目录，我们改用卷标名（例如 "D:"）
			if baseName == string(os.PathSeparator) || baseName == "." {
				vol := filepath.VolumeName(p)
				if vol != "" {
					baseName = strings.TrimRight(vol, ":") // 这里 baseName 变为 "D:"
				} else {
					// 如果是 Linux 根目录 "/" 或其他情况，给个默认名
					baseName = "ROOT"
				}
			}

			// Handle duplicate names by appending a counter (e.g., data, data-2)
			alias := baseName
			if count, exists := seenAliases[alias]; exists {
				seenAliases[baseName]++
				alias = fmt.Sprintf("%s-%d", baseName, count+1)
			} else {
				seenAliases[alias] = 1
			}

			s.mounts = append(s.mounts, virtualMount{
				Alias:    alias,
				RealPath: p,
			})
		}
		s.logger.Printf("Server initialized in Multi-Root mode with %d paths", len(s.mounts))
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

	servingMsg := ""
	if s.singleRoot != "" {
		servingMsg = fmt.Sprintf("serving from %s", s.singleRoot)
	} else {
		servingMsg = fmt.Sprintf("serving %d virtual roots", len(s.mounts))
	}

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

// resolvePath maps a URL path to a physical disk path based on the configuration.
// It returns the full path on disk, and a boolean indicating if this is the virtual root.
func (s *Server) resolvePath(urlPath string) (fullPath string, isVirtualRoot bool, err error) {
	urlPath = path.Clean(urlPath)
	if strings.HasPrefix(urlPath, "..") {
		return "", false, fmt.Errorf("directory traversal attempt")
	}

	// Case 1: Single Root Mode (Backward Compatibility)
	if s.singleRoot != "" {
		return filepath.Join(s.singleRoot, urlPath), false, nil
	}

	// Case 2: Multi Root Mode
	// If it's the root "/", we are in the virtual directory listing
	if urlPath == "." || urlPath == "/" {
		return "", true, nil
	}

	// Split the path to find which mount point (alias) is requested
	// e.g. /movies/action/1.mp4 -> part[0]="", part[1]="movies", part[2]="action/1.mp4"
	// clean path always starts with / so splitting gives empty first element
	parts := strings.SplitN(urlPath, "/", 3)
	if len(parts) < 2 {
		return "", false, fmt.Errorf("invalid path")
	}

	alias := parts[1]
	remainder := ""
	if len(parts) > 2 {
		remainder = parts[2]
	}

	// Find the matching mount
	for _, m := range s.mounts {
		if m.Alias == alias {
			return filepath.Join(m.RealPath, remainder), false, nil
		}
	}

	return "", false, os.ErrNotExist
}

// virtualFileInfo wraps fs.FileInfo to override the Name() method.
type virtualFileInfo struct {
	fs.FileInfo
	name string
}

func (v virtualFileInfo) Name() string {
	return v.name
}

// serveFiles handles all requests to the root path.
func (s *Server) serveFiles(w http.ResponseWriter, r *http.Request) {
	requestedPath := path.Clean(r.URL.Path)

	prefersJSONRecursive := strings.Contains(r.Header.Get("Accept"), "application/json")

	if prefersJSONRecursive {
		s.serveRecursiveList(w, r)
		return
	}

	fullPathOnDisk, isVirtualRoot, err := s.resolvePath(requestedPath)
	if err != nil {
		if strings.Contains(err.Error(), "directory traversal") {
			http.Error(w, "Access Denied", http.StatusForbidden)
			s.logger.Printf("Access denied: %v for path '%s' from %s", err, r.URL.Path, r.RemoteAddr)
		} else if os.IsNotExist(err) {
			http.NotFound(w, r)
			s.logger.Printf("Not found: Path '%s' requested from %s", r.URL.Path, r.RemoteAddr)
		} else {
			s.logger.Printf("Error resolving path '%s': %v", r.URL.Path, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Handle Virtual Root Listing (Multi-path mode only)
	if isVirtualRoot {
		// Construct a list of fake FileInfos representing the roots
		var entries []fs.FileInfo
		for _, m := range s.mounts {
			stat, err := os.Stat(m.RealPath)
			if err != nil {
				s.logger.Printf("Warning: Could not stat mounted path %s: %v", m.RealPath, err)
				continue
			}
			// Create a wrapper to show the Alias as the name instead of the folder name
			entries = append(entries, virtualFileInfo{FileInfo: stat, name: m.Alias})
		}
		s.serveHTMLDirectoryListing(w, r, entries, "/")
		return
	}

	// Handle Physical File/Directory
	f, err := os.Open(fullPathOnDisk)
	if err != nil {
		if os.IsNotExist(err) {
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
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
			s.logger.Printf("Redirected: %s to %s/ (from %s)", r.URL.Path, r.URL.Path, r.RemoteAddr)
			return
		}
		// Check for index files (index.html, index.htm) if WebMode is enabled
		if s.config.WebMode {
			indexFiles := []string{"index.html", "index.htm"}
			for _, indexName := range indexFiles {
				indexFilePath := filepath.Join(fullPathOnDisk, indexName)
				if idxStat, err := os.Stat(indexFilePath); err == nil && !idxStat.IsDir() {
					fIndex, err := os.Open(indexFilePath)
					if err == nil {
						defer fIndex.Close()
						s.logger.Printf("WebMode: Serving %s for directory %s", indexName, r.URL.Path)
						s.handleFileDownload(w, r, fIndex, idxStat)
						return
					}
				}
			}
		}

		// 1. 读取目录项 (DirEntry)，即使有错误也尝试获取已读取的部分
		dirEntries, err := f.ReadDir(-1)
		if err != nil {
			// ReadDir 如果在读到一半时出错，会返回已读取的部分和错误。
			// 我们记录警告，但不要中断，尝试显示已经读到的文件。
			s.logger.Printf("Warning: Error reading directory listing for %s (showing partial results): %v", fullPathOnDisk, err)
		}

		// 2. 将 DirEntry 转换为 FileInfo，并过滤掉无法访问的文件
		var entries []fs.FileInfo
		for _, de := range dirEntries {
			info, err := de.Info()
			if err != nil {
				// 如果某个特定文件无法获取详情（例如权限不足），记录日志并跳过，不影响其他文件显示
				s.logger.Printf("Warning: Skipping file '%s' in '%s': could not stat: %v", de.Name(), fullPathOnDisk, err)
				continue
			}
			entries = append(entries, info)
		}

		s.serveHTMLDirectoryListing(w, r, entries, r.URL.Path)
		return
	}

	s.logger.Printf("Serving file '%s' (size %s) to %s", r.URL.Path, formatBytes(stat.Size()), r.RemoteAddr)
	s.handleFileDownload(w, r, f, stat)
	s.logger.Printf("Served file '%s' (size %s) to %s", r.URL.Path, formatBytes(stat.Size()), r.RemoteAddr)
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

// serveRecursiveList walks the given base path recursively and streams FileInfo objects as NDJSON.
func (s *Server) serveRecursiveList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Transfer-Encoding", "chunked")

	requestedPath := path.Clean(r.URL.Path)

	// Define a helper walker function
	walkAndStream := func(rootDiskPath string, virtualPrefix string) {
		s.logger.Printf("Starting recursive NDJSON list from '%s' (prefix '%s') for %s", rootDiskPath, virtualPrefix, r.RemoteAddr)

		err := filepath.WalkDir(rootDiskPath, func(currentPath string, d fs.DirEntry, err error) error {
			if err != nil {
				s.logger.Printf("Error walking path %s: %v", currentPath, err)
				return nil
			}

			// Calculate relative path from the specific root
			relPath, err := filepath.Rel(rootDiskPath, currentPath)
			if err != nil {
				return nil
			}

			// Prepend the virtual prefix (Alias) if we are in multi-root mode
			// If virtualPrefix is empty (Single Root), it behaves normally.
			// If virtualPrefix is "/Movies", and file is "action/x.mp4", result is "/Movies/action/x.mp4"
			fullVirtualPath := path.Join(virtualPrefix, filepath.ToSlash(relPath))
			if !strings.HasPrefix(fullVirtualPath, "/") {
				fullVirtualPath = "/" + fullVirtualPath
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}

			fileInfo := FileInfo{
				Name:    d.Name(),
				IsDir:   d.IsDir(),
				ModTime: info.ModTime(),
				Size:    info.Size(),
				Path:    fullVirtualPath,
			}

			encoder := json.NewEncoder(w)
			if err := encoder.Encode(fileInfo); err != nil {
				s.logger.Printf("Error encoding FileInfo for %s: %v", currentPath, err)
				return fmt.Errorf("client write error: %w", err)
			}

			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return nil
		})

		if err != nil && strings.Contains(err.Error(), "client write error") {
			s.logger.Printf("Recursive list stopped due to client disconnect.")
		}
	}

	// Case 1: Single Root Mode
	if s.singleRoot != "" {
		fullPath := filepath.Join(s.singleRoot, requestedPath)
		if _, err := os.Stat(fullPath); err != nil {
			http.Error(w, "invalid path", http.StatusNotFound)
			return
		}
		walkAndStream(fullPath, requestedPath) // Prefix is just the requested path (e.g. "/")
		return
	}

	// Case 2: Multi Root Mode
	// If requesting Root "/", walk ALL roots
	if requestedPath == "/" || requestedPath == "." {
		for _, m := range s.mounts {
			// Virtual path prefix will be "/Alias"
			walkAndStream(m.RealPath, "/"+m.Alias)
		}
		return
	}

	// If requesting a specific sub-path (e.g., /movies)
	fullPath, _, err := s.resolvePath(requestedPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// We need to keep the requested path as prefix so client sees "/movies/action/..."
	walkAndStream(fullPath, requestedPath)
}

// handleFileDownload serves a single file.
func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request, file fs.File, stat fs.FileInfo) {
	if !s.config.WebMode {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, stat.Name()))
	}
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
