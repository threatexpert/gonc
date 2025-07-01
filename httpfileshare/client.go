package httpfileshare

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic" // For atomic operations on progress counters
	"time"
)

// ClientConfig holds the client configuration for downloads.
type ClientConfig struct {
	ServerURL              string
	LocalDir               string
	Concurrency            int
	Overwrite              bool
	Exclude                []string
	Include                []string
	Resume                 bool
	DryRun                 bool
	Verbose                bool
	LoggerOutput           io.Writer
	ProgressOutput         io.Writer
	ProgressUpdateInterval time.Duration
}

// Client represents our download client.
type Client struct {
	config ClientConfig
	logger *log.Logger
	queue  chan FileInfo // Channel for files to download
	wg     sync.WaitGroup

	absLocalDownloadRoot string

	progressTracker *DownloadProgress
}

// DownloadProgress tracks the overall download progress.
type DownloadProgress struct {
	totalFiles      atomic.Int64 // Total number of files to download
	filesDownloaded atomic.Int64 // Number of files completed
	totalBytes      atomic.Int64 // Total bytes expected from all files
	bytesDownloaded atomic.Int64 // Total bytes downloaded so far

	bytesDownloadedLastInterval atomic.Int64 // Bytes downloaded since last speed calculation
	lastSpeedCalcTime           atomic.Int64 // UnixNano timestamp of last speed calculation

	mu             sync.Mutex    // Protects console updates
	progressOutput io.Writer     // The writer to send progress updates to
	lastUpdateTime time.Time     // Last time progress was printed
	updateInterval time.Duration // Desired update frequency
}

// NewDownloadProgress initializes a new progress tracker.
func NewDownloadProgress(output io.Writer, updateInterval time.Duration) *DownloadProgress {
	p := &DownloadProgress{
		progressOutput:    output,
		lastUpdateTime:    time.Now(),
		updateInterval:    updateInterval,
		lastSpeedCalcTime: atomic.Int64{},
	}
	p.bytesDownloadedLastInterval.Store(0)
	p.lastSpeedCalcTime.Store(time.Now().UnixNano()) // Initialize
	return p
}

// IncrementTotalFiles adds to the total count of files to be processed.
func (p *DownloadProgress) IncrementTotalFiles() {
	p.totalFiles.Add(1)
}

// AddTotalBytes adds to the total expected bytes.
func (p *DownloadProgress) AddTotalBytes(size int64) {
	p.totalBytes.Add(size)
}

// AddBytesDownloaded increments bytes for the overall download.
func (p *DownloadProgress) AddBytesDownloaded(n int64) {
	p.bytesDownloaded.Add(n)
}

func (p *DownloadProgress) AddBytesCopied(n int64) {
	p.bytesDownloaded.Add(n)
	p.bytesDownloadedLastInterval.Add(n) // Add to interval counter for speed
}

// FileCompleted increments the count of downloaded files.
func (p *DownloadProgress) FileCompleted() {
	p.filesDownloaded.Add(1)
}

// PrintProgress updates the console with current progress, rate-limited.
func (p *DownloadProgress) PrintProgress(force, ended bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Rate limit check
	now := time.Now()
	if !force && now.Sub(p.lastUpdateTime) < p.updateInterval {
		return // Not enough time has passed since last update
	}
	p.lastUpdateTime = now // Update last update time

	overallProgress := 0.0
	totalBytes := p.totalBytes.Load()
	bytesDownloaded := p.bytesDownloaded.Load()
	if totalBytes > 0 {
		overallProgress = float64(bytesDownloaded) / float64(totalBytes) * 100
	}

	// Calculate speed
	currentBytesDownloadedInterval := p.bytesDownloadedLastInterval.Swap(0) // Get and reset
	lastCalcTime := time.Unix(0, p.lastSpeedCalcTime.Swap(now.UnixNano()))  // Get and reset

	duration := now.Sub(lastCalcTime).Seconds()
	speed := 0.0
	if duration > 0 {
		speed = float64(currentBytesDownloadedInterval) / duration
	}

	// Clear current line and print new progress.
	fmt.Fprintf(p.progressOutput, "\r\033[K * Overall: %d/%d files (%s/%s, %.1f%%) Speed: %s/s  ",
		p.filesDownloaded.Load(), p.totalFiles.Load(),
		formatBytes(bytesDownloaded), formatBytes(totalBytes), overallProgress,
		formatBytes(int64(speed)))
	if ended {
		totalBytes := p.totalBytes.Load()
		bytesDownloaded := p.bytesDownloaded.Load()

		if bytesDownloaded == totalBytes {
			fmt.Fprintf(p.progressOutput, "\n * Download complete. Total files: %d, Total bytes: %s.\n",
				p.filesDownloaded.Load(), formatBytes(bytesDownloaded))
		} else if bytesDownloaded > totalBytes {
			fmt.Fprintf(p.progressOutput, "\n * Download exceeds the expected total. Total files: %d, Total bytes: %s.\n",
				p.filesDownloaded.Load(), formatBytes(bytesDownloaded))
		} else {
			// If downloaded bytes are less than expected total
			fmt.Fprintf(p.progressOutput, "\n * Download incomplete. Downloaded %s of %s. Files processed: %d of %d.\n",
				formatBytes(bytesDownloaded), formatBytes(totalBytes),
				p.filesDownloaded.Load(), p.totalFiles.Load())
		}
	}
}

// ClearProgressLine clears the last printed progress line.
func (p *DownloadProgress) ClearProgressLine() {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprint(p.progressOutput, "\r\033[K")
}

// ProgressWriter wraps an io.Writer to report progress.
type ProgressWriter struct {
	Writer   io.Writer
	Progress *DownloadProgress
}

// Write implements the io.Writer interface.
func (pw *ProgressWriter) Write(p []byte) (int, error) {
	n, err := pw.Writer.Write(p)
	if err == nil {
		pw.Progress.AddBytesCopied(int64(n))
		pw.Progress.PrintProgress(false, false) // Update progress, not forcing
	}
	return n, err
}

// NewClient creates a new Client instance.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("server URL cannot be empty")
	}
	if cfg.LocalDir == "" {
		return nil, fmt.Errorf("local directory cannot be empty")
	}

	absLocalDir, err := filepath.Abs(cfg.LocalDir)
	if err != nil {
		return nil, fmt.Errorf("invalid local directory path: %w", err)
	}
	cfg.LocalDir = absLocalDir

	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}

	if cfg.LoggerOutput == nil {
		cfg.LoggerOutput = io.Discard
	}
	clientLogger := log.New(cfg.LoggerOutput, "[CLIENT] ", log.Ldate|log.Ltime)

	if cfg.ProgressOutput == nil {
		cfg.ProgressOutput = io.Discard
	}
	if cfg.ProgressUpdateInterval <= 0 {
		cfg.ProgressUpdateInterval = time.Second
	}
	progressTracker := NewDownloadProgress(cfg.ProgressOutput, cfg.ProgressUpdateInterval)

	return &Client{
		config:               cfg,
		logger:               clientLogger,
		queue:                make(chan FileInfo, cfg.Concurrency*2),
		absLocalDownloadRoot: absLocalDir,
		progressTracker:      progressTracker,
	}, nil
}

// Start initiates the download process.
func (c *Client) Start(ctx context.Context) error {
	c.logger.Printf("Starting client download from %s to %s", c.config.ServerURL, c.config.LocalDir)

	if !c.config.DryRun {
		if err := os.MkdirAll(c.config.LocalDir, 0755); err != nil {
			return fmt.Errorf("failed to create local directory %s: %w", c.config.LocalDir, err)
		}
	} else {
		c.logger.Printf("Dry run enabled: no files will be downloaded or created.")
	}

	// Fetch all file information first
	filesToDownload, err := c.fetchFileList(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch file list: %w", err)
	}

	// Initialize queue size based on number of files determined
	c.queue = make(chan FileInfo, c.config.Concurrency*2)

	for i := 0; i < c.config.Concurrency; i++ {
		c.wg.Add(1)
		go c.worker(ctx)
	}

	// Now populate the queue with files to download
	for _, fileInfo := range filesToDownload {
		select {
		case c.queue <- fileInfo: // Try to send fileInfo
			// Successfully sent
		case <-ctx.Done(): // Context cancelled
			c.logger.Printf("Client stopped populating queue due to context cancellation: %v", ctx.Err())
			close(c.queue)   // Close queue to unblock workers
			c.wg.Wait()      // Wait for workers to finish current tasks
			return ctx.Err() // Return context cancellation error
		}
	}

	close(c.queue)
	c.wg.Wait()

	c.progressTracker.PrintProgress(true, true)
	//c.progressTracker.ClearProgressLine() // Clear final progress line
	c.logger.Println("Download process completed.")
	return nil
}

// fetchFileList connects to the server and streams recursive file info,
// collecting all FileInfo objects before returning them.
func (c *Client) fetchFileList(ctx context.Context) ([]FileInfo, error) {
	serverURL, err := url.Parse(c.config.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	requestPath := path.Clean(serverURL.Path)
	if requestPath == "." {
		requestPath = "/"
	} else if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}

	fullRequestURL := serverURL.Scheme + "://" + serverURL.Host + requestPath

	req, err := http.NewRequestWithContext(ctx, "GET", fullRequestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non-OK status for file list (%s): %s", fullRequestURL, resp.Status)
	}

	var collectedFiles []FileInfo // Collect files here
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			c.logger.Printf("Aborting file list fetch due to context cancellation: %v", ctx.Err())
			return nil, ctx.Err()
		default:
		}
		line := scanner.Bytes()
		var fileInfo FileInfo
		if err := json.Unmarshal(line, &fileInfo); err != nil {
			c.logger.Printf("Error unmarshaling JSON line: %v, line: %s", err, string(line))
			continue
		}

		if fileInfo.IsDir {
			if !c.config.DryRun {
				urlPathRelativeToRoot := path.Clean(serverURL.Path)
				if urlPathRelativeToRoot == "." {
					urlPathRelativeToRoot = "/"
				} else if !strings.HasPrefix(urlPathRelativeToRoot, "/") {
					urlPathRelativeToRoot = "/" + urlPathRelativeToRoot
				}
				adjustedRelativePath := fileInfo.Path
				if strings.HasPrefix(fileInfo.Path, urlPathRelativeToRoot) {
					adjustedRelativePath = strings.TrimPrefix(fileInfo.Path, urlPathRelativeToRoot)
					if strings.HasPrefix(adjustedRelativePath, "/") && len(adjustedRelativePath) > 1 {
						adjustedRelativePath = adjustedRelativePath[1:]
					} else if adjustedRelativePath == "/" {
						adjustedRelativePath = ""
					}
				}

				if adjustedRelativePath != "" {
					dirPath := filepath.Join(c.config.LocalDir, filepath.FromSlash(adjustedRelativePath))
					if c.config.Verbose {
						c.logger.Printf("Creating directory: %s", dirPath)
					}
					if err := os.MkdirAll(dirPath, 0755); err != nil {
						c.logger.Printf("Warning: Failed to create directory %s: %v", dirPath, err)
					}
				} else {
					if c.config.Verbose {
						c.logger.Printf("Skipping creating base directory, as it is the target local directory: %s", c.config.LocalDir)
					}
				}
			} else if c.config.Verbose && fileInfo.Path != requestPath {
				urlPathRelativeToRoot := path.Clean(serverURL.Path)
				if urlPathRelativeToRoot == "." {
					urlPathRelativeToRoot = "/"
				} else if !strings.HasPrefix(urlPathRelativeToRoot, "/") {
					urlPathRelativeToRoot = "/" + urlPathRelativeToRoot
				}
				adjustedRelativePath := fileInfo.Path
				if strings.HasPrefix(fileInfo.Path, urlPathRelativeToRoot) {
					adjustedRelativePath = strings.TrimPrefix(fileInfo.Path, urlPathRelativeToRoot)
					if strings.HasPrefix(adjustedRelativePath, "/") && len(adjustedRelativePath) > 1 {
						adjustedRelativePath = adjustedRelativePath[1:]
					} else if adjustedRelativePath == "/" {
						adjustedRelativePath = ""
					}
				}
				if adjustedRelativePath != "" {
					c.logger.Printf("Dry run: Would create directory: %s", filepath.Join(c.config.LocalDir, filepath.FromSlash(adjustedRelativePath)))
				}
			}
			continue
		}

		if !c.shouldInclude(fileInfo.Path) || c.shouldExclude(fileInfo.Path) {
			if c.config.Verbose {
				c.logger.Printf("Skipping %s due to include/exclude filters", fileInfo.Path)
			}
			continue
		}

		collectedFiles = append(collectedFiles, fileInfo) // Collect the fileInfo
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading server response: %w", err)
	}

	// After collecting all files, calculate totals and populate progress tracker
	for _, fileInfo := range collectedFiles {
		c.progressTracker.IncrementTotalFiles()
		c.progressTracker.AddTotalBytes(fileInfo.Size)
	}

	c.logger.Printf("Finished fetching file list. Total files to process: %d, total bytes: %s",
		c.progressTracker.totalFiles.Load(), formatBytes(c.progressTracker.totalBytes.Load()))

	// Return the list of files to the Start method
	return collectedFiles, nil
}

// worker goroutine to download files from the queue.
func (c *Client) worker(ctx context.Context) {
	defer c.wg.Done()
	httpClient := &http.Client{}

	for fileInfo := range c.queue {
		select {
		case <-ctx.Done(): // Context cancelled, exit worker
			c.logger.Printf("worker exiting due to context cancellation: %v", ctx.Err())
			return // Exit the worker goroutine
		default:
			// Continue with download
		}
		err := c.downloadFile(ctx, httpClient, fileInfo)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue // Skip to next file in queue
		}
		c.progressTracker.FileCompleted()
		c.progressTracker.PrintProgress(true, false) // Force a final progress update for overall count
	}
}

// downloadFile downloads a single file, supporting resume with Range header.
func (c *Client) downloadFile(ctx context.Context, httpClient *http.Client, fileInfo FileInfo) error {
	select {
	case <-ctx.Done():
		return ctx.Err() // Return context cancellation error immediately
	default:
	}
	remoteURL, err := url.Parse(c.config.ServerURL)
	if err != nil {
		c.logger.Printf("Error parsing server URL for %s: %v", fileInfo.Path, err)
		return err
	}

	serverBaseURLPath := path.Clean(remoteURL.Path)
	if serverBaseURLPath == "." {
		serverBaseURLPath = "/"
	} else if !strings.HasPrefix(serverBaseURLPath, "/") {
		serverBaseURLPath = "/" + serverBaseURLPath
	}

	actualDownloadPathOnServer := serverBaseURLPath
	if fileInfo.Path != "" {
		if !strings.HasSuffix(serverBaseURLPath, "/") {
			actualDownloadPathOnServer += "/"
		}
		actualDownloadPathOnServer += filepath.ToSlash(fileInfo.Path)
	}

	downloadURL := remoteURL.Scheme + "://" + remoteURL.Host + actualDownloadPathOnServer

	proposedLocalPath := filepath.Join(c.config.LocalDir, filepath.FromSlash(fileInfo.Path))
	cleanedLocalPath := filepath.Clean(proposedLocalPath)

	if !strings.HasPrefix(cleanedLocalPath, c.absLocalDownloadRoot) {
		return fmt.Errorf("SECURITY ALERT: Attempted path traversal detected for server path '%s'. Resolved local path '%s' is outside root '%s'",
			fileInfo.Path, cleanedLocalPath, c.absLocalDownloadRoot)
	}
	localFilePath := cleanedLocalPath

	var localFileExists bool
	var localFileSize int64
	fileMode := os.O_CREATE | os.O_WRONLY

	if stat, err := os.Stat(localFilePath); err == nil {
		localFileExists = true
		localFileSize = stat.Size()
		if c.config.Verbose {
			c.logger.Printf("Local file exists: %s, size: %d bytes", localFilePath, localFileSize)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error checking local file %s: %w", localFilePath, err)
	}

	if c.config.Resume && localFileExists && localFileSize < fileInfo.Size {
		if c.config.Verbose {
			c.logger.Printf("Resuming download for %s. Local size: %d, Server size: %d", localFilePath, localFileSize, fileInfo.Size)
		}
		fileMode |= os.O_APPEND
		c.progressTracker.AddBytesDownloaded(localFileSize)
	} else if c.config.Resume && localFileExists && localFileSize >= fileInfo.Size {
		if c.config.Verbose {
			c.logger.Printf("File %s already appears complete (local size %d >= server size %d). Skipping download.", localFilePath, localFileSize, fileInfo.Size)
		}
		c.progressTracker.AddBytesDownloaded(localFileSize)
		return nil
	} else if localFileExists && !c.config.Overwrite {
		if c.config.Verbose {
			c.logger.Printf("Skipping existing file (use -o to overwrite): %s", localFilePath)
		}
		c.progressTracker.AddBytesDownloaded(localFileSize)
		return nil
	} else if localFileExists && c.config.Overwrite {
		c.logger.Printf("Overwriting existing file: %s", localFilePath)
	} else if c.config.DryRun {
		c.logger.Printf("Dry run: Would download %s to %s", downloadURL, localFilePath)
		return nil
	}
	// Attach context to the request for HTTP client operation
	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return fmt.Errorf("error creating download request for %s: %w", downloadURL, err)
	}

	if c.config.Resume && localFileExists && localFileSize < fileInfo.Size {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", localFileSize))
		if c.config.Verbose {
			c.logger.Printf("Requesting bytes %d- for %s", localFileSize, downloadURL)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// Differentiate context cancellation from other errors
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err // Propagate context cancellation error
		}
		return fmt.Errorf("error downloading %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()

	responseBytesOffset := int64(0)
	if resp.StatusCode == http.StatusPartialContent {
		if !c.config.Resume || !localFileExists || localFileSize >= fileInfo.Size {
			c.logger.Printf("Warning: Received 206 Partial Content for %s but not in resume mode or file already complete. Proceeding as full download.", downloadURL)
		}
		responseBytesOffset = localFileSize
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned unexpected status %s for %s", resp.Status, downloadURL)
	} else if resp.StatusCode == http.StatusOK && c.config.Resume && localFileExists && localFileSize < fileInfo.Size {
		c.logger.Printf("Server does not support Range requests for %s (received 200 OK instead of 206). Restarting download.", downloadURL)
		fileMode = os.O_CREATE | os.O_WRONLY
	}

	if err := os.MkdirAll(filepath.Dir(localFilePath), 0755); err != nil {
		return fmt.Errorf("error creating parent directories for %s: %w", localFilePath, err)
	}

	outFile, err := os.OpenFile(localFilePath, fileMode, 0644)
	if err != nil {
		return fmt.Errorf("error opening/creating local file %s with mode %s: %v", localFilePath, getFileModeString(fileMode), err)
	}
	defer outFile.Close()

	if resp.StatusCode == http.StatusPartialContent && c.config.Resume && localFileExists {
		if _, err := outFile.Seek(localFileSize, io.SeekStart); err != nil {
			return fmt.Errorf("error seeking to end of file %s for resume: %w", localFilePath, err)
		}
	}

	writerForCopy := io.Writer(outFile)
	if !c.config.Verbose {
		writerForCopy = &ProgressWriter{
			Writer:   outFile,
			Progress: c.progressTracker,
		}
	}

	bytesCopiedSuccessfully, err := io.Copy(writerForCopy, resp.Body) // Use the wrapped bodyReader

	if err != nil && err != io.EOF {
		// If the error is due to context cancellation, just return it.
		// Otherwise, it's a genuine copy error.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("error during file copy for %s: %w", localFilePath, err)
	}

	if expectedBytesToRead := resp.ContentLength; expectedBytesToRead != -1 && bytesCopiedSuccessfully != expectedBytesToRead {
		return fmt.Errorf("integrity warning: downloaded %d bytes for %s, but expected %d from response. File segment might be incomplete",
			bytesCopiedSuccessfully, filepath.Base(localFilePath), expectedBytesToRead)
	}

	finalTotalBytesOnDisk := bytesCopiedSuccessfully + responseBytesOffset

	if finalTotalBytesOnDisk != fileInfo.Size {
		return fmt.Errorf("CRITICAL WARNING: Final size of %s (%d bytes) does not match expected server size (%d bytes)! File is incomplete or corrupted",
			localFilePath, finalTotalBytesOnDisk, fileInfo.Size)
	} else {
		c.logger.Printf("Downloaded %s (%d bytes) to %s. Total size on disk: %d bytes (expected full: %d)",
			filepath.Base(localFilePath), bytesCopiedSuccessfully, localFilePath, finalTotalBytesOnDisk, fileInfo.Size)
	}

	if err := os.Chtimes(localFilePath, time.Now(), fileInfo.ModTime); err != nil {
		c.logger.Printf("Warning: Could not set modification time for %s: %v", localFilePath, err)
	}

	return nil
}

// Helper for logging file mode strings
func getFileModeString(mode int) string {
	var parts []string
	if mode&os.O_RDONLY != 0 {
		parts = append(parts, "O_RDONLY")
	}
	if mode&os.O_WRONLY != 0 {
		parts = append(parts, "O_WRONLY")
	}
	if mode&os.O_RDWR != 0 {
		parts = append(parts, "O_RDWR")
	}
	if mode&os.O_APPEND != 0 {
		parts = append(parts, "O_APPEND")
	}
	if mode&os.O_CREATE != 0 {
		parts = append(parts, "O_CREATE")
	}
	if mode&os.O_EXCL != 0 {
		parts = append(parts, "O_EXCL")
	}
	if mode&os.O_SYNC != 0 {
		parts = append(parts, "O_SYNC")
	}
	if mode&os.O_TRUNC != 0 {
		parts = append(parts, "O_TRUNC")
	}
	return strings.Join(parts, "|")
}

// shouldExclude checks if a path matches any exclude patterns.
func (c *Client) shouldExclude(filePath string) bool {
	for _, pattern := range c.config.Exclude {
		cleanFilePath := path.Clean(filePath)

		matched, err := filepath.Match(pattern, filepath.Base(cleanFilePath))
		if err != nil {
			c.logger.Printf("Error with exclude pattern %s (base name): %v", pattern, err)
			continue
		}
		if matched {
			return true
		}
		matched, err = filepath.Match(pattern, cleanFilePath)
		if err != nil {
			c.logger.Printf("Error with exclude pattern %s (full path): %v", pattern, err)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// shouldInclude checks if a path matches any include patterns.
func (c *Client) shouldInclude(filePath string) bool {
	if len(c.config.Include) == 0 {
		return true
	}
	for _, pattern := range c.config.Include {
		cleanFilePath := path.Clean(filePath)

		matched, err := filepath.Match(pattern, filepath.Base(cleanFilePath))
		if err != nil {
			c.logger.Printf("Error with include pattern %s (base name): %v", pattern, err)
			continue
		}
		if matched {
			return true
		}
		matched, err = filepath.Match(pattern, cleanFilePath)
		if err != nil {
			c.logger.Printf("Error with include pattern %s (full path): %v", pattern, err)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}
