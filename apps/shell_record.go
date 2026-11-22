package apps

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const shellRecordChunk = 4096

// Serialize complete watch lines across sessions, independently of -v=false/-log.
var shellWatchMu sync.Mutex

// Display IDs are process-local; recording filenames remain unique across runs.
var shellRecordID atomic.Uint64

type shellRecordEvent struct {
	at   time.Time
	dir  string
	data []byte
}

type shellRecorder struct {
	mu      sync.RWMutex
	closed  bool
	id      string
	file    io.WriteCloser
	watch   io.Writer
	events  chan shellRecordEvent
	done    chan struct{}
	dropped atomic.Uint64
	end     string // Set before closing events, after all producers have stopped.
}

func newShellRecorder(config *PtyShellConfig, peer string) (*shellRecorder, error) {
	if !config.Watch && config.RecordDir == "" {
		return nil, nil
	}
	id := fmt.Sprintf("id-%d", shellRecordID.Add(1)-1)
	r := &shellRecorder{id: id, events: make(chan shellRecordEvent, 128), done: make(chan struct{})}
	if config.RecordDir != "" {
		if err := os.MkdirAll(config.RecordDir, 0700); err != nil {
			return nil, err
		}
		name := time.Now().Format("20060102-150405") + "-" + id + "-*.log"
		f, err := os.CreateTemp(config.RecordDir, name)
		if err != nil {
			return nil, err
		}
		r.file = f
	}
	if config.Watch {
		r.watch = os.Stderr
	}
	go r.run()
	r.add("META", []byte(fmt.Sprintf("start peer=%q pty=%t args=%q", peer, config.EnablePty, config.Args)))
	return r, nil
}

// Never let a slow disk or observer stall the shell. Loss is reported explicitly.
func (r *shellRecorder) add(dir string, p []byte) {
	if r == nil {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return
	}
	for len(p) > 0 {
		n := min(len(p), shellRecordChunk)
		e := shellRecordEvent{at: time.Now(), dir: dir, data: bytes.Clone(p[:n])}
		select {
		case r.events <- e:
		default:
			r.dropped.Add(uint64(n))
		}
		p = p[n:]
	}
}

func (r *shellRecorder) close(end string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		r.end = end
		close(r.events)
	}
	r.mu.Unlock()
	<-r.done
}

func (r *shellRecorder) warn(message string) {
	shellWatchMu.Lock()
	defer shellWatchMu.Unlock()
	fmt.Fprintf(os.Stderr, "[:sh %s] %s\n", r.id, message)
}

func (r *shellRecorder) line(at time.Time, dir string, p []byte) {
	// Quote preserves printable Unicode and escapes invalid bytes, terminal
	// controls and backslashes. Remove only the surrounding quotation marks.
	quoted := strconv.Quote(string(p))
	line := fmt.Sprintf("%s [%s %-4s] %s\n", at.Local().Format("15:04:05"), r.id, dir, quoted[1:len(quoted)-1])
	if r.file != nil {
		if _, err := io.WriteString(r.file, line); err != nil {
			r.warn(fmt.Sprintf("recording failed; subsequent data will not be saved: %v", err))
			r.file.Close()
			r.file = nil
		}
	}
	if r.watch != nil {
		shellWatchMu.Lock()
		_, err := io.WriteString(r.watch, line)
		shellWatchMu.Unlock()
		if err != nil {
			r.warn(fmt.Sprintf("watch output failed: %v", err))
			r.watch = nil
		}
	}
}

func (r *shellRecorder) run() {
	defer close(r.done)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var pending shellRecordEvent
	flush := func() {
		if len(pending.data) > 0 {
			r.line(pending.at, pending.dir, pending.data)
			pending.data = nil
		}
	}
	reportLoss := func() {
		if n := r.dropped.Swap(0); n > 0 {
			flush()
			message := fmt.Sprintf("recording queue full: %d bytes omitted (gap location approximate)", n)
			r.line(time.Now(), "GAP", []byte(message))
			r.warn(message)
		}
	}
	for {
		select {
		case e, ok := <-r.events:
			reportLoss()
			if !ok {
				flush()
				r.line(time.Now(), "META", []byte(r.end))
				if r.file != nil {
					if err := r.file.Close(); err != nil {
						r.warn(fmt.Sprintf("closing recording failed: %v", err))
					}
				}
				return
			}
			if pending.dir != e.dir {
				flush()
			}
			for len(e.data) > 0 {
				if len(pending.data) == 0 {
					pending.at, pending.dir = e.at, e.dir
				}
				n := min(len(e.data), shellRecordChunk-len(pending.data))
				if i := bytes.IndexByte(e.data[:n], '\n'); i >= 0 {
					n = i + 1
				}
				pending.data = append(pending.data, e.data[:n]...)
				e.data = e.data[n:]
				if pending.data[len(pending.data)-1] == '\n' || len(pending.data) == shellRecordChunk {
					flush()
				}
			}
		case <-ticker.C:
			reportLoss()
			flush()
		}
	}
}

// Input is recorded only after the shell accepts it. Output is recorded as it
// is read from the process, including bytes a disconnect prevents delivering.
type shellRecordWriter struct {
	w   io.Writer
	r   *shellRecorder
	dir string
}

func (w shellRecordWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.r.add(w.dir, p[:n])
	return n, err
}

type shellRecordReader struct {
	r        io.Reader
	recorder *shellRecorder
}

func (r shellRecordReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.recorder.add("OUT", p[:n])
	return n, err
}
