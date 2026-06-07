package apps

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"golang.org/x/term"
)

const (
	ptyshVersion       = 1
	ptyshOSCPrefix     = "\x1b]777;gonc-ptysh="
	ptyshOSCMaxPayload = 1024
	ptyshSIDSize       = 8
	ptyshResizeFrameN  = 17
)

var ptyshResizeMagic = []byte{0xff, 0xff, 'g', 'r', ptyshVersion}

type ptyshCaps struct {
	V    int      `json:"v"`
	SID  string   `json:"sid"`
	Caps []string `json:"caps,omitempty"`
}

func newPtyshSID() ([]byte, string, error) {
	sid := make([]byte, ptyshSIDSize)
	if _, err := rand.Read(sid); err != nil {
		return nil, "", err
	}
	return sid, hex.EncodeToString(sid), nil
}

func encodePtyshCaps(sidHex string) ([]byte, error) {
	payload, err := json.Marshal(ptyshCaps{
		V:    ptyshVersion,
		SID:  sidHex,
		Caps: []string{"pty.resize"},
	})
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(ptyshOSCPrefix)+len(payload)+1)
	out = append(out, ptyshOSCPrefix...)
	out = append(out, payload...)
	out = append(out, '\a')
	return out, nil
}

func encodePtyshResize(sid []byte, rows, cols int) []byte {
	frame := make([]byte, ptyshResizeFrameN)
	copy(frame, ptyshResizeMagic)
	copy(frame[len(ptyshResizeMagic):], sid)
	off := len(ptyshResizeMagic) + ptyshSIDSize
	binary.BigEndian.PutUint16(frame[off:], uint16(rows))
	binary.BigEndian.PutUint16(frame[off+2:], uint16(cols))
	return frame
}

func decodePtyshSID(sidHex string) ([]byte, bool) {
	sid, err := hex.DecodeString(sidHex)
	return sid, err == nil && len(sid) == ptyshSIDSize
}

func ptyshCapsSupportResize(caps []string) bool {
	for _, cap := range caps {
		if cap == "pty.resize" {
			return true
		}
	}
	return false
}

type lockedWriter struct {
	w  io.Writer
	mu sync.Mutex
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

type ptyshCapsOutputWriter struct {
	dst     io.Writer
	onCaps  func([]byte)
	state   int
	done    bool
	prefix  []byte
	payload []byte
	pending []byte
}

func newPtyshCapsOutputWriter(dst io.Writer, onCaps func([]byte)) *ptyshCapsOutputWriter {
	return &ptyshCapsOutputWriter{
		dst:    dst,
		onCaps: onCaps,
		prefix: []byte(ptyshOSCPrefix),
	}
}

func (w *ptyshCapsOutputWriter) Write(p []byte) (int, error) {
	if w.done {
		_, err := w.dst.Write(p)
		return len(p), err
	}

	for i, b := range p {
		switch w.state {
		case 0:
			w.pending = append(w.pending, b)
			if len(w.pending) <= len(w.prefix) && w.pending[len(w.pending)-1] == w.prefix[len(w.pending)-1] {
				if len(w.pending) == len(w.prefix) {
					w.state = 1
				}
				continue
			}
			w.done = true
			if _, err := w.dst.Write(w.pending); err != nil {
				return len(p), err
			}
			w.pending = nil
			if i+1 < len(p) {
				if _, err := w.dst.Write(p[i+1:]); err != nil {
					return len(p), err
				}
			}
			return len(p), nil
		case 1:
			w.pending = append(w.pending, b)
			if b == '\a' {
				w.done = true
				var caps ptyshCaps
				if err := json.Unmarshal(w.payload, &caps); err == nil && caps.V == ptyshVersion && ptyshCapsSupportResize(caps.Caps) {
					if sid, ok := decodePtyshSID(caps.SID); ok && w.onCaps != nil {
						w.onCaps(sid)
					}
				} else {
					if _, err := w.dst.Write(w.pending); err != nil {
						return len(p), err
					}
				}
				w.pending = nil
				w.payload = nil
				if i+1 < len(p) {
					if _, err := w.dst.Write(p[i+1:]); err != nil {
						return len(p), err
					}
				}
				return len(p), nil
			}
			w.payload = append(w.payload, b)
			if len(w.payload) > ptyshOSCMaxPayload {
				w.done = true
				if _, err := w.dst.Write(w.pending); err != nil {
					return len(p), err
				}
				w.pending = nil
				w.payload = nil
				if i+1 < len(p) {
					if _, err := w.dst.Write(p[i+1:]); err != nil {
						return len(p), err
					}
				}
				return len(p), nil
			}
		}
	}
	return len(p), nil
}

type ptyshResizeInputReader struct {
	r        io.Reader
	sid      []byte
	onResize func(rows, cols int)

	state    int
	frameBuf []byte
	out      []byte
	readBuf  []byte
	savedErr error
}

func newPtyshResizeInputReader(r io.Reader, sid []byte, onResize func(rows, cols int)) *ptyshResizeInputReader {
	return &ptyshResizeInputReader{r: r, sid: sid, onResize: onResize, readBuf: make([]byte, 32*1024)}
}

func (r *ptyshResizeInputReader) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.savedErr != nil {
			err := r.savedErr
			r.savedErr = nil
			return 0, err
		}

		n, err := r.r.Read(r.readBuf)
		if n > 0 {
			for _, b := range r.readBuf[:n] {
				r.consume(b)
			}
		}
		if err != nil {
			if len(r.frameBuf) > 0 {
				r.emit(r.frameBuf)
				r.frameBuf = nil
				r.state = 0
				r.savedErr = err
			} else if len(r.out) == 0 {
				return 0, err
			} else {
				r.savedErr = err
			}
		}
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *ptyshResizeInputReader) consume(b byte) {
	switch r.state {
	case 0:
		if b == 0xff {
			r.frameBuf = append(r.frameBuf[:0], b)
			r.state = 1
			return
		}
		r.out = append(r.out, b)
	case 1:
		if b == 0xff {
			r.frameBuf = append(r.frameBuf, b)
			r.state = 2
			return
		}
		r.emit(append(r.frameBuf, b))
		r.frameBuf = nil
		r.state = 0
	case 2:
		if b == 'g' {
			r.frameBuf = append(r.frameBuf, b)
			r.state = 3
			return
		}
		r.emit(append(r.frameBuf, b))
		r.frameBuf = nil
		r.state = 0
	case 3:
		if b == 'r' {
			r.frameBuf = append(r.frameBuf, b)
			r.state = 4
			return
		}
		r.emit(append(r.frameBuf, b))
		r.frameBuf = nil
		r.state = 0
	case 4:
		if b == ptyshVersion {
			r.frameBuf = append(r.frameBuf, b)
			r.state = 5
			return
		}
		r.emit(append(r.frameBuf, b))
		r.frameBuf = nil
		r.state = 0
	case 5:
		r.frameBuf = append(r.frameBuf, b)
		if len(r.frameBuf) < ptyshResizeFrameN {
			return
		}
		r.handleFrame()
		r.frameBuf = nil
		r.state = 0
	}
}

func (r *ptyshResizeInputReader) emit(b []byte) {
	r.out = append(r.out, b...)
}

func (r *ptyshResizeInputReader) handleFrame() {
	off := len(ptyshResizeMagic)
	if len(r.sid) != ptyshSIDSize || string(r.frameBuf[off:off+ptyshSIDSize]) != string(r.sid) {
		r.emit(r.frameBuf)
		return
	}
	off += ptyshSIDSize
	rows := int(binary.BigEndian.Uint16(r.frameBuf[off:]))
	cols := int(binary.BigEndian.Uint16(r.frameBuf[off+2:]))
	if rows <= 0 || cols <= 0 {
		return
	}
	if r.onResize != nil {
		r.onResize(rows, cols)
	}
}

func startPtyshResizeSender(stop <-chan struct{}, writer io.Writer, sid []byte, logger *log.Logger) {
	var lastRows, lastCols int
	sendCurrent := func() {
		cols, rows, err := localTerminalSize()
		if err != nil || rows <= 0 || cols <= 0 {
			return
		}
		if rows == lastRows && cols == lastCols {
			return
		}
		lastRows, lastCols = rows, cols
		if _, err := writer.Write(encodePtyshResize(sid, rows, cols)); err != nil {
			if logger != nil {
				logger.Printf("pty resize send error: %v\n", err)
			}
			return
		}
	}

	sendCurrent()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			sendCurrent()
		case <-stop:
			return
		}
	}
}

func localTerminalSize() (cols, rows int, err error) {
	cols, rows, err = term.GetSize(int(os.Stdout.Fd()))
	if err == nil {
		return cols, rows, nil
	}
	return term.GetSize(int(os.Stdin.Fd()))
}
