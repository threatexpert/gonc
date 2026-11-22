package apps

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

const shellSessionCapability = "session.v2"
const shellUpgradeTimeout = 5 * time.Second

func encodeShellSessionCaps(sid string) []byte {
	payload, _ := json.Marshal(ptyshCaps{V: 1, SID: sid, Caps: []string{"pty.resize", shellSessionCapability, "file.v1"}})
	return append(append([]byte(ptyshOSCPrefix), payload...), '\a')
}

func shellUpgradeAck(sid []byte) []byte {
	return []byte("\x1b]777;gonc-session=2;" + hex.EncodeToString(sid) + "\a")
}

func shellMuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2 // Per-stream flow control keeps a stalled file from blocking the terminal.
	c.MaxFrameSize = 16 * 1024
	return c
}

type shellBufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *shellBufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// shellServerConn starts as the legacy byte stream. Writes and the upgrade ACK
// share a lock, making the ACK an exact raw-output/framed-output boundary.
type shellServerConn struct {
	net.Conn
	reader   *ptyshResizeInputReader
	mu       sync.Mutex
	control  sync.WaitGroup
	writer   io.Writer
	session  *smux.Session
	sid      []byte
	resize   func(int, int)
	recorder *shellRecorder
}

func newShellServerConn(conn net.Conn, sid []byte, resize func(int, int), recorder *shellRecorder) *shellServerConn {
	c := &shellServerConn{Conn: conn, writer: conn, sid: sid, resize: resize, recorder: recorder}
	c.reader = newPtyshResizeInputReader(conn, sid, resize)
	c.reader.onUpgrade = c.upgrade
	return c
}

func (c *shellServerConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *shellServerConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writer.Write(p)
}

func (c *shellServerConn) upgrade(input io.Reader) (io.Reader, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Once we acknowledge, failure must close the session, never fall back.
	c.Conn.SetWriteDeadline(time.Now().Add(shellUpgradeTimeout))
	_, err := c.Conn.Write(shellUpgradeAck(c.sid))
	c.Conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	session, err := smux.Server(&shellBufferedConn{Conn: c.Conn, r: input}, shellMuxConfig())
	if err != nil {
		return nil, err
	}
	c.session = session
	session.SetDeadline(time.Now().Add(shellUpgradeTimeout))
	shell, err := session.AcceptStream()
	if err != nil {
		session.Close()
		return nil, err
	}
	ctrl, err := session.AcceptStream()
	if err != nil {
		session.Close()
		return nil, err
	}
	session.SetDeadline(time.Time{})
	c.writer = shell
	c.control.Add(1)
	go func() {
		defer c.control.Done()
		defer ctrl.Close()
		// Control bytes never enter the PTY. Keep the existing resize encoding.
		_, _ = io.Copy(io.Discard, newPtyshResizeInputReader(ctrl, c.sid, c.resize))
	}()
	go serveShellFiles(session, c.recorder)
	return shell, nil
}

func (c *shellServerConn) Close() error {
	err := c.Conn.Close() // Unblock an in-flight write/upgrade before taking mu.
	c.mu.Lock()
	if c.session != nil {
		c.session.Close()
	}
	c.mu.Unlock()
	c.control.Wait()
	return err
}

type shellClientConn struct {
	net.Conn
	reader    io.Reader
	shell     *smux.Stream
	ctrl      *smux.Stream
	session   *smux.Session
	api       *shellLocalAPI
	closeOnce sync.Once
}

func (c *shellClientConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if err != nil {
		c.Close()
	}
	return n, err
}
func (c *shellClientConn) SetReadDeadline(t time.Time) error {
	if c.shell != nil {
		return c.shell.SetReadDeadline(t)
	}
	return c.Conn.SetReadDeadline(t)
}
func (c *shellClientConn) Write(p []byte) (int, error) {
	if c.shell != nil {
		return c.shell.Write(p)
	}
	return c.Conn.Write(p)
}
func (c *shellClientConn) CloseWrite() error {
	if c.shell != nil {
		return c.shell.CloseWrite()
	}
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
func (c *shellClientConn) Close() error {
	c.closeOnce.Do(func() {
		if c.api != nil {
			c.api.Close()
		}
		if c.session != nil {
			c.session.Close()
		}
		c.Conn.Close()
	})
	return nil
}

// Probe only the initial legacy announcement. Before an upgrade request a
// timeout/non-capability stream is a safe fallback, with every byte preserved.
// This also permits silent, non-PTY shells which need input before any output.
func newShellClientConn(conn net.Conn, notices io.Writer) (*shellClientConn, error) {
	c := &shellClientConn{Conn: conn}
	r := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	initial, caps := readShellCaps(r)
	conn.SetReadDeadline(time.Time{})
	c.reader = io.MultiReader(bytes.NewReader(initial), r)
	sid, validSID := decodePtyshSID(caps.SID)
	canUpgrade := false
	for _, capability := range caps.Caps {
		if capability == shellSessionCapability {
			canUpgrade = true
		}
	}
	if caps.V != 1 || !validSID || !ptyshCapsSupportResize(caps.Caps) || !canUpgrade {
		fmt.Fprintln(notices, "File API unavailable: peer did not advertise session.v2 (legacy or non-PTY shell).")
		return c, nil
	}
	conn.SetDeadline(time.Now().Add(shellUpgradeTimeout))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write(encodePtyshResize(sid, 0, 0)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("shell upgrade request: %w", err)
	}
	ack := shellUpgradeAck(sid)
	var beforeAck []byte
	for !bytes.HasSuffix(beforeAck, ack) {
		b, err := r.ReadByte()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("shell upgrade acknowledgement: %w", err)
		}
		beforeAck = append(beforeAck, b)
		if len(beforeAck) > 1024*1024 {
			conn.Close()
			return nil, fmt.Errorf("shell upgrade acknowledgement exceeded output limit")
		}
	}
	beforeAck = beforeAck[:len(beforeAck)-len(ack)]
	session, err := smux.Client(&shellBufferedConn{Conn: conn, r: r}, shellMuxConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}
	c.session = session
	c.shell, err = session.OpenStream()
	if err == nil {
		c.ctrl, err = session.OpenStream()
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	// Reuse the old capability filter and resize setup, including raw terminal
	// handling; resize writes are redirected to the dedicated control stream.
	c.reader = io.MultiReader(bytes.NewReader(initial), bytes.NewReader(beforeAck), c.shell)
	c.api, err = startShellLocalAPI(session)
	if err != nil {
		fmt.Fprintf(notices, "File API unavailable: %v\n", err)
	} else {
		printShellFileHints(notices, c.api.baseURL)
	}
	go func() {
		// The server sends no payload on this stream. Read it to notice a
		// disconnect even when terminal output is blocked in the caller.
		// Leave buffered shell output available for the normal read loop.
		_, _ = io.Copy(io.Discard, c.ctrl)
		if c.api != nil {
			c.api.Close()
		}
	}()
	return c, nil
}

func readShellCaps(r *bufio.Reader) ([]byte, ptyshCaps) {
	var raw []byte
	var caps ptyshCaps
	for i := 0; i < len(ptyshOSCPrefix)+ptyshOSCMaxPayload+1; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return raw, caps
		}
		raw = append(raw, b)
		if i < len(ptyshOSCPrefix) {
			if b != ptyshOSCPrefix[i] {
				return raw, caps
			}
		} else if b == '\a' {
			if json.Unmarshal(raw[len(ptyshOSCPrefix):len(raw)-1], &caps) != nil {
				caps = ptyshCaps{}
			}
			return raw, caps
		}
	}
	return raw, caps
}
