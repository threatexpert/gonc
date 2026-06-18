package apps

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"time"
)

// RunNetcat runs the gonc engine from library callers without going through
// main() or os.Args. It is intentionally thin so mobile integrations can first
// reuse the battle-tested CLI path, then replace internals module by module.
func RunNetcat(ctx context.Context, console net.Conn, logWriter io.Writer, args []string) int {
	if ctx == nil {
		ctx = context.Background()
	}
	if logWriter == nil {
		logWriter = io.Discard
	}
	if console == nil {
		console = discardConn{}
	}

	config, err := AppNetcatConfigByArgs(logWriter, "gonc", args)
	if err != nil {
		if err != flag.ErrHelp {
			fmt.Fprintf(logWriter, "Error parsing gonc args: %v\n", err)
		}
		return 1
	}
	config.ctx = ctx
	config.ConsoleMode = false

	return App_Netcat_main_withconfig(console, config)
}

type discardConn struct{}

func (discardConn) Read(p []byte) (int, error)         { return 0, io.EOF }
func (discardConn) Write(p []byte) (int, error)        { return len(p), nil }
func (discardConn) Close() error                       { return nil }
func (discardConn) LocalAddr() net.Addr                { return dummyAddr("mobile") }
func (discardConn) RemoteAddr() net.Addr               { return dummyAddr("mobile") }
func (discardConn) SetDeadline(t time.Time) error      { return nil }
func (discardConn) SetReadDeadline(t time.Time) error  { return nil }
func (discardConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }
