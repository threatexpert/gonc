package apps

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/threatexpert/gonc/v2/httpfileshare"
)

type RunOptions struct {
	P2PWithLANMode bool
	HTTPFileSource httpfileshare.FileSource
	ProgressSink   func(ProgressSnapshot)
}

// RunNetcat runs the gonc engine from library callers without going through
// main() or os.Args. It is intentionally thin so mobile integrations can first
// reuse the battle-tested CLI path, then replace internals module by module.
func RunNetcat(ctx context.Context, console net.Conn, logWriter io.Writer, args []string) int {
	return RunNetcatWithOptions(ctx, console, logWriter, args, RunOptions{})
}

func RunNetcatWithProgress(ctx context.Context, console net.Conn, logWriter io.Writer, args []string, progressSink func(ProgressSnapshot)) int {
	return RunNetcatWithOptions(ctx, console, logWriter, args, RunOptions{ProgressSink: progressSink})
}

func RunNetcatP2PWithHTTPFileSource(ctx context.Context, console net.Conn, logWriter io.Writer, args []string, source httpfileshare.FileSource) int {
	return RunNetcatWithOptions(ctx, console, logWriter, args, RunOptions{HTTPFileSource: source})
}

func RunNetcatP2PWithHTTPFileSourceAndProgress(ctx context.Context, console net.Conn, logWriter io.Writer, args []string, source httpfileshare.FileSource, progressSink func(ProgressSnapshot)) int {
	return RunNetcatWithOptions(ctx, console, logWriter, args, RunOptions{
		HTTPFileSource: source,
		ProgressSink:   progressSink,
	})
}

func RunNetcatWithOptions(ctx context.Context, console net.Conn, logWriter io.Writer, args []string, options RunOptions) int {
	if logWriter == nil {
		logWriter = io.Discard
	}
	code, err := RunNetcatWithOptionsE(ctx, console, logWriter, args, options)
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		if _, ok := AppExitCode(err); !ok {
			fmt.Fprintf(logWriter, "Error running gonc: %v\n", err)
		}
	}
	return code
}

func RunNetcatWithOptionsE(ctx context.Context, console net.Conn, logWriter io.Writer, args []string, options RunOptions) (int, error) {
	if console == nil {
		console = discardConn{}
	}

	config, err := PrepareNetcatConfigWithOptions(ctx, logWriter, args, options)
	if err != nil {
		if code, ok := AppExitCode(err); ok {
			return code, err
		}
		return 1, err
	}

	return RunPreparedNetcat(console, config), nil
}

func PrepareNetcatConfigWithOptions(ctx context.Context, logWriter io.Writer, args []string, options RunOptions) (*AppNetcatConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if logWriter == nil {
		logWriter = io.Discard
	}

	config, err := AppNetcatConfigByArgs(logWriter, "gonc", args)
	if err != nil {
		return nil, err
	}
	config.ctx = ctx
	config.ConsoleMode = false
	config.ProgressSink = options.ProgressSink
	if config.daemon {
		return nil, fmt.Errorf("daemon mode is not supported when embedded")
	}
	if options.P2PWithLANMode && config.useLAN {
		return nil, fmt.Errorf("error preparing P2P with LAN mode: -lan selects LAN-only mode")
	}
	config.p2pWithLanMode = options.P2PWithLANMode
	if options.HTTPFileSource != nil {
		if config.app_mux_Config == nil || config.app_mux_Config.AppMode != "httpserver" {
			return nil, fmt.Errorf("error preparing P2P HTTP file source: P2P httpserver mode is required")
		}
		config.app_mux_Config.HttpFileSource = options.HTTPFileSource
	}

	return config, nil
}

func RunPreparedNetcat(console net.Conn, config *AppNetcatConfig) int {
	if console == nil {
		console = discardConn{}
	}
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
