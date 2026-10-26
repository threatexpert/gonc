package apps

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type relayFallbackProgressWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

type relayPreparationDialer struct {
	Dialer
	dial func(time.Duration) (net.Conn, error)
}

func (d *relayPreparationDialer) DialTimeout(_, _ string, timeout time.Duration) (net.Conn, error) {
	return d.dial(timeout)
}

func TestP2PRelayInitializationLogsBeforeDialAndSelectsTimeout(t *testing.T) {
	for _, flag := range []string{"-x", "-x2"} {
		t.Run(flag, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			output := &relayFallbackProgressWriter{cancel: cancel}
			config, err := AppNetcatConfigByArgs(output, "gonc", []string{
				"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z", "-u", flag, "127.0.0.1:1080",
			})
			if err != nil {
				t.Fatal(err)
			}
			config.ctx = ctx
			wantTimeout := 20 * time.Second
			wantLog := "Initializing SOCKS5 relay (-x) connection to 127.0.0.1:1080 (timeout: 20s)..."
			if flag == "-x2" {
				wantTimeout = 15 * time.Second
				wantLog = "Initializing fallback relay (-x2) connection to 127.0.0.1:1080 (timeout: 15s)..."
			}
			called := false
			config.arg_proxyc_Config.UpstreamDialer = &relayPreparationDialer{dial: func(timeout time.Duration) (net.Conn, error) {
				called = true
				if timeout != wantTimeout {
					t.Errorf("dial timeout = %s, want %s", timeout, wantTimeout)
				}
				if !strings.Contains(output.String(), wantLog) {
					t.Errorf("initialization was not logged before dialing: %q", output.String())
				}
				return nil, context.DeadlineExceeded
			}}
			conn, err := do_P2P(config)
			if conn != nil {
				_ = conn.Close()
				t.Fatal("unexpected established connection")
			}
			if !called || err == nil {
				t.Fatalf("dial called=%v err=%v", called, err)
			}
			if flag == "-x2" && !errors.Is(err, context.Canceled) {
				t.Fatalf("timed out fallback did not continue to direct P2P: %v", err)
			}
		})
	}
}

func (w *relayFallbackProgressWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if bytes.Contains(p, []byte("=== Checking NAT reachability ===")) {
		// Stop at the direct P2P entry point, before contacting public brokers
		// or STUN servers. Reaching it proves proxy failure was nonfatal.
		w.cancel()
	}
	return n, err
}

func TestP2PRelayPreparationFailure(t *testing.T) {
	for _, rejection := range []string{"authentication", "udp-associate"} {
		for _, flag := range []string{"-x", "-x2"} {
			t.Run(rejection+"/"+flag, func(t *testing.T) {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
				proxyDone := make(chan error, 1)
				go func() {
					proxyDone <- func() error {
						conn, err := listener.Accept()
						if err != nil {
							return err
						}
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
						var greeting [2]byte
						if _, err := io.ReadFull(conn, greeting[:]); err != nil {
							return err
						}
						if _, err := io.CopyN(io.Discard, conn, int64(greeting[1])); err != nil {
							return err
						}
						if rejection == "authentication" {
							_, err := conn.Write([]byte{5, 0xff})
							return err
						}
						if _, err := conn.Write([]byte{5, 0}); err != nil {
							return err
						}
						var request [10]byte // UDP ASSOCIATE for 0.0.0.0:0
						if _, err := io.ReadFull(conn, request[:]); err != nil {
							return err
						}
						if !bytes.Equal(request[:4], []byte{5, 3, 0, 1}) {
							return errors.New("expected SOCKS5 UDP ASSOCIATE request")
						}
						_, err = conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}) // Command not supported.
						return err
					}()
				}()

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				output := &relayFallbackProgressWriter{cancel: cancel}
				config, err := AppNetcatConfigByArgs(output, "gonc", []string{
					"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z", "-u", flag, listener.Addr().String(),
				})
				if err != nil {
					t.Fatal(err)
				}
				config.ctx = ctx
				conn, err := do_P2P(config)
				if conn != nil {
					_ = conn.Close()
					t.Fatal("unexpected established connection")
				}
				if proxyErr := <-proxyDone; proxyErr != nil {
					t.Fatalf("mock proxy: %v", proxyErr)
				}
				reachedP2P := strings.Contains(output.String(), "=== Checking NAT reachability ===")
				warned := strings.Contains(output.String(), "Fallback relay unavailable (-x2):")
				if flag == "-x2" {
					if !reachedP2P || !warned || !errors.Is(err, context.Canceled) {
						t.Fatalf("fallback did not warn and continue to direct P2P: err=%v log=%q", err, output.String())
					}
				} else if reachedP2P || warned || err == nil || !strings.Contains(err.Error(), "prepare socks5 UDP client failed:") {
					t.Fatalf("required proxy failure did not remain fatal: err=%v log=%q", err, output.String())
				}
			})
		}
	}
}
