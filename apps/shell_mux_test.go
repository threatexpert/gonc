//go:build !gonc_noexec

package apps

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShellMuxEchoProcess(t *testing.T) {
	if os.Args[len(os.Args)-1] != "shell-mux-echo-helper" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "exit" {
			os.Exit(0)
		}
		fmt.Println("reply:" + line)
	}
	os.Exit(0)
}

// Exercise the actual outer mux dispatch, PTY shell upgrade and local HTTP API.
// A port listener gets a second shell after the first exits, proving that
// closing an inner session does not close the shared outer mux connection.
func TestShellShortcutOverMux(t *testing.T) {
	for _, engine := range []string{"smux", "yamux"} {
		for _, portMode := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/port=%t", engine, portMode), func(t *testing.T) {
				exe, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				previousEngine := VarmuxEngine
				t.Cleanup(func() { VarmuxEngine = previousEngine })
				shell := fmt.Sprintf(`-watch=false "%s" -test.run=^TestShellMuxEchoProcess$ -- shell-mux-echo-helper`, filepath.ToSlash(exe))
				agent, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{"-shellagent", "-:sh", shell, "-mux", "-mux-engine", engine, "-l", "1234"})
				if err != nil {
					t.Fatal(err)
				}
				localPort := "-"
				if portMode {
					localPort = "0"
				}
				client, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{"-shell", "-mux-l", localPort, "-mux-engine", engine, "-remote", "127.0.0.1:1234"})
				if err != nil {
					t.Fatal(err)
				}
				client.ConsoleMode = true
				var localListener net.Listener
				if portMode {
					localListener, err = net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer localListener.Close()
					client.muxLocalListener = localListener
				}

				// Hints intentionally use stderr rather than the configurable logger.
				// Drain it continuously so the full API instructions cannot block.
				hintsRead, hintsWrite, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				previousStderr := os.Stderr
				os.Stderr = hintsWrite
				apis := make(chan string, 8)
				hintsDone := make(chan struct{})
				go func() {
					defer close(hintsDone)
					scanner := bufio.NewScanner(hintsRead)
					for scanner.Scan() {
						if base, ok := strings.CutPrefix(scanner.Text(), "Base URL: "); ok {
							apis <- base
						}
					}
				}()
				defer func() {
					os.Stderr = previousStderr
					hintsWrite.Close()
					<-hintsDone
					hintsRead.Close()
				}()

				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				console, user := net.Pipe()
				defer console.Close()
				defer user.Close()
				agentDone, clientDone := make(chan int, 1), make(chan int, 1)
				go func() { agentDone <- handleSingleConnection(discardConn{}, agent, a) }()
				go func() {
					code := handleSingleConnection(console, client, b)
					console.Close()
					clientDone <- code
				}()
				defer func() {
					user.Close()
					console.Close()
					a.Close()
					b.Close()
					if localListener != nil {
						localListener.Close()
					}
					for _, done := range []chan int{clientDone, agentDone} {
						select {
						case <-done:
						case <-time.After(5 * time.Second):
							t.Error("outer mux did not stop")
						}
					}
					if client.ConsoleMode != !portMode {
						t.Errorf("local console mode=%t, want %t", client.ConsoleMode, !portMode)
					}
				}()

				transport := &http.Transport{DisableKeepAlives: true}
				defer transport.CloseIdleConnections()
				hc := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				var previousBase string
				count := 1
				if portMode {
					count = 2
				}
				for i := 0; i < count; i++ {
					terminal := net.Conn(user)
					if portMode {
						terminal, err = net.DialTimeout("tcp4", localListener.Addr().String(), time.Second)
						if err != nil {
							t.Fatal(err)
						}
						defer terminal.Close()
					}
					terminal.SetDeadline(time.Now().Add(15 * time.Second))
					lines := make(chan string, 32)
					go func() {
						defer close(lines)
						r := bufio.NewReader(terminal)
						for {
							line, err := r.ReadString('\n')
							if line != "" {
								lines <- line
							}
							if err != nil {
								return
							}
						}
					}()
					var base string
					select {
					case base = <-apis:
					case <-time.After(10 * time.Second):
						t.Fatal("nested shell did not expose file API")
					}
					if base == previousBase {
						t.Fatal("new shell reused a closed file API")
					}
					previousBase = base
					path := filepath.Join(t.TempDir(), "mux file.bin")
					payload := bytes.Repeat([]byte{0, 255, '\x1b', '\r', '\n', 'g'}, 200000)
					pr, pw := io.Pipe()
					defer pr.Close()
					defer pw.Close()
					req, _ := http.NewRequest(http.MethodPut, testFileURL(base, path), pr)
					uploadDone := make(chan error, 1)
					go func() {
						resp, err := hc.Do(req)
						if err == nil {
							body, _ := io.ReadAll(resp.Body)
							resp.Body.Close()
							if resp.StatusCode != http.StatusCreated {
								err = fmt.Errorf("upload: %d %s", resp.StatusCode, body)
							}
						}
						uploadDone <- err
					}()
					if _, err := pw.Write(payload[:1024]); err != nil {
						t.Fatal(err)
					}
					if _, err := io.WriteString(terminal, "mux-alive\r\n"); err != nil {
						t.Fatal(err)
					}
					var output strings.Builder
					waitReply := time.NewTimer(5 * time.Second)
					for !strings.Contains(output.String(), "reply:mux-alive") {
						select {
						case line, ok := <-lines:
							if !ok {
								t.Fatalf("shell closed before reply: %q", output.String())
							}
							output.WriteString(line)
						case <-waitReply.C:
							t.Fatalf("terminal stalled during file upload: %q", output.String())
						}
					}
					waitReply.Stop()
					if strings.Contains(output.String(), ptyshOSCPrefix) {
						t.Fatal("capability bytes leaked to terminal")
					}
					if _, err := pw.Write(payload[1024:]); err != nil {
						t.Fatal(err)
					}
					pw.Close()
					if err := <-uploadDone; err != nil {
						t.Fatal(err)
					}
					resp, err := hc.Get(testFileURL(base, path))
					if err != nil {
						t.Fatal(err)
					}
					data, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil || resp.StatusCode != 200 || !bytes.Equal(data, payload) {
						t.Fatalf("nested file download: status=%d bytes=%d err=%v", resp.StatusCode, len(data), err)
					}
					if _, err := io.WriteString(terminal, "exit\r\n"); err != nil {
						t.Fatal(err)
					}
					closed := time.NewTimer(7 * time.Second)
				drain:
					for {
						select {
						case _, ok := <-lines:
							if !ok {
								break drain
							}
						case <-closed.C:
							t.Fatal("shell stream did not close after exit")
						}
					}
					closed.Stop()
					terminal.Close()
					if resp, err := hc.Get(base + "info"); err == nil {
						resp.Body.Close()
						t.Fatal("file API survived shell exit")
					}
				}
			})
		}
	}
}
