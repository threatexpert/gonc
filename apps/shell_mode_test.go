//go:build !gonc_noexec

package apps

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestShellShortcutDefaults(t *testing.T) {
	for _, p2p := range []bool{false, true} {
		for _, agent := range []bool{false, true} {
			t.Run(fmt.Sprintf("p2p=%t/agent=%t", p2p, agent), func(t *testing.T) {
				mode := "-shell"
				if agent {
					mode = "-shellagent"
				}
				args := []string{mode}
				if p2p {
					args = append(args, "-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z")
				} else if agent {
					args = append(args, "-l", "1234")
				} else {
					args = append(args, "-remote", "127.0.0.1:1234")
				}
				c, err := AppNetcatConfigByArgs(io.Discard, "gonc", args)
				if err != nil {
					t.Fatal(err)
				}
				if c.keepOpen != agent || c.enablePty == agent || c.remoteCall != "" ||
					c.useMQTTWait != (p2p && agent) || c.useMQTTHello != (p2p && !agent) {
					t.Fatalf("unexpected defaults: keep=%t pty=%t call=%q wait=%t hello=%t", c.keepOpen, c.enablePty, c.remoteCall, c.useMQTTWait, c.useMQTTHello)
				}
				if agent {
					if c.runCmd != ":sh -watch" || c.app_sh_Config == nil || !c.app_sh_Config.EnablePty || !c.app_sh_Config.Watch {
						t.Fatalf("agent did not initialize a direct PTY shell: %q", c.runCmd)
					}
				} else if c.runCmd != "" || c.app_sh_Config != nil || shouldRetryPersistentDial(c) {
					t.Fatal("client should only connect, without running a local shell or automatically reconnecting")
				}
			})
		}
	}
}

func TestShellShortcutHonorsShellOptions(t *testing.T) {
	for _, keepFlag := range []string{"-k=false", "-keep-open=false"} {
		c, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
			"-shellagent", "-:sh", `-pty=false -stderr=false -watch=false -record "my logs" "custom shell" -x`, keepFlag, "-l", "1234",
		})
		if err != nil {
			t.Fatal(err)
		}
		sh := c.app_sh_Config
		if !c.keepOpen || sh == nil || sh.EnablePty || sh.MergeStderr || sh.Watch || sh.RecordDir != "my logs" ||
			!reflect.DeepEqual(sh.Args, []string{"custom shell", "-x"}) {
			t.Fatalf("shell options were not preserved: %+v", sh)
		}
	}
}

func TestShellShortcutForcesPresets(t *testing.T) {
	for _, args := range [][]string{
		{"-shell", "-pty=false", "-H=false"},
		{"-pty=false", "-mqtt-hello=false", "-shell"},
		{"-shellagent", "-W=false"},
		{"-mqtt-wait=false", "-shellagent"},
		{"-shellagent", "-:sh", "-"},
		{"-shell", "-:sh", "-"},
	} {
		c, err := AppNetcatConfigByArgs(io.Discard, "gonc", append(args, "-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z"))
		if err != nil {
			t.Fatal(err)
		}
		if c.enablePty != c.shellClient || c.useMQTTWait != c.shellAgent || c.useMQTTHello != c.shellClient || c.keepOpen != c.shellAgent {
			t.Fatalf("shell presets not applied for %v: pty=%t wait=%t hello=%t keep=%t", args, c.enablePty, c.useMQTTWait, c.useMQTTHello, c.keepOpen)
		}
	}
}

func TestShellShortcutLogDefaultsFollowAppMode(t *testing.T) {
	for _, tc := range []struct {
		args     []string
		wantTime bool
	}{
		{[]string{"-shellagent"}, true},
		{[]string{"-shellagent", "-k=false"}, true},
		{[]string{"-shellagent", "-keep-open=false"}, true},
		{[]string{"-shellagent", "-k=false", "-keep-open=true"}, true},
		{[]string{"-shellagent", "-keep-open=true", "-k=false"}, true},
		{[]string{"-shellagent", "-v=false"}, false},
		{[]string{"-shell"}, false},
		{[]string{"-shell", "-k"}, true},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var output bytes.Buffer
			c, err := AppNetcatConfigByArgs(&output, "gonc", append(tc.args, "-remote", "127.0.0.1:1234"))
			if err != nil {
				t.Fatal(err)
			}
			if c.verboseWithTime != tc.wantTime {
				t.Fatalf("log timestamps: config=%t, want %t", c.verboseWithTime, tc.wantTime)
			}
			output.Reset()
			c.Logger.Print("shell-log-probe")
			line := output.String()
			if tc.wantTime {
				stamp, rest, _ := strings.Cut(line, " ")
				if _, err := time.Parse("20060102-150405", stamp); err != nil || rest != "[gonc] shell-log-probe\n" {
					t.Fatalf("expected timestamp and application prefix, got %q", line)
				}
			} else if c.verbose && line != "shell-log-probe\n" || !c.verbose && line != "" {
				t.Fatalf("unexpected plain or disabled log output: %q", line)
			}
		})
	}
}

func TestShellShortcutInitializationErrorLogDefaults(t *testing.T) {
	for _, keepFlag := range []string{"", "-k=false", "-keep-open=false"} {
		t.Run(fmt.Sprintf("flag=%s", keepFlag), func(t *testing.T) {
			args := []string{"-shellagent", "-:sh", "-unknown-shell-option", "-remote", "127.0.0.1:1234"}
			if keepFlag != "" {
				args = append(args, keepFlag)
			}
			var output bytes.Buffer
			_, err := AppNetcatConfigByArgs(&output, "gonc", args)
			if err == nil || !strings.Contains(err.Error(), "unknown-shell-option") {
				t.Fatalf("expected shell initialization error, got %v", err)
			}
			if !strings.Contains(output.String(), "[gonc]") {
				t.Fatalf("missing initialization log prefix: %s", output.String())
			}
		})
	}
}

func TestShellShortcutRejectsConflicts(t *testing.T) {
	for _, mode := range []string{"-shellagent", "-shell"} {
		for _, tc := range []struct {
			args []string
			want string
		}{
			{[]string{"-shellagent", "-shell"}, "-shellagent and -shell"},
			{[]string{"-e", ":sh"}, "app modes"},
			{[]string{"-exec", ":service"}, "app modes"},
			{[]string{"-call", ":sh"}, "-call"},
			{[]string{"-nat-checker"}, "-nat-checker"},
			{[]string{"-http-download"}, "-http-download"},
			{[]string{"-speedtest", "1s"}, "-speedtest"},
		} {
			t.Run(mode+" "+strings.Join(tc.args, " "), func(t *testing.T) {
				var output bytes.Buffer
				args := append([]string{mode, "-remote", "127.0.0.1:1234"}, tc.args...)
				_, err := AppNetcatConfigByArgs(&output, "gonc", args)
				if err == nil || !strings.Contains(err.Error()+output.String(), tc.want) {
					t.Fatalf("expected conflict mentioning %s, got %v; logs: %s", tc.want, err, output.String())
				}
			})
		}
	}
	if _, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{"-shell", "-:sh", "", "-remote", "127.0.0.1:1234"}); err == nil {
		t.Fatal("client accepted provider shell options")
	}
}

func TestShellShortcutUsesAppModePrecedence(t *testing.T) {
	for _, mode := range []string{"-shellagent", "-shell"} {
		for _, extra := range [][]string{
			{"-linkagent"}, {"-link", "1080"}, {"-httpserver", "."},
			{"-download", "."}, {"-socks5server"}, {"-browser"}, {"-httplocal-port", "0"},
			{"-:s5s", ""}, {"-:nc", "127.0.0.1 80"}, {"-:httpserver", "."}, {"-:mux", "socks5"},
			{"-z"},
			{"-mux"}, {"-mux-l", "-"}, {"-mux-l", "0"},
		} {
			t.Run(mode+" "+strings.Join(extra, " "), func(t *testing.T) {
				args := append([]string{mode, "-remote", "127.0.0.1:1234"}, extra...)
				c, err := AppNetcatConfigByArgs(io.Discard, "gonc", args)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "-shellagent" {
					if c.runCmd != ":sh -watch" || c.app_sh_Config == nil {
						t.Fatalf("shell provider was replaced: %q", c.runCmd)
					}
				} else if c.runCmd != "" || !c.shellClient {
					t.Fatalf("shell client was replaced: %q", c.runCmd)
				}
				if extra[0] == "-z" && !c.scanOnly {
					t.Fatal("scan-only flag was lost")
				}
			})
		}
	}
}

func TestShellShortcutProcess(t *testing.T) {
	if os.Args[len(os.Args)-1] != "shell-shortcut-helper" {
		return
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "shortcut-input" {
		os.Exit(2)
	}
	fmt.Println("shortcut-output")
	os.Exit(0)
}

// Exercise both shortcuts through the normal connection handlers. The child
// rejects any injected service selector before the actual user input.
func TestShellShortcutDirectSession(t *testing.T) {
	for _, mode := range []struct{ serverPty, clientPty bool }{{false, true}, {true, true}, {true, false}} {
		t.Run(fmt.Sprintf("serverPTY=%t/requestedClientPTY=%t", mode.serverPty, mode.clientPty), func(t *testing.T) {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			shell := fmt.Sprintf(`-pty=%t "%s" -test.run=^TestShellShortcutProcess$ -- shell-shortcut-helper`, mode.serverPty, filepath.ToSlash(exe))
			agent, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{"-shellagent", "-:sh", shell, "-l", "1234"})
			if err != nil {
				t.Fatal(err)
			}
			client, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{"-shell", fmt.Sprintf("-pty=%t", mode.clientPty), "-remote", "127.0.0.1:1234"})
			if err != nil {
				t.Fatal(err)
			}
			a, b := net.Pipe()
			console, user := net.Pipe()
			defer a.Close()
			defer b.Close()
			defer console.Close()
			defer user.Close()
			deadline := time.Now().Add(15 * time.Second)
			a.SetDeadline(deadline)
			b.SetDeadline(deadline)
			user.SetDeadline(deadline)
			done := make(chan int, 2)
			go func() { done <- handleSingleConnection(discardConn{}, agent, a) }()
			go func() {
				code := handleSingleConnection(console, client, b)
				console.Close()
				done <- code
			}()
			output := make(chan []byte, 1)
			go func() { data, _ := io.ReadAll(user); output <- data }()
			if _, err := user.Write([]byte("shortcut-input\r\n")); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				select {
				case code := <-done:
					if code != 0 {
						t.Fatalf("connection handler returned %d", code)
					}
				case <-time.After(20 * time.Second):
					t.Fatal("shell session did not exit")
				}
			}
			data := string(<-output)
			if !strings.Contains(data, "shortcut-output") || strings.Contains(data, ptyshOSCPrefix) {
				t.Fatalf("unexpected shell output: %q", data)
			}
		})
	}
}
