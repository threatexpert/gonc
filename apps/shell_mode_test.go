package apps

import (
	"bufio"
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

func TestShellShortcutHonorsExplicitOptions(t *testing.T) {
	for _, keepFlag := range []string{"-k=false", "-keep-open=false"} {
		c, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
			"-shellagent", "-:sh", `-pty=false -stderr=false -watch=false -record "my logs" "custom shell" -x`, keepFlag, "-l", "1234",
		})
		if err != nil {
			t.Fatal(err)
		}
		sh := c.app_sh_Config
		if c.keepOpen || sh == nil || sh.EnablePty || sh.MergeStderr || sh.Watch || sh.RecordDir != "my logs" ||
			!reflect.DeepEqual(sh.Args, []string{"custom shell", "-x"}) {
			t.Fatalf("shell options were not preserved: %+v", sh)
		}
	}
	for _, args := range [][]string{
		{"-shell", "-pty=false", "-H=false"},
		{"-pty=false", "-mqtt-hello=false", "-shell"},
		{"-shellagent", "-W=false"},
	} {
		c, err := AppNetcatConfigByArgs(io.Discard, "gonc", append(args, "-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z"))
		if err != nil {
			t.Fatal(err)
		}
		if c.enablePty || c.useMQTTWait || c.useMQTTHello {
			t.Fatalf("explicit false was ignored for %v", args)
		}
	}
}

func TestShellShortcutRejectsConflicts(t *testing.T) {
	for _, args := range [][]string{
		{"-shellagent", "-shell"},
		{"-shellagent", "-e", ":sh"},
		{"-shell", "-exec", ":service"},
		{"-shell", "-call", ":sh"},
		{"-shellagent", "-call", ":sh"},
		{"-shellagent", "-:sh", "-"},
		{"-shell", "-:sh", ""},
		{"-shellagent", "-:s5s", ""},
		{"-shell", "-linkagent"},
		{"-shellagent", "-link", "1080"},
		{"-shellagent", "-httpserver", "."},
		{"-shell", "-browser"},
		{"-shell", "-mux"},
		{"-shellagent", "-nat-checker"},
		{"-shell", "-speedtest", "1s"},
		{"-shellagent", "-z"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			_, err := AppNetcatConfigByArgs(io.Discard, "gonc", append(args, "-remote", "127.0.0.1:1234"))
			if err == nil || !strings.Contains(err.Error(), "-shell") {
				t.Fatalf("expected a shell mode conflict, got %v", err)
			}
		})
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
		t.Run(fmt.Sprintf("serverPTY=%t/clientPTY=%t", mode.serverPty, mode.clientPty), func(t *testing.T) {
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
