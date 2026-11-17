package apps

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestShellRecordingOptions(t *testing.T) {
	c, err := PtyShellConfigByArgs(io.Discard, []string{"-watch", "-record", "my logs", "custom-shell", "-x"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Watch || c.RecordDir != "my logs" || strings.Join(c.Args, " ") != "custom-shell -x" {
		t.Fatalf("config = %+v", c)
	}
	c, err = PtyShellConfigByArgs(io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := newShellRecorder(c, "peer")
	if err != nil || r != nil {
		t.Fatalf("recording enabled by default: %v, %v", r, err)
	}
}

func testShellRecorder(w io.Writer, capacity int) *shellRecorder {
	return &shellRecorder{id: "id-0", watch: w, events: make(chan shellRecordEvent, capacity), done: make(chan struct{})}
}

func TestShellRecordingReadableAndFlushed(t *testing.T) {
	var log bytes.Buffer
	r := testShellRecorder(&log, 128)
	// Enqueue first to make the fragmented Unicode test independent of timers.
	r.add("IN", []byte("p"))
	r.add("IN", []byte("wd\r"))
	unicode := []byte("你好")
	r.add("OUT", unicode[:2])
	r.add("OUT", append(unicode[2:], []byte("\r\n\x1b[2J\b\x03\xff\\x03")...))
	go r.run()
	r.close("session ended")
	text := log.String()
	for _, want := range []string{"[id-0 IN  ] pwd\\r", "你好\\r\\n", "\\x1b[2J\\b\\x03\\xff\\\\x03", "session ended"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
	if strings.ContainsAny(text, "\x1b\r\b\x03") {
		t.Fatalf("unescaped terminal controls: %q", text)
	}
}

type shellLineChannel chan string

func (c shellLineChannel) Write(p []byte) (int, error) {
	c <- string(p)
	return len(p), nil
}

func TestShellRecordingPromptFlushesWithoutNewline(t *testing.T) {
	lines := make(shellLineChannel, 4)
	r := testShellRecorder(lines, 128)
	go r.run()
	defer r.close("ended")
	r.add("OUT", []byte("prompt> "))
	select {
	case line := <-lines:
		if !strings.Contains(line, "prompt> ") {
			t.Fatalf("line = %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prompt was not flushed")
	}
}

func TestShellRecordingOverflowReportsGap(t *testing.T) {
	var log bytes.Buffer
	r := testShellRecorder(&log, 1)
	r.add("IN", []byte("kept"))
	r.add("OUT", []byte("lost"))
	go r.run()
	r.close("ended")
	if !strings.Contains(log.String(), "GAP") || !strings.Contains(log.String(), "4 bytes omitted") || !strings.Contains(log.String(), "kept") {
		t.Fatalf("log = %q", log.String())
	}
}

type brokenShellLog struct{ closed bool }

func (*brokenShellLog) Write([]byte) (int, error) { return 0, errors.New("disk full") }
func (w *brokenShellLog) Close() error            { w.closed = true; return nil }

func TestShellRecordingFailureDoesNotBreakForwarding(t *testing.T) {
	var log, delivered bytes.Buffer
	r := testShellRecorder(&log, 128)
	f := &brokenShellLog{}
	r.file = f
	go r.run()
	w := shellRecordWriter{w: &delivered, r: r, dir: "IN"}
	if _, err := io.WriteString(w, "command\r"); err != nil {
		t.Fatal(err)
	}
	r.close("ended")
	if delivered.String() != "command\r" || !f.closed || !strings.Contains(log.String(), "command\\r") {
		t.Fatalf("delivered=%q, closed=%t, log=%q", delivered.String(), f.closed, log.String())
	}
}

func TestShellRecordingSeparateSessions(t *testing.T) {
	dir := t.TempDir()
	c := &PtyShellConfig{RecordDir: dir}
	a, err := newShellRecorder(c, "peer-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := newShellRecorder(c, "peer-b")
	if err != nil {
		a.close("ended")
		t.Fatal(err)
	}
	a.add("IN", []byte("only-a"))
	b.add("IN", []byte("only-b"))
	a.close("ended")
	b.close("ended")
	id, err := strconv.ParseUint(strings.TrimPrefix(a.id, "id-"), 10, 64)
	if err != nil || b.id != fmt.Sprintf("id-%d", id+1) {
		t.Fatalf("session IDs are not sequential: %q, %q", a.id, b.id)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.log"))
	if err != nil || len(files) != 2 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "only-a") == strings.Contains(string(data), "only-b") {
			t.Fatalf("sessions mixed: %s", data)
		}
	}
}

// Runs in a child test executable, avoiding platform-specific shell syntax.
func TestShellRecordProcess(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "shell-record-helper" {
		return
	}
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "stderr-marker")
	if os.Args[len(os.Args)-1] == "pipe" {
		fmt.Fprint(os.Stdout, strings.Repeat("final-output\n", 8192))
	}
	fmt.Fprint(os.Stdout, "final-marker-你好\n")
	os.Exit(0)
}

func TestShellRecordingSession(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pty, merge bool
	}{
		{"pipe-separate-stderr", false, false},
		{"pipe-merged-stderr", false, true},
		{"pty", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			mode := "pipe"
			if tc.pty {
				mode = "pty"
			}
			dir := t.TempDir()
			c := &PtyShellConfig{
				Logger: log.New(io.Discard, "", 0), EnablePty: tc.pty, MergeStderr: tc.merge,
				RecordDir: dir, Args: []string{exe, "-test.run=^TestShellRecordProcess$", "--", "shell-record-helper", mode},
			}
			server, client := net.Pipe()
			defer client.Close()
			client.SetDeadline(time.Now().Add(15 * time.Second))
			done := make(chan struct{})
			go func() { defer close(done); App_shell_main_withconfig(server, c) }()
			output := make(chan []byte, 1)
			go func() { data, _ := io.ReadAll(client); output <- data }()
			if _, err := client.Write([]byte("test-command\r\n")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("session did not terminate")
			}
			data := <-output
			if !bytes.Contains(data, []byte("final-marker-你好")) {
				t.Fatalf("missing final output: %q", data)
			}
			files, _ := filepath.Glob(filepath.Join(dir, "*.log"))
			if len(files) != 1 {
				t.Fatalf("files=%v", files)
			}
			contents, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"test-command", "stderr-marker", "final-marker-你好", "session ended", "wait=<nil>"} {
				if !bytes.Contains(contents, []byte(want)) {
					t.Fatalf("missing %q in log (%d bytes)", want, len(contents))
				}
			}
			if !tc.pty {
				var recorded bytes.Buffer
				for _, line := range strings.Split(string(contents), "\n") {
					_, payload, ok := strings.Cut(line, " OUT ] ")
					if !ok {
						continue
					}
					decoded, err := strconv.Unquote("\"" + payload + "\"")
					if err != nil {
						t.Fatal(err)
					}
					recorded.WriteString(decoded)
				}
				if !bytes.Equal(recorded.Bytes(), data) || bytes.Count(data, []byte("final-output")) != 8192 {
					t.Fatalf("final output truncated: delivered=%d recorded=%d lines=%d", len(data), recorded.Len(), bytes.Count(data, []byte("final-output")))
				}
			}
		})
	}
}

func TestShellRecordingExcludesResizeFrames(t *testing.T) {
	var log, delivered bytes.Buffer
	r := testShellRecorder(&log, 128)
	go r.run()
	sid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	data := append([]byte("before"), encodePtyshResize(sid, 40, 120)...)
	data = append(data, []byte("after")...)
	reader := newPtyshResizeInputReader(bytes.NewReader(data), sid, func(rows, cols int) {
		r.add("SIZE", []byte(fmt.Sprintf("rows=%d cols=%d", rows, cols)))
	})
	_, err := io.Copy(shellRecordWriter{w: &delivered, r: r, dir: "IN"}, reader)
	r.close("ended")
	if err != nil || delivered.String() != "beforeafter" {
		t.Fatalf("delivered=%q err=%v", delivered.String(), err)
	}
	if !strings.Contains(log.String(), "rows=40 cols=120") || !strings.Contains(log.String(), "beforeafter") || strings.Contains(log.String(), "\\xff") {
		t.Fatalf("log=%q", log.String())
	}
}
