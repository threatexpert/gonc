package apps

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/threatexpert/gonc/v2/misc"
)

type PtyShell struct {
	config *PtyShellConfig
}

// NewPtyShell 构造函数
func NewPtyShell(config *PtyShellConfig) (*PtyShell, error) {
	sh := &PtyShell{config: config}
	return sh, nil
}

type PtyShellConfig struct {
	Logger                 *log.Logger
	EnablePty, MergeStderr bool
	Args                   []string
	Watch                  bool
	RecordDir              string
}

// PtyShellConfigByArgs 从命令行参数构造 config
func PtyShellConfigByArgs(logWriter io.Writer, args []string) (*PtyShellConfig, error) {
	// 👇 根据操作系统决定默认 Shell
	var defaultShell []string
	if runtime.GOOS == "windows" {
		// Windows 下通常用 COMSPEC 环境变量，它指向 cmd.exe 的绝对路径
		// 如果找不到环境变量，回退到 "cmd.exe"
		cmdPath := os.Getenv("COMSPEC")
		if cmdPath == "" {
			cmdPath = "cmd.exe"
		}
		defaultShell = []string{cmdPath}
	} else {
		// Linux/Mac 下尝试获取 SHELL 环境变量（比如 /bin/zsh）
		// 如果找不到，回退到 "/bin/sh"
		shPath := os.Getenv("SHELL")
		if shPath == "" {
			shPath = "/bin/sh"
		}
		defaultShell = []string{shPath}
	}
	config := &PtyShellConfig{
		Logger: misc.NewLog(logWriter, "[:sh] ", log.LstdFlags|log.Lmsgprefix),
		Args:   defaultShell,
	}

	fs := flag.NewFlagSet("PtyShellConfig", flag.ContinueOnError)
	fs.SetOutput(logWriter)

	fs.BoolVar(&config.EnablePty, "pty", true, "")
	fs.BoolVar(&config.MergeStderr, "stderr", true, "Merge stderr into stdout")
	fs.BoolVar(&config.Watch, "watch", false, "Show shell input/output locally on stderr")
	fs.StringVar(&config.RecordDir, "record", "", "Save a readable .log per shell session in this directory")

	fs.Usage = func() {
		PtyShell_usage_flagSet(fs)
	}

	err := fs.Parse(args)
	if err != nil {
		return nil, err
	}

	remainingArgs := fs.Args()
	if len(remainingArgs) > 0 {
		config.Args = remainingArgs
	}

	return config, nil
}

func PtyShell_usage_flagSet(fs *flag.FlagSet) {
	fmt.Fprintln(fs.Output(), ":sh Usage: [options] shell-path <args>")
	fmt.Fprintln(fs.Output(), "Options:")
	fs.PrintDefaults()
	fmt.Fprintln(fs.Output(), "")
	fmt.Fprintln(fs.Output(), "Examples:")
	fmt.Fprintln(fs.Output(), "  :sh /bin/bash")
	fmt.Fprintln(fs.Output(), "  :sh -watch -record ./shell-records /bin/bash")
}

// App_shell_main_withconfig 启动 shell 并绑定到 conn
func App_shell_main_withconfig(conn net.Conn, config *PtyShellConfig) {
	defer conn.Close()

	config.Logger.Printf("Starting shell: %v for %s\n", config.Args, conn.RemoteAddr())
	recorder, err := newShellRecorder(config, conn.RemoteAddr().String())
	if err != nil {
		config.Logger.Printf("Cannot start shell recording: %v\n", err)
		fmt.Fprintf(conn, "Cannot start shell recording: %v\n", err)
		return
	}
	end := "session ended before shell started"
	defer func() { recorder.close(end) }()

	var proc misc.PtyProcess
	var input io.ReadCloser
	var output io.WriteCloser
	var ptyIO misc.ResizablePty
	var ptyshSID []byte

	if config.EnablePty {
		cmd, ptmx, err := misc.PtyStart(config.Args[0], config.Args[1:]...)
		if err != nil {
			end = fmt.Sprintf("pty start failed: %v", err)
			conn.Write([]byte(fmt.Sprintf("Failed to start pty: %v\n", err)))
			return
		}
		proc = cmd
		ptyIO = ptmx
		input = ptmx
		output = ptmx
		sid, sidHex, err := newPtyshSID()
		if err == nil {
			if caps, err := encodePtyshCaps(sidHex); err == nil {
				if _, err := conn.Write(caps); err == nil {
					ptyshSID = sid
				}
			}
		}
	} else {
		cmd := exec.Command(config.Args[0], config.Args[1:]...)
		// 创建管道
		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("Error creating stdin pipe: %v\n", err)))
			return
		}

		// Own the output pipe so cmd.Wait cannot close it before we drain it.
		stdoutPipe, stdoutWrite, err := os.Pipe()
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("Error creating stdout pipe: %v\n", err)))
			stdinPipe.Close()
			if pr, ok := cmd.Stdin.(*os.File); ok {
				pr.Close()
			}
			return
		}
		defer stdoutPipe.Close()
		defer stdoutWrite.Close()
		cmd.Stdout = stdoutWrite

		if config.MergeStderr {
			cmd.Stderr = cmd.Stdout
		} else {
			cmd.Stderr = os.Stderr
			if recorder != nil {
				cmd.Stderr = shellRecordWriter{w: os.Stderr, r: recorder, dir: "ERR"}
			}
		}

		proc = &misc.StdProcess{Cmd: cmd}
		input = stdoutPipe
		output = stdinPipe

		// 启动命令
		if err := cmd.Start(); err != nil {
			// 不处理关闭pipe，cmd.Start失败时，Start里面会closeDescriptors把创建的pipe关闭
			end = fmt.Sprintf("command start failed: %v", err)
			conn.Write([]byte(fmt.Sprintf("Command start error: %v\n", err)))
			return
		}
		stdoutWrite.Close()
	}

	inputDone := make(chan struct{})
	outputDone := make(chan struct{})
	exited := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer close(inputDone)
		var shellInput io.Reader = conn
		if len(ptyshSID) == ptyshSIDSize && ptyIO != nil {
			shellInput = newPtyshResizeInputReader(conn, ptyshSID, func(rows, cols int) {
				recorder.add("SIZE", []byte(fmt.Sprintf("rows=%d cols=%d", rows, cols)))
				if err := ptyIO.Resize(cols, rows); err != nil {
					config.Logger.Printf("pty resize error: %v\n", err)
				} else {
					//config.Logger.Printf("pty resize successful: %dx%d\n", cols, rows)
				}
			})
		}
		io.Copy(shellRecordWriter{w: output, r: recorder, dir: "IN"}, shellInput)
	}()
	go func() {
		defer wg.Done()
		defer close(outputDone)
		io.Copy(conn, shellRecordReader{r: input, recorder: recorder})
	}()
	go func() {
		exited <- proc.Wait()
	}()

	var waitErr error
	var processExited bool
	var drainTimedOut bool
	select {
	case <-inputDone:
	case <-outputDone:
	case waitErr = <-exited:
		processExited = true
		// Allow the final output to drain. Bound the wait for a stalled peer
		// or descendants that still hold the output pipe/PTY open.
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-outputDone:
		case <-timer.C:
			drainTimedOut = true
		}
		timer.Stop()
	}
	conn.Close()
	_ = proc.Kill()
	input.Close()
	if !config.EnablePty {
		output.Close()
	}
	wg.Wait()
	if !processExited {
		waitErr = <-exited
	}
	end = fmt.Sprintf("session ended: wait=%v drain_timeout=%t", waitErr, drainTimedOut)
	config.Logger.Printf("Shell session(%s) ended.\n", conn.RemoteAddr())
}
