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
}

// App_shell_main_withconfig 启动 shell 并绑定到 conn
func App_shell_main_withconfig(conn net.Conn, config *PtyShellConfig) {
	defer conn.Close()

	config.Logger.Printf("Starting shell: %v for %s\n", config.Args, conn.RemoteAddr())

	var proc misc.PtyProcess
	var input io.ReadCloser
	var output io.WriteCloser

	if config.EnablePty {
		cmd, ptmx, err := misc.PtyStart(config.Args[0], config.Args[1:]...)
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("Failed to start pty: %v\n", err)))
			return
		}
		proc = cmd
		input = ptmx
		output = ptmx
	} else {
		cmd := exec.Command(config.Args[0], config.Args[1:]...)
		// 创建管道
		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("Error creating stdin pipe: %v\n", err)))
			return
		}

		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("Error creating stdout pipe: %v\n", err)))
			stdinPipe.Close()
			if pr, ok := cmd.Stdin.(*os.File); ok {
				pr.Close()
			}
			return
		}

		if config.MergeStderr {
			cmd.Stderr = cmd.Stdout
		} else {
			cmd.Stderr = os.Stderr
		}

		proc = &misc.StdProcess{Cmd: cmd}
		input = stdoutPipe
		output = stdinPipe

		// 启动命令
		if err := cmd.Start(); err != nil {
			// 不处理关闭pipe，cmd.Start失败时，Start里面会closeDescriptors把创建的pipe关闭
			conn.Write([]byte(fmt.Sprintf("Command start error: %v\n", err)))
			return
		}
	}

	done := make(chan struct{}, 3)
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		defer func() { done <- struct{}{} }()
		io.Copy(output, conn)
	}()
	go func() {
		defer wg.Done()
		defer func() { done <- struct{}{} }()
		io.Copy(conn, input)
	}()
	go func() {
		defer wg.Done()
		defer func() { done <- struct{}{} }()
		proc.Wait()
	}()

	<-done
	conn.Close()
	input.Close()

	_ = proc.Kill()
	_ = proc.Wait()
	wg.Wait()
	config.Logger.Printf("Shell session(%s) ended.\n", conn.RemoteAddr())
}
