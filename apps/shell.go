package apps

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

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
	EnablePty, MergeStderr bool
	Args                   []string
}

// PtyShellConfigByArgs 从命令行参数构造 config
func PtyShellConfigByArgs(args []string) (*PtyShellConfig, error) {
	config := &PtyShellConfig{
		Args: []string{"/bin/sh"},
	}

	fs := flag.NewFlagSet("PtyShellConfig", flag.ContinueOnError)

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
	fmt.Fprintln(os.Stderr, "-sh Usage: [options] shell-path <args>")
	fmt.Fprintln(os.Stderr, "Options:")
	fs.PrintDefaults()
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  -sh /bin/bash")
}

// App_shell_main_withconfig 启动 shell 并绑定到 conn
func App_shell_main_withconfig(conn net.Conn, config *PtyShellConfig) {
	defer conn.Close()

	var input io.ReadCloser
	var output io.WriteCloser

	cmd := exec.Command(config.Args[0], config.Args[1:]...)

	if config.EnablePty {
		ptmx, err := misc.PtyStart(cmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start pty: %v\n", err)
			return
		}
		input = ptmx
		output = ptmx
	} else {
		// 创建管道
		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating stdin pipe: %v\n", err)
			return
		}

		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating stdout pipe: %v\n", err)
			return
		}

		if config.MergeStderr {
			cmd.Stderr = cmd.Stdout
		} else {
			cmd.Stderr = os.Stderr
		}

		input = stdoutPipe
		output = stdinPipe

		// 启动命令
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Command start error: %v\n", err)
			return
		}
	}

	done := make(chan struct{})
	go func() {
		io.Copy(output, conn)
		output.Close()
		close(done)
	}()

	io.Copy(conn, input)
	conn.Close()

	if cmd != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}

	<-done
	//fmt.Fprintf(os.Stderr, "App_shell_main_withconfig done\n")
}
