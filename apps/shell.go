package apps

import (
	"flag"
	"fmt"
	"io"
	"log"
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
	Logger                 *log.Logger
	EnablePty, MergeStderr bool
	Args                   []string
}

// PtyShellConfigByArgs 从命令行参数构造 config
func PtyShellConfigByArgs(logWriter io.Writer, args []string) (*PtyShellConfig, error) {
	config := &PtyShellConfig{
		Logger: misc.NewLog(logWriter, "[:sh] ", log.LstdFlags|log.Lmsgprefix),
		Args:   []string{"/bin/sh"},
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
	fmt.Fprintln(fs.Output(), "-sh Usage: [options] shell-path <args>")
	fmt.Fprintln(fs.Output(), "Options:")
	fs.PrintDefaults()
	fmt.Fprintln(fs.Output(), "")
	fmt.Fprintln(fs.Output(), "Examples:")
	fmt.Fprintln(fs.Output(), "  -sh /bin/bash")
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
			config.Logger.Printf("Failed to start pty: %v\n", err)
			return
		}
		input = ptmx
		output = ptmx
	} else {
		// 创建管道
		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			config.Logger.Printf("Error creating stdin pipe: %v\n", err)
			return
		}

		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			config.Logger.Printf("Error creating stdout pipe: %v\n", err)
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
			config.Logger.Printf("Command start error: %v\n", err)
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
	//config.Logger.Printf("App_shell_main_withconfig done\n")
}
