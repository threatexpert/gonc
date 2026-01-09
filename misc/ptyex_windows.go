//go:build windows
// +build windows

package misc

import (
	"io"
	"os"

	pty "github.com/threatexpert/go-winpty"
)

type WinPtyProcess struct {
	cmd *pty.Cmd // 假设这是那个第三方库的类型
}

func (w *WinPtyProcess) Wait() error {
	return w.cmd.Wait()
}

func (w *WinPtyProcess) Kill() error {
	if w.cmd.Process != nil {
		return w.cmd.Process.Kill()
	}
	return nil
}

func (w *WinPtyProcess) GetProcess() *os.Process {
	return w.cmd.Process
}

func PtyStart(name string, args ...string) (PtyProcess, io.ReadWriteCloser, error) {

	pt, err := pty.New()
	if err != nil {
		return nil, nil, err
	}

	cmd := pt.Command(name, args...)
	if err := cmd.Start(); err != nil {
		pt.Close()
		return nil, nil, err
	}

	return &WinPtyProcess{cmd: cmd}, pt, nil
}
