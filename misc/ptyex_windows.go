//go:build windows
// +build windows

package misc

import (
	"os"

	"golang.org/x/sys/windows"

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

func PtyStart(name string, args ...string) (PtyProcess, ResizablePty, error) {

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

func EnableVirtualTerminal() {
	enableVirtualTerminalFor(os.Stdout)
	enableVirtualTerminalFor(os.Stderr)
}

func enableVirtualTerminalFor(file *os.File) {
	console := windows.Handle(file.Fd())

	// Variable to store the original console mode
	var originalMode uint32

	// Get the current console mode
	if err := windows.GetConsoleMode(console, &originalMode); err == nil {
		if originalMode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
			return
		}
		// Set the new mode with ENABLE_VIRTUAL_TERMINAL_PROCESSING added
		windows.SetConsoleMode(console, originalMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
}
