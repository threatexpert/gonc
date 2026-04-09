//go:build windows
// +build windows

package apps

import (
	"os"

	"golang.org/x/sys/windows"
)

// daemonize for Windows: attempt to start a detached child process.
// We set an environment marker _GONC_DAEMONIZED=1 so the child won't re-daemonize.
// We use CreationFlags DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP and hide the window.
// On success the parent exits. On failure an error is returned.
func daemonize(ncconfig *AppNetcatConfig) error {
	if !ncconfig.daemon {
		return nil
	}
	// If already daemonized (child), do nothing.
	if os.Getenv("_GONC_DAEMONIZED") == "1" {
		return nil
	}

	// Prepare child process attributes.
	files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	attr := &os.ProcAttr{
		Dir:   ".",
		Env:   append(os.Environ(), "_GONC_DAEMONIZED=1"),
		Files: files,
		Sys: &windows.SysProcAttr{
			// DETACHED_PROCESS detaches from console.
			// CREATE_NEW_PROCESS_GROUP prevents the child from receiving CTRL signals from parent's group.
			CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
			HideWindow:    true,
		},
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	proc, err := os.StartProcess(exe, os.Args, attr)
	if err != nil {
		ncconfig.Logger.Printf("Failed to start daemonized process: %v\n", err)
		return err
	}

	ncconfig.Logger.Printf("Daemon process started with pid %d\n", proc.Pid)
	// Parent exits to complete daemonization.
	os.Exit(0)
	return nil
}

func ensureSignalHandler() {
}
