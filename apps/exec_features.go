package apps

import "fmt"

// Building with -tags gonc_noexec leaves out every feature that starts a local
// process: -e/-exec with an external command, the :sh shell, -shellagent and
// -daemon. It also leaves out the remote shell client (-shell) and raw
// terminal mode (-pty). The standard gonc command keeps all of these.
// :service stays available: a peer can only pick one of the
// built-in services configured beforehand, and :sh cannot be configured.
//
// The checks below and the branches guarded by ExecSupported are constant in
// each build, so the compiler drops the disabled code and the linker drops the
// shell implementation it no longer reaches.

func errNoExec(feature string) error {
	return fmt.Errorf("%s is not available in this build of gonc (gonc_noexec)", feature)
}

// checkExecFeatures rejects unavailable process and terminal options after
// flag parsing. External -e commands and :sh given with -e are rejected by
// preinitBuiltinAppConfig.
func checkExecFeatures(config *AppNetcatConfig) error {
	if ExecSupported {
		return nil
	}
	switch {
	case config.daemon:
		return errNoExec("-daemon")
	case config.shellAgent:
		return errNoExec("-shellagent")
	case config.app_sh_args != "-":
		return errNoExec("-:sh")
	case config.shellClient:
		return errNoExec("-shell")
	case config.enablePty:
		return errNoExec("-pty")
	}
	return nil
}
