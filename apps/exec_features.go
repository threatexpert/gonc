package apps

import "fmt"

// Building with -tags gonc_noexec leaves out every feature that starts a local
// process: -e/-exec with an external command, the :sh shell, -shellagent and
// -daemon. Programs that embed gonc for its network features use it so a
// configuration can never start a shell or another program. The gonc command
// keeps all of them. :service stays available: a peer can only pick one of the
// built-in services configured beforehand, and :sh cannot be configured.
//
// The checks below and the branches guarded by ExecSupported are constant in
// each build, so the compiler drops the disabled code and the linker drops the
// shell implementation it no longer reaches.

func errNoExec(feature string) error {
	return fmt.Errorf("%s is not available: this build of gonc cannot run local programs (gonc_noexec)", feature)
}

// checkExecFeatures rejects options that run local programs when ExecSupported
// is false. External -e commands and :sh given with -e are rejected by
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
	}
	return nil
}
