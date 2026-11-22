package apps

import (
	"flag"
	"fmt"
)

// Apply defaults before normal initialization, honoring explicitly supplied
// flags (including aliases). These shortcuts use a direct shell data stream.
func configureShellShortcut(config *AppNetcatConfig, fs *flag.FlagSet) error {
	if !config.shellAgent && !config.shellClient {
		return nil
	}
	if config.shellAgent && config.shellClient {
		return fmt.Errorf("-shellagent and -shell cannot be used together")
	}
	mode := "-shell"
	if config.shellAgent {
		mode = "-shellagent"
	}
	if config.runCmd != "" {
		return fmt.Errorf("%s cannot be used with -e/-exec", mode)
	}
	if config.remoteCall != "" {
		return fmt.Errorf("%s uses a direct shell and cannot be used with -call", mode)
	}
	if config.runAppFileServ != "" || config.runAppFileGet != "" ||
		config.appMuxSocksMode || config.appMuxLinkAgent || config.runAppLink != "" ||
		config.appMuxListenMode || config.appMuxListenOn != "" || isEnabledMuxMode(config) ||
		config.natchecker || config.httpdownload {
		return fmt.Errorf("%s cannot be used with another application mode", mode)
	}
	if config.app_mux_args != "-" || config.app_s5s_args != "-" ||
		config.app_nc_args != "-" || config.app_httpserver_args != "-" {
		return fmt.Errorf("%s cannot configure other dynamic services", mode)
	}
	if config.scanOnly || config.speedTestDuration != 0 {
		return fmt.Errorf("%s cannot be used with -z or -speedtest", mode)
	}

	explicit := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if config.shellAgent {
		if explicit[":sh"] && config.app_sh_args == "-" {
			return fmt.Errorf("-shellagent requires an enabled shell; -:sh '-' disables it")
		}
		// Put the default before user options so -watch=false can override it.
		config.runCmd = ":sh -watch"
		if config.app_sh_args != "-" && config.app_sh_args != "" {
			config.runCmd += " " + config.app_sh_args
		}
		if !explicit["keep-open"] && !explicit["k"] {
			config.keepOpen = true
		}
		if config.autoP2P != "" && !explicit["mqtt-wait"] && !explicit["W"] {
			config.useMQTTWait = true
		}
	} else {
		if explicit[":sh"] {
			return fmt.Errorf("-:sh configures the shell provider; use it with -shellagent, not -shell")
		}
		if !explicit["pty"] {
			config.enablePty = true
		}
		if config.autoP2P != "" && !explicit["mqtt-hello"] && !explicit["H"] {
			config.useMQTTHello = true
		}
	}
	return nil
}
