package apps

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
)

func TestRemovedBridgeAndRotationFlagsRejected(t *testing.T) {
	for _, name := range []string{"-kcpbr", "-port-rotate", "-:br", "-:pr"} {
		t.Run(name, func(t *testing.T) {
			_, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{name})
			if err == nil || !strings.Contains(err.Error(), "flag provided but not defined: "+name) {
				t.Fatalf("error = %v, want undefined flag %s", err, name)
			}
		})
	}
}

func TestRemovedBridgeAndRotationCommandsRejected(t *testing.T) {
	for _, command := range []string{":br 127.0.0.1 8080", ":pr -period 600"} {
		t.Run(command, func(t *testing.T) {
			_, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{"-e", command, "-l", "1234"})
			if err == nil || !strings.Contains(err.Error(), "unknown built-in command: "+strings.Fields(command)[0]) {
				t.Fatalf("error = %v, want unknown built-in command", err)
			}
		})
	}
}

func TestHelpOmitsRemovedBridgeAndRotationFlags(t *testing.T) {
	var output bytes.Buffer
	_, err := AppNetcatConfigByArgs(&output, "gonc", []string{"-h"})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help error = %v", err)
	}
	for _, name := range []string{"-kcpbr", "-port-rotate", "-:br", "-:pr"} {
		if strings.Contains(output.String(), name) {
			t.Errorf("help still advertises %s", name)
		}
	}
}

func TestPlainP2PLinkModesRemainAvailable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		command string
	}{
		{"link", []string{"-link", "1080"}, ":mux link 1080"},
		{"linkagent", []string{"-linkagent"}, ":mux linkagent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z"}, tc.args...)
			config, err := AppNetcatConfigByArgs(io.Discard, "gonc", args)
			if err != nil {
				t.Fatal(err)
			}
			if config.runCmd != tc.command || config.app_mux_Config == nil || !config.keepOpen || len(config.featureModulesRun) != 0 {
				t.Fatalf("unexpected P2P app configuration: command=%q keepOpen=%t modules=%v", config.runCmd, config.keepOpen, config.featureModulesRun)
			}
		})
	}
}
