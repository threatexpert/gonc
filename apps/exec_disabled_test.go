//go:build gonc_noexec

package apps

import (
	"io"
	"strings"
	"testing"
)

func TestNoExecBuildRejectsLocalPrograms(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		feature string
	}{
		{"external command", []string{"-l", "-e", "/bin/sh", "1234"}, "-e with an external program"},
		{"exec alias", []string{"-l", "-exec", "cmd.exe /c dir", "1234"}, "-e with an external program"},
		{"shell", []string{"-l", "-e", ":sh", "1234"}, ":sh"},
		{"shell with options", []string{"-l", "-e", ":sh -watch /bin/bash", "1234"}, ":sh"},
		{"shell agent", []string{"-shellagent", "-l", "1234"}, "-shellagent"},
		{"shell service config", []string{"-:sh", "/bin/sh", "-e", ":service", "-l", "1234"}, "-:sh"},
		{"daemon", []string{"-daemon", "-l", "1234"}, "-daemon"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := AppNetcatConfigByArgs(io.Discard, "gonc", tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.feature+" is not available") {
				t.Fatalf("error = %v, want %s rejected", err, tc.feature)
			}
		})
	}
}

func TestNoExecBuildKeepsNetworkFeatures(t *testing.T) {
	for _, args := range [][]string{
		{"-l", "1234"},
		{"-l", "-e", ":mux linkagent", "1234"},
		{"-l", "-e", ":s5s", "1234"},
		{"-l", "-e", ":nc 127.0.0.1 80", "1234"},
		{"-l", "-httpserver", ".", "1234"},
		{"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z", "-linkagent"},
		{"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z", "-link", "1080"},
		{"-:mux", "socks5", "-e", ":service", "-l", "1234"},
	} {
		if _, err := AppNetcatConfigByArgs(io.Discard, "gonc", args); err != nil {
			t.Errorf("%q: %v", args, err)
		}
	}
}
