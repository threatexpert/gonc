package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The CLI uses apps directly, with embedding and GUI dependencies kept outside its build.
func TestCLIDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, dependency := range strings.Fields(string(out)) {
		if strings.Contains(dependency, "/tun2socks/") ||
			strings.HasPrefix(dependency, "gvisor.dev/gvisor/") ||
			dependency == "github.com/threatexpert/gonc/v2/goncembed" ||
			strings.HasPrefix(dependency, "gonc-gui/") {
			t.Fatalf("CLI imports embedding or GUI dependency %s", dependency)
		}
	}
}
