package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Adding the reusable VPN engine must not make the CLI link gVisor/tun2socks,
// and the Nearby protocol is for embedding applications only.
func TestCLIExcludesTunEngine(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, dependency := range strings.Fields(string(out)) {
		if strings.Contains(dependency, "/tun2socks/") || strings.HasPrefix(dependency, "gvisor.dev/gvisor/") || dependency == "github.com/threatexpert/gonc/v2/tunengine" || dependency == "github.com/threatexpert/gonc/v2/mobilegonc" || dependency == "github.com/threatexpert/gonc/v2/nearby" {
			t.Fatalf("CLI imports VPN engine dependency %s", dependency)
		}
	}
}
