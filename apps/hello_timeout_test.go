package apps

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/easyp2p"
)

func TestHelloTimeoutConfiguration(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		option time.Duration
		want   time.Duration
		bad    bool
	}{
		{nil, 0, 30 * time.Second, false},
		{[]string{"-hello-timeout", "5m"}, 0, 0, true},
		{nil, 5 * time.Minute, 5 * time.Minute, false},
		{[]string{"-hello-timeout", "0"}, 0, 0, true},
		{[]string{"-hello-timeout", "-1s"}, 0, 0, true},
		{nil, -time.Second, 0, true},
	} {
		args := append([]string{"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z", "-httplocal"}, tc.args...)
		c, err := PrepareNetcatConfigWithOptions(context.Background(), io.Discard, args, RunOptions{HelloTimeout: tc.option})
		if tc.bad {
			if err == nil {
				t.Fatal("invalid timeout or unsupported CLI flag accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if c.helloTimeout != tc.want || !c.keepOpen || !c.useMQTTHello {
			t.Fatalf("config=%+v", c)
		}
	}
}
func TestHelloTimeoutStatusCode(t *testing.T) {
	if got := p2pPathErrorStatus(fmt.Errorf("wrapped: %w", easyp2p.ErrHelloWaitTimeout)); got != "error:hello-timeout" {
		t.Fatal(got)
	}
	for _, err := range []error{context.DeadlineExceeded, context.Canceled, fmt.Errorf("mqtt-hello timeout network failure")} {
		if p2pPathErrorStatus(err) == "error:hello-timeout" {
			t.Fatalf("misclassified %v", err)
		}
	}
}
