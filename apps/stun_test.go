package apps

import (
	"errors"
	"testing"

	"github.com/threatexpert/gonc/v2/easyp2p"
)

func TestFirstSuccessfulSTUNResultSkipsFailures(t *testing.T) {
	want := &easyp2p.STUNResult{Index: 1, Nat: "203.0.113.10:45678"}
	results := []*easyp2p.STUNResult{
		{Index: 0, Err: errors.New("server unavailable")},
		want,
	}

	got, err := firstSuccessfulSTUNResult(results)
	if err != nil {
		t.Fatalf("firstSuccessfulSTUNResult returned error: %v", err)
	}
	if got != want {
		t.Fatalf("firstSuccessfulSTUNResult returned %#v, want %#v", got, want)
	}
}

func TestFirstSuccessfulSTUNResultRejectsAllFailures(t *testing.T) {
	results := []*easyp2p.STUNResult{
		nil,
		{Index: 0, Err: errors.New("server unavailable")},
		{Index: 1},
	}

	if _, err := firstSuccessfulSTUNResult(results); err == nil {
		t.Fatal("firstSuccessfulSTUNResult returned nil error")
	}
}

func TestFirstSuccessfulSTUNResultRejectsInvalidServerIndex(t *testing.T) {
	results := []*easyp2p.STUNResult{
		{Index: len(easyp2p.STUNServers), Nat: "203.0.113.10:45678"},
	}

	if _, err := firstSuccessfulSTUNResult(results); err == nil {
		t.Fatal("firstSuccessfulSTUNResult returned nil error")
	}
}
