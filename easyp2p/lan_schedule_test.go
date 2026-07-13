package easyp2p

import (
	"testing"
	"time"
)

func TestLANBeaconSchedule(t *testing.T) {
	want := []time.Duration{
		250 * time.Millisecond,
		750 * time.Millisecond,
		4 * time.Second,
		10 * time.Second,
	}
	for i, delay := range want {
		if got := lanNextBeaconDelay(true, i+1); got != delay {
			t.Fatalf("passive delay %d = %s, want %s", i, got, delay)
		}
	}

	for i := 0; i < 64; i++ {
		got := lanNextBeaconDelay(true, len(want)+1)
		if got != lanPassiveBeaconInterval {
			t.Fatalf("steady passive delay = %s, want %s", got, lanPassiveBeaconInterval)
		}
	}
	fastBeaconCount := int(lanActiveFastBeaconWindow / lanActiveBeaconInterval)
	if got := lanNextBeaconDelay(false, fastBeaconCount); got != lanActiveBeaconInterval {
		t.Fatalf("last fast active delay = %s, want %s", got, lanActiveBeaconInterval)
	}
	if got := lanNextBeaconDelay(false, fastBeaconCount+1); got != lanActiveSlowBeaconInterval {
		t.Fatalf("slow active delay = %s, want %s", got, lanActiveSlowBeaconInterval)
	}
}
