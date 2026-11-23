package nearby

import "time"

// rateLimiter allows up to limit events per key within window. Callers hold
// the service lock.
type rateLimiter struct {
	limit  int
	window time.Duration
	events map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, events: map[string][]time.Time{}}
}

func (r *rateLimiter) allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-r.window)
	if len(r.events) > 1024 {
		for k, times := range r.events {
			if len(times) == 0 || times[len(times)-1].Before(cutoff) {
				delete(r.events, k)
			}
		}
	}
	times := r.events[key]
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.limit {
		r.events[key] = kept
		return false
	}
	r.events[key] = append(kept, now)
	return true
}
