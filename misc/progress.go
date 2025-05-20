package misc

import (
	"fmt"
	"time"
)

type ProgressStats struct {
	startTime  time.Time
	totalBytes int64
	lastBytes  int64
	lastTime   time.Time
	lastSpeed  float64
}

type StatResult struct {
	TotalBytes int64
	SpeedBps   float64
}

func NewProgressStats() *ProgressStats {
	now := time.Now()
	return &ProgressStats{
		startTime: now,
		lastTime:  now,
	}
}

func (p *ProgressStats) ResetStart() {
	now := time.Now()
	p.startTime = now
	p.lastTime = now
}

func (p *ProgressStats) Update(n int64) {
	p.totalBytes += n
}

func (p *ProgressStats) Stats(now time.Time, final bool) StatResult {
	var timeDiff float64
	var bytesDiff int64

	if final {
		timeDiff = now.Sub(p.startTime).Seconds()
		bytesDiff = p.totalBytes
	} else {
		timeDiff = now.Sub(p.lastTime).Seconds()
		bytesDiff = p.totalBytes - p.lastBytes
	}

	var speed float64
	if timeDiff > 0 {
		speed = float64(bytesDiff) / timeDiff
		p.lastSpeed = speed
	} else {
		speed = p.lastSpeed
	}

	p.lastTime = now
	p.lastBytes = p.totalBytes

	return StatResult{
		TotalBytes: p.totalBytes,
		SpeedBps:   speed,
	}
}

func (p *ProgressStats) StartTime() time.Time {
	return p.startTime
}

func FormatBytes(bytes int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB"}
	value := float64(bytes)

	for _, unit := range units {
		if value < 1024.0 {
			return fmt.Sprintf("%.1f %s", value, unit)
		}
		value /= 1024.0
	}
	return fmt.Sprintf("%.1f YiB", value)
}
