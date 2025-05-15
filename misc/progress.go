package misc

import (
	"fmt"
	"time"
)

// 新增的进度统计相关代码
type ProgressStats struct {
	startTime    time.Time
	totalBytes   int64
	lastBytes    int64     // 上次统计时的字节数
	lastTime     time.Time // 上次统计时间
	lastSpeed    float64   // 上次计算的速度（字节/秒）
	lastSpeedStr string
}

func NewProgressStats() *ProgressStats {
	now := time.Now()
	return &ProgressStats{
		startTime: now,
		lastTime:  now,
	}
}

func (p *ProgressStats) Update(n int64) {
	p.totalBytes += n
}

func (p *ProgressStats) String(final bool) string {
	now := time.Now()
	// 计算瞬时速度（最近一次间隔的速度）
	timeDiff := now.Sub(p.lastTime).Seconds()
	bytesDiff := p.totalBytes - p.lastBytes
	if final {
		timeDiff = now.Sub(p.startTime).Seconds()
		bytesDiff = p.totalBytes
	}

	var speed float64
	if timeDiff > 0 {
		speed = float64(bytesDiff) / timeDiff
		p.lastSpeed = speed // 保存最后一次计算的速度
	} else {
		speed = p.lastSpeed // 使用上次计算的速度
	}

	// 更新最后统计时间和字节数
	p.lastTime = now
	p.lastBytes = p.totalBytes

	// 计算总时间
	totalElapsed := now.Sub(p.startTime).Seconds()
	hours := int(totalElapsed) / 3600
	minutes := (int(totalElapsed) % 3600) / 60
	seconds := int(totalElapsed) % 60

	// 格式化输出
	sizeStr := formatBytes(p.totalBytes)
	speedStr := formatBytes(int64(speed)) + "/s"

	p.lastSpeedStr = fmt.Sprintf("%d bytes (%s) copied, %02d:%02d:%02d, %s",
		p.totalBytes, sizeStr, hours, minutes, seconds, speedStr)
	return p.lastSpeedStr
}

func formatBytes(bytes int64) string {
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
