package misc

import (
	"fmt"
	"io"
	"log"
	"time"
)

type SwitchableWriter struct {
	w       io.Writer
	enabled bool
}

func NewSwitchableWriter(w io.Writer, enabled bool) *SwitchableWriter {
	return &SwitchableWriter{
		w:       w,
		enabled: enabled,
	}
}

func (tw *SwitchableWriter) Enable(b bool) {
	tw.enabled = b
}

func (tw *SwitchableWriter) Write(p []byte) (int, error) {
	if tw.enabled {
		return tw.w.Write(p)
	}
	return len(p), nil
}

// ShortTimeWriter 在每行日志前追加短时间戳
// 格式：YYYYMMDD-HHMMSS(.mmm)
type ShortTimeWriter struct {
	w         io.Writer
	withMilli bool
}

func NewShortTimeWriter(w io.Writer, withMilli bool) *ShortTimeWriter {
	return &ShortTimeWriter{
		w:         w,
		withMilli: withMilli,
	}
}

func (tw *ShortTimeWriter) Write(p []byte) (int, error) {
	if sw, ok := tw.w.(*SwitchableWriter); ok && !sw.enabled {
		return len(p), nil
	}
	var ts string
	if tw.withMilli {
		ts = time.Now().Format("20060102-150405.000")
	} else {
		ts = time.Now().Format("20060102-150405")
	}
	return fmt.Fprintf(tw.w, "%s %s", ts, p)
}

const timeFlags = log.Ldate | log.Ltime | log.Lmicroseconds

// New 创建一个带 tag 的 logger
//
// 输出示例：
// [MQTT] 20251226-113930 Will retry in 10 seconds...
func NewLog(w io.Writer, tag string, flag int) *log.Logger {
	flag &^= timeFlags

	// 强制使用 Lmsgprefix
	flag |= log.Lmsgprefix

	return log.New(
		NewShortTimeWriter(w, false),
		tag,
		flag,
	)
}

// NewMilli 创建一个带毫秒时间戳的 logger
//
// 输出示例：
// [MQTT] 20251226-113930.217 Will retry in 10 seconds...
func NewLogMilli(w io.Writer, tag string, flag int) *log.Logger {
	flag &^= timeFlags
	flag |= log.Lmsgprefix
	return log.New(
		NewShortTimeWriter(w, true),
		tag,
		flag,
	)
}
