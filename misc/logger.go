package misc

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

type SwitchableWriter struct {
	mu                    sync.Mutex
	w                     io.Writer
	enabled               bool
	lastWasProgress       bool
	lastProgressLen       int
	cursorAtLineStart     bool
	lastLogTime           time.Time // 上一次写入普通日志的时间
	lastProgressWriteTime time.Time // 上一次实际写入进度条的时间
}

func NewSwitchableWriter(w io.Writer, enabled bool) *SwitchableWriter {
	return &SwitchableWriter{
		w:                 w,
		enabled:           enabled,
		cursorAtLineStart: true,
	}
}

func (tw *SwitchableWriter) Enable(b bool) {
	tw.mu.Lock()
	tw.enabled = b
	tw.mu.Unlock()
}

func visibleLen(p []byte) int {
	n := 0
	for _, b := range p {
		if b == '\r' || b == '\n' {
			break
		}
		n++
	}
	return n
}

func isProgressWrite(p []byte) bool {
	// 特征：以 \r 结尾，且不包含 \n
	if len(p) == 0 {
		return false
	}
	if p[len(p)-1] != '\r' {
		return false
	}
	for _, b := range p {
		if b == '\n' {
			return false
		}
	}
	return true
}

func (tw *SwitchableWriter) Write(p []byte) (int, error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if !tw.enabled {
		return len(p), nil
	}

	isProgress := isProgressWrite(p)
	now := time.Now()

	// 进度条优先级控制 ---
	if isProgress {
		// 规则 1：计算距离上一次普通日志过去了多久
		sinceLastLog := now.Sub(tw.lastLogTime)
		// 规则 2：计算距离上一次进度条显示过去了多久
		sinceLastProg := now.Sub(tw.lastProgressWriteTime)

		// 判定：如果普通日志刚输出不久 (<2s)，且进度条还没超时 (<10s)
		// 则跳过本次进度条输出，避免抢占视线
		if sinceLastLog < 2*time.Second && sinceLastProg < 10*time.Second {
			// 直接返回 len(p)，欺骗调用者写入成功，实际上什么都没做
			return len(p), nil
		}
	}

	// 2. 关键修复：解决 "Do something..." 未换行就被进度条覆盖的问题
	//    如果当前是进度条，但屏幕光标不在行首（说明有残留日志），强制换行。
	if isProgress && !tw.cursorAtLineStart {
		if _, err := tw.w.Write([]byte("\n")); err != nil {
			return 0, err
		}
		tw.cursorAtLineStart = true
	}

	// 处理进度条 Padding（防止短进度条覆盖不了长进度条）
	if isProgress {
		currLen := visibleLen(p)

		if tw.lastWasProgress && tw.lastProgressLen > currLen {
			padding := tw.lastProgressLen - currLen
			buf := make([]byte, 0, len(p)+padding)
			buf = append(buf, p[:len(p)-1]...)
			buf = append(buf, bytes.Repeat([]byte(" "), padding)...)
			buf = append(buf, '\r')
			p = buf
		}

		tw.lastProgressLen = currLen
	} else {
		tw.lastProgressLen = 0
	}

	// 进度 → 普通日志，先换行
	if tw.lastWasProgress && !isProgress {
		if _, err := tw.w.Write([]byte("\n")); err != nil {
			return 0, err
		}
		tw.cursorAtLineStart = true
	}

	n, err := tw.w.Write(p)

	// 更新时间戳 ---
	if err == nil { // 只有写入成功才更新时间
		if isProgress {
			tw.lastProgressWriteTime = now
		} else {
			tw.lastLogTime = now
		}
	}

	tw.lastWasProgress = isProgress
	if isProgress {
		// 进度条以 \r 结尾，虽然光标回到了行首，但该行被占用了。
		// 这里我们要看策略：
		// 如果你希望下一条普通日志另起一行，这里可以设为 false（强迫下次换行）。
		// 但通常进度条都是自己管自己的 \r，所以这里我们标记为 true (视为行首)，
		// 但我们在上面第2步增加了 !tw.cursorAtLineStart 的判断，
		// 实际上，只要是进度条，我们默认它总是“霸道”地要从行首开始。

		// 修正逻辑：进度条写完后，光标其实是在行首（因为\r），
		// 但如果你紧接着写普通日志，普通日志会覆盖进度条。
		// 所以最稳妥的做法是：认为进度条写完后，光标虽然在物理行首，但逻辑上这行“不干净”。
		// 不过，按照上面第4步的逻辑（进度->普通 自动换行），这里设为 true 也没问题。
		tw.cursorAtLineStart = true
	} else {
		// 普通日志：必须检查结尾有没有换行符
		if n > 0 {
			tw.cursorAtLineStart = (p[n-1] == '\n')
		}
	}
	return n, err
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
