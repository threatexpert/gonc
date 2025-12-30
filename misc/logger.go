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
	mu                sync.Mutex
	w                 io.Writer
	enabled           bool
	lastWasProgress   bool
	lastProgressLen   int
	cursorAtLineStart bool

	lastLogTime           time.Time
	lastProgressWriteTime time.Time
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

// 计算显示长度（遇到 \r 或 \n 停止）
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
	if len(p) == 0 {
		return false
	}
	// 特征：以 \r 结尾，且不包含 \n
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

	// ---------------------------------------------------------
	// 1. 流控逻辑：依然保留
	//    目的：防止高频日志输出时，进度条像频闪灯一样在底部闪烁。
	// ---------------------------------------------------------
	if isProgress {
		sinceLastLog := now.Sub(tw.lastLogTime)
		sinceLastProg := now.Sub(tw.lastProgressWriteTime)

		// 如果日志很密集(<1s)，且进度条没憋太久(<10s)，这轮进度条就不输出了
		if sinceLastLog < 1*time.Second && sinceLastProg < 10*time.Second {
			return len(p), nil
		}
	}

	// ---------------------------------------------------------
	// 2. 进度条写入逻辑
	// ---------------------------------------------------------
	if isProgress {
		// Case: 上一行是残留的日志（未换行），进度条必须换行才能不破坏上一条日志
		if !tw.cursorAtLineStart {
			if _, err := tw.w.Write([]byte("\n")); err != nil {
				return 0, err
			}
			tw.cursorAtLineStart = true
		}

		// 处理进度条自身的 Padding (防止本次短进度 盖不住 上次长进度)
		currLen := visibleLen(p)
		if tw.lastWasProgress && tw.lastProgressLen > currLen {
			padding := tw.lastProgressLen - currLen
			// 构造： 内容 + 空格 + \r
			buf := make([]byte, 0, len(p)+padding)
			buf = append(buf, p[:len(p)-1]...)                       // 去掉 \r
			buf = append(buf, bytes.Repeat([]byte(" "), padding)...) // 补空格
			buf = append(buf, '\r')                                  // 补回 \r
			p = buf
		}
		tw.lastProgressLen = currLen
	}

	// ---------------------------------------------------------
	// 3. 普通日志写入逻辑 (覆盖模式核心)
	// ---------------------------------------------------------
	if !isProgress {
		// 【关键优化】：删除了 "if lastWasProgress { write(\n) }" 的逻辑
		// 我们现在希望直接覆盖。

		// 处理 "幽灵字符"：如果上一条是进度条，且比当前日志长，需要补空格擦除
		if tw.lastWasProgress {
			currLogLen := visibleLen(p)
			if currLogLen < tw.lastProgressLen {
				padding := tw.lastProgressLen - currLogLen

				// 这里的 p 通常以 \n 结尾，我们要把空格插在 \n 前面
				// 步骤：分离内容和换行符 -> 拼接空格 -> 拼接换行符

				// 检查末尾是否有换行
				hasNewline := len(p) > 0 && p[len(p)-1] == '\n'
				contentEnd := len(p)
				if hasNewline {
					contentEnd--
				}

				buf := make([]byte, 0, len(p)+padding)
				buf = append(buf, p[:contentEnd]...)                     // 日志内容
				buf = append(buf, bytes.Repeat([]byte(" "), padding)...) // 擦除用的空格
				if hasNewline {
					buf = append(buf, '\n')
				}
				p = buf
			}
			// 既然已经覆盖了，重置记录
			tw.lastProgressLen = 0
		}
	}

	// ---------------------------------------------------------
	// 4. 执行写入与状态更新
	// ---------------------------------------------------------
	n, err := tw.w.Write(p)

	if err == nil {
		if isProgress {
			tw.lastProgressWriteTime = now
			tw.cursorAtLineStart = true // \r 回到行首
		} else {
			tw.lastLogTime = now
			// 普通日志：如果末尾有 \n，则下次从行首开始
			if n > 0 {
				tw.cursorAtLineStart = (p[n-1] == '\n')
			}
		}
		tw.lastWasProgress = isProgress
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
func NewLogMilli(w io.Writer, tag string, flag int) *log.Logger {
	flag &^= timeFlags
	flag |= log.Lmsgprefix
	return log.New(
		NewShortTimeWriter(w, true),
		tag,
		flag,
	)
}
