package misc

import (
	"io"
	"log"
)

// 定义日志级别
const (
	LogLevelDebug = iota // 0
	LogLevelInfo         // 1
	LogLevelWarn         // 2
	LogLevelError        // 3
	LogLevelNone         // 4 (最高级别，表示不输出任何日志)
)

// CustomLogger 是我们自定义的日志器
type CustomLogger struct {
	logger *log.Logger
	level  int // 当前日志级别
}

// NewCustomLogger 创建一个新的 CustomLogger
func NewCustomLogger(output io.Writer, minLevel int) *CustomLogger {
	// log.LstdFlags | log.Lshortfile 可以添加时间和文件行号
	return &CustomLogger{
		logger: log.New(output, "", log.LstdFlags|log.Lshortfile),
		level:  minLevel,
	}
}

// SetLevel 设置日志输出的最低级别
func (l *CustomLogger) SetLevel(level int) {
	l.level = level
}

// Debug 输出调试信息
func (l *CustomLogger) Debug(format string, v ...interface{}) {
	if l.level <= LogLevelDebug {
		l.logger.Printf("DEBUG: "+format, v...)
	}
}

// Info 输出普通信息
func (l *CustomLogger) Info(format string, v ...interface{}) {
	if l.level <= LogLevelInfo {
		l.logger.Printf("INFO: "+format, v...)
	}
}

// Warn 输出警告信息
func (l *CustomLogger) Warn(format string, v ...interface{}) {
	if l.level <= LogLevelWarn {
		l.logger.Printf("WARN: "+format, v...)
	}
}

// Error 输出错误信息
func (l *CustomLogger) Error(format string, v ...interface{}) {
	if l.level <= LogLevelError {
		l.logger.Printf("ERROR: "+format, v...)
	}
}
