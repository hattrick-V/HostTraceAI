package logger

import (
	"io"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.Logger

	closer io.Closer
}

func New(level, output string, diagnostics ...DiagnosticOptions) *Logger {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapLevel)
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	var (
		writeSyncer zapcore.WriteSyncer
		closer      io.Closer
	)
	if output == "stdout" {
		writeSyncer = zapcore.AddSync(os.Stdout)
	} else if output == "stderr" {
		writeSyncer = zapcore.AddSync(os.Stderr)
	} else {
		// 惰性打开文件：避免只为构造 logger 就长期持有文件句柄。
		// 这样 Windows 上测试/调用方可以正常清理日志目录，
		// 同时保持 "打开失败时回退 stdout" 的既有行为。
		fileSyncer := newLazyFileWriter(output)
		writeSyncer = fileSyncer
		closer = fileSyncer
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(config.EncoderConfig),
		writeSyncer,
		zapLevel,
	)

	options := DiagnosticOptions{}
	if len(diagnostics) > 0 {
		options = diagnostics[0]
	}
	if !options.Disabled {
		// The diagnostic threshold is independent of the primary output level.
		core = zapcore.NewTee(core, zapcore.NewCore(
			zapcore.NewJSONEncoder(config.EncoderConfig),
			newDailyWriter(options), zapcore.WarnLevel,
		))
	}

	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return &Logger{Logger: logger, closer: closer}
}

// Sync 刷新缓冲日志。实现 zap.Logger 的既有用法（defer log.Sync()）。
func (l *Logger) Sync() error {
	if l == nil || l.Logger == nil {
		return nil
	}
	return l.Logger.Sync()
}

// Close 释放底层日志文件句柄。多次调用安全。
// 调用方应在进程退出前（或测试结束）调用，避免文件句柄泄漏。
func (l *Logger) Close() error {
	if l == nil || l.closer == nil {
		return nil
	}
	err := l.closer.Close()
	l.closer = nil
	return err
}

func (l *Logger) Fatal(msg string, fields ...interface{}) {
	zapFields := make([]zap.Field, 0, len(fields))
	for _, f := range fields {
		switch v := f.(type) {
		case error:
			zapFields = append(zapFields, zap.Error(v))
		default:
			zapFields = append(zapFields, zap.Any("field", v))
		}
	}
	l.Logger.Fatal(msg, zapFields...)
}
