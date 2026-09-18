package logger

import (
	"os"
	"sync"
)

// lazyFileWriter 只在真正写入时才打开目标文件，并在写入后立即关闭。
//
// 这样做的原因：
//   - 构造 logger 时不再长期占用文件句柄，Windows 上才能正常删除/清理日志目录；
//   - 保留原行为：文件打不开时回退到 stdout，日志不丢。
//
// 与 dailyWriter 的策略一致（写即打开、写完即关），使日志目录始终可被回收。
type lazyFileWriter struct {
	path string

	mu       sync.Mutex
	fallback bool // true 表示文件不可用，后续直接写 stdout
}

func newLazyFileWriter(path string) *lazyFileWriter {
	return &lazyFileWriter{path: path}
}

// Write 以追加方式写入一行日志。文件打开失败时回退 stdout。
func (w *lazyFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.fallback {
		return os.Stdout.Write(p)
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		w.fallback = true
		return os.Stdout.Write(p)
	}
	n, writeErr := f.Write(p)
	closeErr := f.Close()
	if writeErr != nil {
		return n, writeErr
	}
	return n, closeErr
}

// Sync 无需缓冲，直接返回 nil（每次 Write 都已落盘并关闭句柄）。
func (w *lazyFileWriter) Sync() error { return nil }

// Close 关闭惰性写入器。因句柄不常驻，这里只需标记结束。
func (w *lazyFileWriter) Close() error { return nil }
