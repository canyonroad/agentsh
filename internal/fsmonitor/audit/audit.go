package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ErrQueueFull is returned when the logger queue is full and dropOldest is disabled.
var ErrQueueFull = errors.New("audit queue full")

// Event represents a single audited filesystem action.
type Event struct {
	Op         string `json:"op"`
	Path       string `json:"path,omitempty"`
	DstPath    string `json:"dst_path,omitempty"`
	Result     string `json:"result,omitempty"` // allowed|blocked|diverted|error
	Reason     string `json:"reason,omitempty"`
	TrashToken string `json:"trash_token,omitempty"`
	Size       int64  `json:"size,omitempty"`
	LinkCount  int    `json:"nlink,omitempty"`

	PID     int       `json:"pid"`
	UID     int       `json:"uid"`
	GID     int       `json:"gid"`
	Session string    `json:"session,omitempty"`
	TS      time.Time `json:"ts"`
}

type Options struct {
	// DrainDelay is only used in tests to slow the drain goroutine so the queue can fill.
	DrainDelay time.Duration
	// DisableWorker skips starting the async goroutine; Close will drain synchronously.
	// Intended for deterministic tests.
	DisableWorker bool
}

// Logger is a bounded async jsonl sink.
type Logger struct {
	events     chan Event
	dropOldest bool

	writerClose func() error
	enc         *json.Encoder

	err       atomic.Value
	wg        sync.WaitGroup
	closeOnce sync.Once

	opts Options
}

// New creates a Logger writing to the given path. If dropOldest is true, events are enqueued
// by evicting the oldest when the buffer is full; otherwise Log returns ErrQueueFull.
func New(path string, maxQueue int, dropOldest bool) (*Logger, error) {
	return NewWithOptions(path, maxQueue, dropOldest, Options{})
}

// NewWithOptions allows injecting test options.
func NewWithOptions(path string, maxQueue int, dropOldest bool, opts Options) (*Logger, error) {
	if maxQueue <= 0 {
		return nil, fmt.Errorf("maxQueue must be > 0")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriter(f)

	l := &Logger{
		events:     make(chan Event, maxQueue),
		dropOldest: dropOldest,
		writerClose: func() error {
			if err := w.Flush(); err != nil {
				_ = f.Close()
				return err
			}
			return f.Close()
		},
		enc:  json.NewEncoder(w),
		opts: opts,
	}

	l.wg.Add(1)
	if !opts.DisableWorker {
		go func() {
			defer l.wg.Done()
			for ev := range l.events {
				if opts.DrainDelay > 0 {
					time.Sleep(opts.DrainDelay)
				}
				if err := l.enc.Encode(ev); err != nil {
					l.err.Store(err)
					continue
				}
			}
		}()
	} else {
		l.wg.Done() // no goroutine; mark done for Close wait
	}

	return l, nil
}

// Log enqueues an event. It sets PID/UID/GID/TS if not already set.
func (l *Logger) Log(ev Event) error {
	if err := l.getErr(); err != nil {
		return err
	}
	if ev.PID == 0 {
		ev.PID = os.Getpid()
	}
	if ev.UID == 0 {
		ev.UID = currentUID()
	}
	if ev.GID == 0 {
		ev.GID = currentGID()
	}
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}

	select {
	case l.events <- ev:
		return nil
	default:
		if l.dropOldest {
			select {
			case <-l.events:
			default:
			}
			select {
			case l.events <- ev:
				return nil
			default:
				return ErrQueueFull
			}
		}
		return ErrQueueFull
	}
}

// Close waits for the queue to drain and closes the writer.
func (l *Logger) Close() error {
	var closeErr error
	l.closeOnce.Do(func() {
		close(l.events)
		if l.opts.DisableWorker {
			for ev := range l.events {
				if err := l.enc.Encode(ev); err != nil && closeErr == nil {
					closeErr = err
				}
			}
		} else {
			l.wg.Wait()
		}
		if err := l.writerClose(); err != nil {
			closeErr = err
		}
		if err := l.getErr(); err != nil && closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}

func (l *Logger) getErr() error {
	if v := l.err.Load(); v != nil {
		if err, ok := v.(error); ok {
			return err
		}
	}
	return nil
}

func currentUID() int {
	u, err := user.Current()
	if err != nil {
		return -1
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1
	}
	return uid
}

func currentGID() int {
	u, err := user.Current()
	if err != nil {
		return -1
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return -1
	}
	return gid
}
