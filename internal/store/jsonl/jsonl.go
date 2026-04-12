package jsonl

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/agentsh/agentsh/pkg/types"
)

// PartialWriteError indicates a write failed and partial data may remain
// on disk because truncate also failed. Callers must NOT assume rollback
// is safe when they receive this error. Use IsPartialWrite() to detect.
type PartialWriteError struct {
	WriteErr    error
	TruncateErr error
}

func (e *PartialWriteError) Error() string {
	return "partial write: " + e.WriteErr.Error() + " (truncate failed: " + e.TruncateErr.Error() + ")"
}

func (e *PartialWriteError) Unwrap() error { return e.WriteErr }

// IsPartialWrite implements the interface checked by IntegrityStore.
func (e *PartialWriteError) IsPartialWrite() bool { return true }

// DurabilityError indicates bytes were appended but could not be confirmed
// durable, so callers must treat the write as potentially visible on disk.
type DurabilityError struct {
	Err error
}

func (e *DurabilityError) Error() string { return "durability error: " + e.Err.Error() }
func (e *DurabilityError) Unwrap() error { return e.Err }
func (e *DurabilityError) IsPartialWrite() bool { return true }

type Store struct {
	path       string
	maxBytes   int64
	maxBackups int

	mu       sync.Mutex
	file     *os.File
	lockFile *os.File
}

func New(path string, maxSizeMB int, maxBackups int) (*Store, error) {
	lockFile, err := AcquireLock(path)
	if err != nil {
		return nil, fmt.Errorf("lock jsonl: %w", err)
	}
	store, err := NewWithLock(path, maxSizeMB, maxBackups, lockFile)
	if err != nil {
		_ = ReleaseLock(lockFile)
		return nil, err
	}
	return store, nil
}

func NewWithLock(path string, maxSizeMB int, maxBackups int, lockFile *os.File) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("jsonl path is empty")
	}
	if lockFile == nil {
		return nil, fmt.Errorf("jsonl lock file is nil")
	}
	if maxSizeMB <= 0 {
		maxSizeMB = 100
	}
	if maxBackups <= 0 {
		maxBackups = 3
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir log dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open jsonl: %w", err)
	}

	return &Store{
		path:       path,
		maxBytes:   int64(maxSizeMB) * 1024 * 1024,
		maxBackups: maxBackups,
		file:       f,
		lockFile:   lockFile,
	}, nil
}

func (s *Store) AppendEvent(_ context.Context, ev types.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.rotateIfNeededLocked(); err != nil {
		return err
	}

	b, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if _, err := s.file.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write jsonl: %w", err)
	}
	return nil
}

// WriteRaw writes pre-serialized bytes as a single JSONL line.
// It uses the same locking and rotation logic as AppendEvent.
// On write failure, it attempts to truncate back to the pre-write size.
// If truncate succeeds, a normal error is returned and callers may safely
// roll back chain state. If truncate fails, a PartialWriteError is returned
// and callers must NOT roll back (partial data may be on disk).
func (s *Store) WriteRaw(_ context.Context, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.rotateIfNeededLocked(); err != nil {
		return err
	}

	// Record file size before write so we can truncate on failure.
	// We use Stat rather than Seek because the file is opened with O_APPEND.
	st, err := s.file.Stat()
	if err != nil {
		return fmt.Errorf("write jsonl raw stat: %w", err)
	}
	preSize := st.Size()

	buf := make([]byte, len(data)+1)
	copy(buf, data)
	buf[len(data)] = '\n'
	n, writeErr := s.file.Write(buf)
	if writeErr != nil || n != len(buf) {
		if writeErr == nil {
			writeErr = fmt.Errorf("short write (%d/%d bytes)", n, len(buf))
		}
		// Truncate back to remove any partial data.
		if truncErr := s.file.Truncate(preSize); truncErr != nil {
			return &PartialWriteError{WriteErr: writeErr, TruncateErr: truncErr}
		}
		return fmt.Errorf("write jsonl raw: %w", writeErr)
	}
	if err := s.file.Sync(); err != nil {
		return &DurabilityError{Err: fmt.Errorf("sync jsonl raw: %w", err)}
	}
	return nil
}

func (s *Store) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, fmt.Errorf("jsonl store does not support queries")
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	if s.file != nil {
		if err := s.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.file = nil
	}
	if s.lockFile != nil {
		if err := ReleaseLock(s.lockFile); err != nil && firstErr == nil {
			firstErr = err
		}
		s.lockFile = nil
	}
	return firstErr
}

func (s *Store) rotateIfNeededLocked() error {
	if s.file == nil {
		return fmt.Errorf("jsonl file not open")
	}
	st, err := s.file.Stat()
	if err != nil {
		return fmt.Errorf("stat jsonl: %w", err)
	}
	if st.Size() < s.maxBytes {
		return nil
	}
	if err := s.file.Close(); err != nil {
		return fmt.Errorf("close for rotate: %w", err)
	}

	for i := s.maxBackups - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", s.path, i)
		to := fmt.Sprintf("%s.%d", s.path, i+1)
		if _, err := os.Stat(from); err == nil {
			_ = os.Rename(from, to)
		}
	}
	_ = os.Rename(s.path, fmt.Sprintf("%s.1", s.path))

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("reopen jsonl: %w", err)
	}
	s.file = f
	return nil
}
