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

type Store struct {
	path       string
	maxBytes   int64
	maxBackups int

	mu   sync.Mutex
	file *os.File
}

func New(path string, maxSizeMB int, maxBackups int) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("jsonl path is empty")
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

func (s *Store) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, fmt.Errorf("jsonl store does not support queries")
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
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

