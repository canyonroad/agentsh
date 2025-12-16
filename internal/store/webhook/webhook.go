package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

type Store struct {
	url           string
	batchSize     int
	flushInterval time.Duration
	timeout       time.Duration
	headers       map[string]string

	client *http.Client

	mu        sync.Mutex
	buf       []types.Event
	lastFlush time.Time
	closed    bool
}

func New(url string, batchSize int, flushInterval time.Duration, timeout time.Duration, headers map[string]string) (*Store, error) {
	if url == "" {
		return nil, fmt.Errorf("webhook url is empty")
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	if flushInterval <= 0 {
		flushInterval = 10 * time.Second
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	hcopy := map[string]string{}
	for k, v := range headers {
		hcopy[k] = v
	}
	return &Store{
		url:           url,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		timeout:       timeout,
		headers:       hcopy,
		client:        &http.Client{Timeout: timeout},
		lastFlush:     time.Now().UTC(),
	}, nil
}

func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
	var toFlush []types.Event

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("webhook store closed")
	}
	s.buf = append(s.buf, ev)
	now := time.Now().UTC()
	shouldFlush := len(s.buf) >= s.batchSize || (s.flushInterval > 0 && now.Sub(s.lastFlush) >= s.flushInterval)
	if shouldFlush {
		toFlush = append([]types.Event(nil), s.buf...)
		s.buf = nil
		s.lastFlush = now
	}
	s.mu.Unlock()

	if len(toFlush) == 0 {
		return nil
	}
	return s.flush(ctx, toFlush)
}

func (s *Store) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, fmt.Errorf("webhook store does not support queries")
}

func (s *Store) Close() error {
	var toFlush []types.Event
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if len(s.buf) > 0 {
		toFlush = append([]types.Event(nil), s.buf...)
		s.buf = nil
	}
	s.mu.Unlock()

	if len(toFlush) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	return s.flush(ctx, toFlush)
}

func (s *Store) flush(ctx context.Context, batch []types.Event) error {
	b, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook responded %s", resp.Status)
	}
	return nil
}
