package provider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryClient_Retries5xxThenSucceeds(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	c := newRetryClient(retryConfig{
		MaxAttempts: 5,
		BaseBackoff: 1 * time.Millisecond,
		MaxBackoff:  10 * time.Millisecond,
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("want 3 attempts, got %d", got)
	}
}

func TestRetryClient_RespectsRetryAfterHeader(t *testing.T) {
	start := time.Now()
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newRetryClient(retryConfig{
		MaxAttempts:       3,
		BaseBackoff:       1 * time.Millisecond,
		MaxBackoff:        10 * time.Second,
		RespectRetryAfter: true,
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	elapsed := time.Since(start)
	if elapsed < 900*time.Millisecond {
		t.Fatalf("expected ~1s wait for Retry-After, got %v", elapsed)
	}
}

func TestRetryClient_GivesUpAfterMaxAttempts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newRetryClient(retryConfig{MaxAttempts: 3, BaseBackoff: 1 * time.Millisecond, MaxBackoff: 5 * time.Millisecond})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, strings.NewReader(""))
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected error after max attempts, got nil")
	}
}
