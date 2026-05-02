package provider

import (
	"context"
	"errors"
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

func TestRetryClient_AbortsOnContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newRetryClient(retryConfig{
		MaxAttempts: 5,
		BaseBackoff: 200 * time.Millisecond,
		MaxBackoff:  500 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)

	start := time.Now()
	_, err := c.Do(req)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected error chain to include context.Canceled, got: %v", err)
	}
	// Cancellation must NOT be classified as max-attempts exhaustion.
	if errors.Is(err, errMaxAttempts) {
		t.Errorf("cancellation should not wrap errMaxAttempts, got: %v", err)
	}
	// Should abort well before doing 5 attempts × 200ms+ each.
	if elapsed > 600*time.Millisecond {
		t.Errorf("retry loop did not abort promptly on ctx cancel; elapsed=%v", elapsed)
	}
}

func TestRetryClient_GivesUp_WrapsErrMaxAttempts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newRetryClient(retryConfig{MaxAttempts: 2, BaseBackoff: 1 * time.Millisecond, MaxBackoff: 5 * time.Millisecond})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	_, err := c.Do(req)
	if !errors.Is(err, errMaxAttempts) {
		t.Fatalf("expected error chain to include errMaxAttempts, got: %v", err)
	}
}

func TestCircuitBreaker_OpensAfterConsecutiveFailures(t *testing.T) {
	cb := newCircuitBreaker(circuitBreakerConfig{
		Threshold:  3,
		Window:     time.Second,
		OpenPeriod: 100 * time.Millisecond,
	})

	if !cb.Allow() {
		t.Fatal("breaker should start closed")
	}
	cb.RecordFailure()
	cb.RecordFailure()
	if !cb.Allow() {
		t.Fatal("breaker should still be closed after 2 failures")
	}
	cb.RecordFailure()
	if cb.Allow() {
		t.Fatal("breaker should be open after 3 failures")
	}
}

func TestCircuitBreaker_ClosesAfterOpenPeriod(t *testing.T) {
	cb := newCircuitBreaker(circuitBreakerConfig{
		Threshold:  2,
		Window:     time.Second,
		OpenPeriod: 50 * time.Millisecond,
	})
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.Allow() {
		t.Fatal("breaker should be open")
	}
	time.Sleep(80 * time.Millisecond)
	if !cb.Allow() {
		t.Fatal("breaker should re-close after open period")
	}
}

func TestCircuitBreaker_SuccessResetsFailures(t *testing.T) {
	cb := newCircuitBreaker(circuitBreakerConfig{
		Threshold:  3,
		Window:     time.Second,
		OpenPeriod: 100 * time.Millisecond,
	})
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()
	cb.RecordFailure()
	cb.RecordFailure()
	if !cb.Allow() {
		t.Fatal("breaker should still be closed: success reset failure count")
	}
}

func TestCallWithBreaker_ShortCircuitsWhenOpen(t *testing.T) {
	cb := newCircuitBreaker(circuitBreakerConfig{
		Threshold:  2,
		Window:     time.Second,
		OpenPeriod: 100 * time.Millisecond,
	})

	// Trip the breaker by recording two failures.
	calls := 0
	failing := func() error { calls++; return errors.New("boom") }
	_ = callWithBreaker(cb, failing)
	_ = callWithBreaker(cb, failing)
	if calls != 2 {
		t.Fatalf("want 2 fn invocations, got %d", calls)
	}

	// Now the breaker is open — fn must not be called.
	err := callWithBreaker(cb, failing)
	if !errors.Is(err, errBreakerOpen) {
		t.Errorf("expected errBreakerOpen, got %v", err)
	}
	if calls != 2 {
		t.Errorf("fn must not have been invoked while breaker is open; calls=%d", calls)
	}
}

func TestCallWithBreaker_RecordsSuccessAndError(t *testing.T) {
	cb := newCircuitBreaker(circuitBreakerConfig{
		Threshold:  3,
		Window:     time.Second,
		OpenPeriod: 100 * time.Millisecond,
	})
	if err := callWithBreaker(cb, func() error { return nil }); err != nil {
		t.Fatalf("success path returned error: %v", err)
	}
	want := errors.New("boom")
	got := callWithBreaker(cb, func() error { return want })
	if !errors.Is(got, want) {
		t.Errorf("error path should return fn's error, got %v", got)
	}
}

func TestCallWithBreaker_NilBreakerPassesThrough(t *testing.T) {
	calls := 0
	err := callWithBreaker(nil, func() error { calls++; return nil })
	if err != nil {
		t.Errorf("nil breaker should not error, got %v", err)
	}
	if calls != 1 {
		t.Errorf("fn should have run; calls=%d", calls)
	}
}

func TestRetryClient_CtxCancelOnFinalAttemptIsNotMaxAttempts(t *testing.T) {
	// Server always returns 500 so every attempt is a retry trigger.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// We need the cancellation to land BEFORE Do reaches its final return.
	// A timing-based goroutine is racy; instead, the handler blocks the
	// second (final) response on a channel that the test closes only after
	// cancel() has been called. This makes the ordering deterministic:
	//   1. First request → 500 (no block).
	//   2. Loop sleeps backoff, second request lands.
	//   3. Test closes secondReady, handler returns 500.
	//   4. Loop reaches final-return, ctx.Err() is non-nil → aborted, not max.
	srvHits := make(chan struct{}, 4)
	secondReady := make(chan struct{})
	var hitCount int32
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hitCount, 1)
		srvHits <- struct{}{}
		if n == 2 {
			<-secondReady
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv2.Close()

	c := newRetryClient(retryConfig{
		MaxAttempts: 2,
		BaseBackoff: 50 * time.Millisecond,
		MaxBackoff:  100 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv2.URL, nil)

	go func() {
		<-srvHits         // first attempt landed at server
		<-srvHits         // second (final) attempt landed; handler is blocked
		cancel()          // ensure ctx is cancelled before final return reads ctx.Err()
		close(secondReady) // unblock handler so client.Do returns 500
	}()

	_, err := c.Do(req)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled in chain, got %v", err)
	}
	if errors.Is(err, errMaxAttempts) {
		t.Errorf("ctx cancel on final attempt must not be classified as max-attempts; got %v", err)
	}
}

func TestCallWithBreaker_DoesNotRecordCallerCancellation(t *testing.T) {
	cb := newCircuitBreaker(circuitBreakerConfig{
		Threshold:  2,
		Window:     time.Second,
		OpenPeriod: 100 * time.Millisecond,
	})
	// Record one real failure so we're one short of opening.
	_ = callWithBreaker(cb, func() error { return errors.New("real failure") })

	// Now return a ctx-cancel error N times — the breaker must NOT open.
	for i := 0; i < 5; i++ {
		err := callWithBreaker(cb, func() error { return context.Canceled })
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d: want context.Canceled, got %v", i, err)
		}
	}
	if !cb.Allow() {
		t.Fatal("breaker must not have opened from caller-driven cancellations")
	}
}

func TestCallWithBreaker_DoesNotRecordDeadlineExceeded(t *testing.T) {
	cb := newCircuitBreaker(circuitBreakerConfig{
		Threshold:  2,
		Window:     time.Second,
		OpenPeriod: 100 * time.Millisecond,
	})
	_ = callWithBreaker(cb, func() error { return errors.New("real failure") })
	for i := 0; i < 5; i++ {
		_ = callWithBreaker(cb, func() error { return context.DeadlineExceeded })
	}
	if !cb.Allow() {
		t.Fatal("breaker must not have opened from caller-driven deadline-exceeded")
	}
}
