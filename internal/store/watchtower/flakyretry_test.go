package watchtower_test

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// flakyTestT wraps a testing.TB to capture Fatalf/Errorf messages
// without failing the outer test, so a retry harness can decide whether
// the failure matches a known-flake fingerprint and re-run.
//
// Methods that DON'T fail or log assertion data (Helper, TempDir,
// Cleanup, Logf, Name, etc.) pass through to the embedded testing.TB
// unchanged. The body of a retried test must use t.Cleanup-via-defer
// for per-attempt teardown — anything registered through t.Cleanup on
// the embedded TB runs once at end-of-parent-test, not per-attempt, so
// it WILL leak resources across retries if used inside the body.
//
// Embedding testing.TB (not *testing.T) lets flakyTestT itself satisfy
// the testing.TB interface (including TB's unexported private() method)
// via method promotion. The retry body therefore takes a testing.TB
// parameter rather than *testing.T.
type flakyTestT struct {
	testing.TB
	mu     sync.Mutex
	errors []string
}

// Errorf captures the message without marking the embedded T failed.
// retryFlake inspects ft.errors afterwards.
func (f *flakyTestT) Errorf(format string, args ...interface{}) {
	f.mu.Lock()
	f.errors = append(f.errors, fmt.Sprintf(format, args...))
	f.mu.Unlock()
}

// Fatalf captures the message then exits the body goroutine via
// Goexit. Deferred cleanups in the body still run. retryFlake decides
// based on the captured message whether this is a known flake.
func (f *flakyTestT) Fatalf(format string, args ...interface{}) {
	f.mu.Lock()
	f.errors = append(f.errors, fmt.Sprintf(format, args...))
	f.mu.Unlock()
	runtime.Goexit()
}

// Fatal mirrors Fatalf for the no-format case.
func (f *flakyTestT) Fatal(args ...interface{}) {
	f.mu.Lock()
	f.errors = append(f.errors, fmt.Sprint(args...))
	f.mu.Unlock()
	runtime.Goexit()
}

// Error mirrors Errorf for the no-format case.
func (f *flakyTestT) Error(args ...interface{}) {
	f.mu.Lock()
	f.errors = append(f.errors, fmt.Sprint(args...))
	f.mu.Unlock()
}

// Failed reports whether any error/fatal message was captured.
func (f *flakyTestT) Failed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.errors) > 0
}

// FailNow exits the body without recording a message. retryFlake
// treats this as a non-flake failure (no fingerprint to match).
func (f *flakyTestT) FailNow() {
	f.mu.Lock()
	f.errors = append(f.errors, "FailNow called")
	f.mu.Unlock()
	runtime.Goexit()
}

// isKnownWTPTransportLossFlake reports whether msg matches the
// fingerprint of the known timing-flake family in the watchtower
// integration tests: any of the testserver.WaitFor* polling helpers
// times out under CI load while the watchtower itself logged the
// expected event as emitted. See project_wtp_transportloss_flakes
// memory and PRs #265 / #266.
//
// Three helper-shapes count as flake fingerprints:
//   - WaitForTransportLoss: deadline N elapsed
//   - WaitForFirstSessionInit: deadline N elapsed
//   - WaitForSessionInits: want N, got M after Ts
//
// All three are time-based polls on testserver state. None is a
// correctness contract — the watchtower's own behavior is verified
// elsewhere. Only failures matching one of these shapes are
// retry-eligible; any other Fatalf/Errorf is a genuine regression and
// propagates.
func isKnownWTPTransportLossFlake(msg string) bool {
	switch {
	case strings.Contains(msg, "WaitForTransportLoss") && strings.Contains(msg, "deadline"):
		return true
	case strings.Contains(msg, "WaitForFirstSessionInit") && strings.Contains(msg, "deadline"):
		return true
	case strings.Contains(msg, "WaitForSessionInits") && strings.Contains(msg, "got"):
		return true
	}
	return false
}

// retryFlake runs body up to maxAttempts times against a flakyTestT
// that captures Fatalf/Errorf without failing the outer test. If body
// fails with EVERY captured message matching the
// isKnownWTPTransportLossFlake fingerprint, retryFlake reruns body
// (with fresh resources owned by the body itself via defer). If body
// fails with any non-flake error, the first such error is escalated
// as the outer test's failure immediately — no retry.
//
// On success, retryFlake returns normally. On exhausted retries, it
// fails the outer test with the last captured flake message.
//
// IMPORTANT: body MUST manage its own per-attempt teardown via defer.
// t.Cleanup calls inside body register on the OUTER test and won't
// fire between attempts. Use defer for closing servers, watchtowers,
// and any other per-attempt resources.
//
// body's argument is testing.TB, not *testing.T, because flakyTestT
// satisfies testing.TB (via embedding) but cannot satisfy *testing.T
// (Go has no inheritance). Tests that need *testing.T-specific methods
// like Run/Parallel should keep them at the outer level, outside
// retryFlake.
func retryFlake(t *testing.T, maxAttempts int, body func(t testing.TB)) {
	t.Helper()
	var lastMessages []string
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ft := &flakyTestT{TB: t}
		done := make(chan struct{})
		go func() {
			defer close(done)
			body(ft)
		}()
		<-done

		if !ft.Failed() {
			if attempt > 1 {
				t.Logf("retryFlake: passed on attempt %d (after %d known-flake retries)", attempt, attempt-1)
			}
			return
		}

		lastMessages = ft.errors
		allFlake := true
		for _, msg := range lastMessages {
			if !isKnownWTPTransportLossFlake(msg) {
				allFlake = false
				break
			}
		}
		if !allFlake {
			t.Fatalf("retryFlake attempt %d failed (not a known flake): %s",
				attempt, strings.Join(lastMessages, "; "))
		}
		if attempt < maxAttempts {
			t.Logf("retryFlake: attempt %d hit known WTP transport-loss flake, retrying (see project_wtp_transportloss_flakes memory)", attempt)
		}
	}
	t.Fatalf("retryFlake: all %d attempts hit the known WTP transport-loss flake. Last messages: %s",
		maxAttempts, strings.Join(lastMessages, "; "))
}
