package transport

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRunLoop_AuthRejectClampsBackoff verifies that when the dialer
// always returns an Unauthenticated error the Run loop sleeps for the
// clamped BackoffMax between retries rather than using the fast
// exponential ramp. With BackoffInitial=1ms and BackoffMax=30s, an
// un-clamped loop would produce many dials within 300ms; a correctly
// clamped loop must produce exactly one.
func TestRunLoop_AuthRejectClampsBackoff(t *testing.T) {
	t.Parallel()
	var dials atomic.Int32
	tr, err := New(Options{
		Dialer: DialerFunc(func(context.Context) (Conn, error) {
			dials.Add(1)
			return nil, status.Error(codes.Unauthenticated, "bad key")
		}),
		AgentID:        "a",
		SessionID:      "s",
		BackoffInitial: time.Millisecond, // would fast-retry many times if NOT clamped
		BackoffMax:     30 * time.Second, // clamp target — no 2nd dial in our window
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	// rdrFactory is never called because the dialer always fails before
	// reaching Replaying/Live; pass a nil-returning stub.
	rdrFactory := func(uint32, uint64) (*wal.Reader, error) {
		t.Fatal("rdrFactory called; Run should not reach Replaying/Live under auth-reject")
		return nil, nil
	}
	go func() {
		done <- tr.Run(ctx, rdrFactory, LiveOptions{
			Batcher: BatcherOptions{
				MaxRecords: 100,
				MaxBytes:   1 << 16,
				MaxAge:     50 * time.Millisecond,
			},
			MaxInflight:    8,
			HeartbeatEvery: time.Second,
		})
	}()

	// With clamping, the first dial fires immediately, then the loop
	// sleeps ~BackoffMax (30s). Within 300ms there must be exactly one
	// dial. Without clamping, the 1ms initial backoff would produce many.
	time.Sleep(300 * time.Millisecond)
	got := dials.Load()
	cancel()
	<-done

	if got != 1 {
		t.Fatalf("dials in 300ms = %d, want 1 (backoff should be clamped to max on auth-reject)", got)
	}
}
