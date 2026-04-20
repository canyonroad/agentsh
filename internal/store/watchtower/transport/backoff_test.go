package transport_test

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// TestBackoff_ExponentialWithJitter verifies the per-attempt sleep grows
// exponentially up to a cap, with jitter inside [0.5x, 1.5x).
func TestBackoff_ExponentialWithJitter(t *testing.T) {
	b := transport.NewBackoff(transport.BackoffOptions{
		Initial: 100 * time.Millisecond,
		Max:     5 * time.Second,
		Factor:  2.0,
	})
	prevMid := 100 * time.Millisecond
	for i := 0; i < 10; i++ {
		d := b.Next()
		if d < prevMid/2 {
			t.Fatalf("attempt %d below jitter floor: %v < %v", i, d, prevMid/2)
		}
		if d > 5*time.Second*15/10 {
			t.Fatalf("attempt %d above cap+jitter: %v", i, d)
		}
		if i > 0 && i < 6 {
			prevMid *= 2
		}
	}
}

func TestBackoff_ResetReturnsToInitial(t *testing.T) {
	b := transport.NewBackoff(transport.BackoffOptions{
		Initial: 200 * time.Millisecond,
		Max:     5 * time.Second,
		Factor:  2.0,
	})
	for i := 0; i < 5; i++ {
		_ = b.Next()
	}
	b.Reset()
	d := b.Next()
	if d > 300*time.Millisecond {
		t.Fatalf("after reset, got %v; expected ~initial", d)
	}
}
