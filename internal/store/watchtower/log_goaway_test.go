package watchtower_test

// TestOptions_LogGoawayMessage_WireThrough verifies that
// watchtower.Options.LogGoawayMessage is threaded into the Store and
// flows all the way to the Transport via transport.New.
//
// Two assertions are made:
//  1. OptsLogGoawayMessageForTest: the watchtower.Options copy is set
//     correctly (guards buildWatchtowerStore → watchtower.Options).
//  2. TransportLogGoawayMessageForTest: the Transport's resolved value
//     matches (guards the store.go hop: watchtower.Options →
//     transport.New call). If store.go ever stops threading
//     opts.LogGoawayMessage into transport.New, the Transport's field
//     stays at its zero value (false), causing the second assertion to
//     fail even when the first passes.
//
// The test uses a nopDialer so the bg goroutine runs but never
// connects; closeStore handles the bounded-deadline shutdown.

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/store/watchtower"
)

func TestOptions_LogGoawayMessage_WireThrough(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value bool
	}{
		{"false", false},
		{"true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := validOpts(t.TempDir())
			opts.LogGoawayMessage = tc.value

			s, err := watchtower.New(context.Background(), opts)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer closeStore(t, s)

			// Assertion 1: the watchtower.Options copy was set.
			got := s.OptsLogGoawayMessageForTest()
			if got != tc.value {
				t.Errorf("OptsLogGoawayMessageForTest() = %v, want %v", got, tc.value)
			}

			// Assertion 2: the value was wired through to the Transport.
			// This assertion fails if store.go stops passing
			// opts.LogGoawayMessage to transport.New — even if
			// Assertion 1 still passes.
			gotTr := s.TransportLogGoawayMessageForTest()
			if gotTr != tc.value {
				t.Errorf("TransportLogGoawayMessageForTest() = %v, want %v (wire-through to transport.New regressed)", gotTr, tc.value)
			}
		})
	}
}

