package watchtower_test

// TestOptions_LogGoawayMessage_WireThrough verifies that
// watchtower.Options.LogGoawayMessage is threaded into the Store and
// accessible via the test-only OptsLogGoawayMessageForTest accessor.
// This guards the watchtower.Options → transport.Options wiring path
// added in Task 27b.
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

			got := s.OptsLogGoawayMessageForTest()
			if got != tc.value {
				t.Errorf("OptsLogGoawayMessageForTest() = %v, want %v", got, tc.value)
			}
		})
	}
}
