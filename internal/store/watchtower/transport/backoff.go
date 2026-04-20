package transport

import (
	"math/rand/v2"
	"time"
)

// BackoffOptions configures exponential backoff with jitter.
type BackoffOptions struct {
	Initial time.Duration
	Max     time.Duration
	Factor  float64
}

// Backoff computes per-attempt sleep durations.
type Backoff struct {
	opts    BackoffOptions
	current time.Duration
}

// NewBackoff returns a Backoff at its initial value.
func NewBackoff(opts BackoffOptions) *Backoff {
	if opts.Factor <= 1 {
		opts.Factor = 2.0
	}
	return &Backoff{opts: opts, current: opts.Initial}
}

// Next returns the next sleep duration, applying [0.5, 1.5) jitter and
// growing the underlying value (pre-jitter) exponentially up to Max.
func (b *Backoff) Next() time.Duration {
	base := b.current
	jitter := 0.5 + rand.Float64()
	d := time.Duration(float64(base) * jitter)

	// Advance for next call.
	next := time.Duration(float64(b.current) * b.opts.Factor)
	if next > b.opts.Max {
		next = b.opts.Max
	}
	b.current = next
	return d
}

// Reset returns the backoff to its initial value.
func (b *Backoff) Reset() { b.current = b.opts.Initial }
