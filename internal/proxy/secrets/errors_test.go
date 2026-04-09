package secrets

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelErrors_AreDistinct(t *testing.T) {
	sentinels := []error{
		ErrNotFound,
		ErrUnauthorized,
		ErrInvalidURI,
		ErrUnsupportedScheme,
		ErrFieldNotSupported,
		ErrKeyringUnavailable,
		ErrCyclicDependency,
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("sentinel %d (%v) should not be errors.Is %d (%v)", i, a, j, b)
			}
		}
	}
}

func TestSentinelErrors_AreWrappable(t *testing.T) {
	sentinels := map[string]error{
		"ErrNotFound":           ErrNotFound,
		"ErrUnauthorized":       ErrUnauthorized,
		"ErrInvalidURI":         ErrInvalidURI,
		"ErrUnsupportedScheme":  ErrUnsupportedScheme,
		"ErrFieldNotSupported":  ErrFieldNotSupported,
		"ErrKeyringUnavailable": ErrKeyringUnavailable,
		"ErrCyclicDependency":   ErrCyclicDependency,
	}
	for name, sentinel := range sentinels {
		wrapped := fmt.Errorf("%w: context detail", sentinel)
		if !errors.Is(wrapped, sentinel) {
			t.Errorf("%s: wrapped error is not errors.Is the sentinel", name)
		}
	}
}

func TestSentinelErrors_MessagesStartWithPrefix(t *testing.T) {
	sentinels := []error{
		ErrNotFound,
		ErrUnauthorized,
		ErrInvalidURI,
		ErrUnsupportedScheme,
		ErrFieldNotSupported,
		ErrKeyringUnavailable,
		ErrCyclicDependency,
	}
	const prefix = "secrets:"
	for _, s := range sentinels {
		msg := s.Error()
		if len(msg) < len(prefix) || msg[:len(prefix)] != prefix {
			t.Errorf("sentinel %q should start with %q", msg, prefix)
		}
	}
}
