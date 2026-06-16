package transport

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsAuthReject(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unauthenticated", status.Error(codes.Unauthenticated, "bad key"), true},
		{"permission denied", status.Error(codes.PermissionDenied, "revoked"), true},
		{"wrapped sentinel", fmt.Errorf("dial (%w): x", ErrAuthRejected), true},
		{"unavailable is transient", status.Error(codes.Unavailable, "down"), false},
		{"plain error", errors.New("connection reset"), false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsAuthReject(tc.err); got != tc.want {
				t.Fatalf("IsAuthReject(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestBackoffClampToMax(t *testing.T) {
	t.Parallel()
	bo := NewBackoff(BackoffOptions{Initial: time.Millisecond, Max: 10 * time.Second, Factor: 2})
	bo.ClampToMax()
	d := bo.Next()
	// Next applies [0.5,1.5) jitter to current (== Max after clamp).
	if d < 5*time.Second || d >= 15*time.Second {
		t.Fatalf("after ClampToMax, Next() = %v, want ~10s ±jitter", d)
	}
}

func TestBackoffAfterConnectError(t *testing.T) {
	t.Parallel()
	tr := &Transport{}

	boAuth := NewBackoff(BackoffOptions{Initial: time.Millisecond, Max: 10 * time.Second, Factor: 2})
	dAuth := tr.backoffAfterConnectError(boAuth, fmt.Errorf("dial (%w): x", ErrAuthRejected))
	if dAuth < 5*time.Second || dAuth >= 15*time.Second {
		t.Fatalf("auth-reject backoff = %v, want clamped ~10s", dAuth)
	}

	boTransient := NewBackoff(BackoffOptions{Initial: 100 * time.Millisecond, Max: 10 * time.Second, Factor: 2})
	dTransient := tr.backoffAfterConnectError(boTransient, errors.New("connection reset"))
	if dTransient < 50*time.Millisecond || dTransient >= 150*time.Millisecond {
		t.Fatalf("transient backoff = %v, want ~Initial 100ms ±jitter", dTransient)
	}
}
