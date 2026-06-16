package transport

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/metrics"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRunConnecting_AuthRejectFromRecv(t *testing.T) {
	t.Parallel()
	fm := &fakeMetrics{}
	fc := &internalFakeConn{recvErr: status.Error(codes.Unauthenticated, "bad key")}
	tr, err := New(Options{
		Dialer:    DialerFunc(func(context.Context) (Conn, error) { return fc, nil }),
		AgentID:   "a",
		SessionID: "s",
		Metrics:   fm,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	st, err := tr.RunOnce(ctx, StateConnecting)
	if st != StateConnecting {
		t.Fatalf("state = %s, want StateConnecting", st)
	}
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("err = %v, want errors.Is ErrAuthRejected", err)
	}
	if !containsReason(fm.sessionInitFailureReasons, "auth_rejected") {
		t.Fatalf("session-init-failure reasons = %v, want auth_rejected", fm.sessionInitFailureReasons)
	}
}

func TestRunConnecting_AuthRejectFromDial(t *testing.T) {
	t.Parallel()
	fm := &fakeMetrics{}
	tr, err := New(Options{
		Dialer: DialerFunc(func(context.Context) (Conn, error) {
			return nil, status.Error(codes.PermissionDenied, "revoked")
		}),
		AgentID:   "a",
		SessionID: "s",
		Metrics:   fm,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	st, err := tr.RunOnce(ctx, StateConnecting)
	if st != StateConnecting {
		t.Fatalf("state = %s, want StateConnecting", st)
	}
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("err = %v, want errors.Is ErrAuthRejected", err)
	}
	if !containsReason(fm.sessionInitFailureReasons, "auth_rejected") {
		t.Fatalf("reasons = %v, want auth_rejected", fm.sessionInitFailureReasons)
	}
}

func containsReason(rs []metrics.WTPSessionFailureReason, want string) bool {
	for _, r := range rs {
		if string(r) == want {
			return true
		}
	}
	return false
}
