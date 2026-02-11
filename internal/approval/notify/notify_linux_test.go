//go:build linux

package notify

import (
	"context"
	"testing"
	"time"
)

func TestHasNotifyBackend(t *testing.T) {
	// Smoke test — should not panic regardless of whether notify-send is installed
	result := hasNotifyBackend()
	t.Logf("hasNotifyBackend() = %v", result)
}

func TestShowNative_Timeout(t *testing.T) {
	if !hasNotifyBackend() {
		t.Skip("notify-send not available")
	}
	if IsCI() {
		t.Skip("skipping notification test in CI")
	}

	// Context with immediate timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Give the timeout a moment to fire
	time.Sleep(5 * time.Millisecond)

	req := Request{
		Title:      "Test Notification",
		Message:    "This should time out immediately",
		AllowLabel: "Allow",
		DenyLabel:  "Deny",
		Urgency:    "low",
	}

	resp, err := showNative(ctx, req)
	if err == nil {
		t.Logf("unexpected nil error, response: %+v", resp)
		return
	}

	if !resp.TimedOut {
		t.Errorf("expected TimedOut=true, got %+v", resp)
	}
}

func TestShowNative_NoBackend(t *testing.T) {
	// This test is meaningful when notify-send is NOT installed
	if hasNotifyBackend() {
		t.Skip("notify-send is available — testing no-backend path requires it to be absent")
	}

	req := Request{
		Title:      "Test",
		Message:    "Should fail",
		AllowLabel: "Allow",
		DenyLabel:  "Deny",
		Urgency:    "normal",
	}

	_, err := showNative(context.Background(), req)
	if err != ErrNoBackend {
		t.Errorf("expected ErrNoBackend, got %v", err)
	}
}
