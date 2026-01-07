package approvals

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakePrompt lets tests control prompt behavior without a real tty.
type fakePrompt struct {
	res   Resolution
	err   error
	delay time.Duration
}

func (f fakePrompt) call(ctx context.Context, req Request) (Resolution, error) {
	select {
	case <-ctx.Done():
		return Resolution{}, ctx.Err()
	case <-time.After(f.delay):
	}
	return f.res, f.err
}

func TestRequestApproval_ContextCancelUnblocksPrompt(t *testing.T) {
	m := New("local_tty", 5*time.Second, nil)
	fp := fakePrompt{delay: 100 * time.Second} // would hang without ctx
	m.prompt = fp.call

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	res, err := m.RequestApproval(ctx, Request{SessionID: "s1", Kind: "command", Target: "echo"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
	if res.Approved {
		t.Fatalf("expected denied due to cancel")
	}
}

func TestRequestApproval_TimesOut(t *testing.T) {
	m := New("local_tty", 100*time.Millisecond, nil)
	fp := fakePrompt{delay: 1 * time.Second}
	m.prompt = fp.call

	ctx := context.Background()
	res, err := m.RequestApproval(ctx, Request{SessionID: "s2", Kind: "command", Target: "sleep"})
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if res.Approved {
		t.Fatalf("expected denied on timeout")
	}
	if res.Reason == "" {
		t.Fatalf("expected reason to be set")
	}
}

func TestRequestApproval_PromptResultWins(t *testing.T) {
	m := New("local_tty", 5*time.Second, nil)
	fp := fakePrompt{delay: 10 * time.Millisecond, res: Resolution{Approved: true, Reason: "ok", At: time.Now()}}
	m.prompt = fp.call

	ctx := context.Background()
	res, err := m.RequestApproval(ctx, Request{SessionID: "s3", Kind: "command", Target: "echo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Approved {
		t.Fatalf("expected approval to pass through")
	}
}

func TestManagerTOTPMode(t *testing.T) {
	mgr := New("totp", 5*time.Second, nil)

	if mgr.mode != "totp" {
		t.Errorf("mode = %q, want totp", mgr.mode)
	}

	// Verify promptTOTP is set
	if mgr.prompt == nil {
		t.Error("prompt function not set")
	}
}

func TestManagerSetTOTPSecretLookup(t *testing.T) {
	mgr := New("totp", 5*time.Second, nil)

	called := false
	mgr.SetTOTPSecretLookup(func(sessionID string) string {
		called = true
		return "TESTSECRET"
	})

	// Verify the lookup was set
	if mgr.totpSecretLookup == nil {
		t.Error("totpSecretLookup not set")
	}

	// Call it to verify it works
	secret := mgr.totpSecretLookup("test-session")
	if !called {
		t.Error("lookup function not called")
	}
	if secret != "TESTSECRET" {
		t.Errorf("secret = %q, want TESTSECRET", secret)
	}
}

func TestManagerDefaultMode(t *testing.T) {
	mgr := New("", 5*time.Second, nil)

	if mgr.mode != "local_tty" {
		t.Errorf("default mode = %q, want local_tty", mgr.mode)
	}
}
