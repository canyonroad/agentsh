package skillcheck

import (
	"context"
	"errors"
	"testing"
)

func TestApprovalAdapter_PassesContextAndDecision(t *testing.T) {
	called := false
	adapter := NewApprovalAdapter(func(ctx context.Context, prompt string) (bool, error) {
		called = true
		if prompt == "" {
			t.Errorf("empty prompt")
		}
		return true, nil
	})
	ok, err := adapter.Ask(context.Background(), SkillRef{Name: "x", SHA256: "h"}, &Verdict{Action: VerdictApprove, Summary: "needs review"})
	if err != nil || !ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
	if !called {
		t.Errorf("backend not invoked")
	}
}

func TestApprovalAdapter_PromptContainsNameSHAAndSummary(t *testing.T) {
	var gotPrompt string
	adapter := NewApprovalAdapter(func(ctx context.Context, prompt string) (bool, error) {
		gotPrompt = prompt
		return true, nil
	})
	sha := "abcdef1234567890"
	skill := SkillRef{Name: "my-skill", SHA256: sha}
	v := &Verdict{Action: VerdictApprove, Summary: "suspicious content"}
	_, _ = adapter.Ask(context.Background(), skill, v)

	for _, want := range []string{"my-skill", sha[:12], "suspicious content"} {
		if !contains(gotPrompt, want) {
			t.Errorf("prompt %q missing %q", gotPrompt, want)
		}
	}
}

func TestApprovalAdapter_BackendErrorSurfaces(t *testing.T) {
	backendErr := errors.New("backend unavailable")
	adapter := NewApprovalAdapter(func(ctx context.Context, prompt string) (bool, error) {
		return false, backendErr
	})
	_, err := adapter.Ask(context.Background(), SkillRef{Name: "x", SHA256: "abc"}, &Verdict{Action: VerdictApprove})
	if !errors.Is(err, backendErr) {
		t.Errorf("expected backend error, got %v", err)
	}
}

func TestApprovalAdapter_ContextCancellationPropagates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	adapter := NewApprovalAdapter(func(ctx context.Context, prompt string) (bool, error) {
		return false, ctx.Err()
	})
	_, err := adapter.Ask(ctx, SkillRef{Name: "x", SHA256: "abc"}, &Verdict{Action: VerdictApprove})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// contains is a simple substring check used in tests.
func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
