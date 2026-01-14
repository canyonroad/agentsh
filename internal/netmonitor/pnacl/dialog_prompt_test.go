package pnacl

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approval/dialog"
)

// skipIfDialogAvailable skips the test if a dialog backend is available,
// since the test would pop up actual modal dialogs requiring user interaction.
func skipIfDialogAvailable(t *testing.T) {
	t.Helper()
	if dialog.CanShowDialog() {
		t.Skip("Skipping test: dialog backend available - would pop modal dialog")
	}
}

func TestDialogPromptProvider_NewDialogPromptProvider(t *testing.T) {
	tests := []struct {
		name     string
		fallback UserDecision
	}{
		{
			name:     "with deny_once fallback",
			fallback: UserDecisionDenyOnce,
		},
		{
			name:     "with allow_once fallback",
			fallback: UserDecisionAllowOnce,
		},
		{
			name:     "with skip fallback",
			fallback: UserDecisionSkip,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewDialogPromptProvider(tt.fallback)
			if provider == nil {
				t.Fatal("expected non-nil provider")
			}
			if provider.FallbackDecision != tt.fallback {
				t.Errorf("expected fallback %s, got %s", tt.fallback, provider.FallbackDecision)
			}
		})
	}
}

func TestDialogPromptProvider_ImplementsPromptProvider(t *testing.T) {
	// Verify that DialogPromptProvider implements PromptProvider interface
	var _ PromptProvider = (*DialogPromptProvider)(nil)
}

func TestDialogPromptProvider_Prompt_RequestFormatting(t *testing.T) {
	skipIfDialogAvailable(t)

	provider := NewDialogPromptProvider(UserDecisionDenyOnce)

	req := ApprovalRequest{
		ID:          "test-id-123",
		ProcessName: "curl",
		ProcessPath: "/usr/bin/curl",
		PID:         12345,
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
		ExpiresAt:   time.Now().Add(30 * time.Second),
	}

	// Calling Prompt will fail because dialog backend is unavailable in test,
	// but it should return the fallback decision
	ctx := context.Background()
	resp, _ := provider.Prompt(ctx, req)

	// When dialog is unavailable, fallback decision should be returned
	if resp.Decision != UserDecisionDenyOnce {
		t.Errorf("expected fallback decision %s, got %s", UserDecisionDenyOnce, resp.Decision)
	}
	if resp.RequestID != req.ID {
		t.Errorf("expected request ID %s, got %s", req.ID, resp.RequestID)
	}
}

func TestDialogPromptProvider_Prompt_FallbackOnError(t *testing.T) {
	skipIfDialogAvailable(t)

	tests := []struct {
		name     string
		fallback UserDecision
	}{
		{
			name:     "fallback deny_once",
			fallback: UserDecisionDenyOnce,
		},
		{
			name:     "fallback allow_once",
			fallback: UserDecisionAllowOnce,
		},
		{
			name:     "fallback skip",
			fallback: UserDecisionSkip,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewDialogPromptProvider(tt.fallback)

			req := ApprovalRequest{
				ID:          "test-request",
				ProcessName: "test-app",
				PID:         1000,
				Target:      "example.com",
				Port:        80,
				Protocol:    "tcp",
				ExpiresAt:   time.Now().Add(10 * time.Second),
			}

			ctx := context.Background()
			resp, _ := provider.Prompt(ctx, req)

			// Should return fallback decision when dialog unavailable
			if resp.Decision != tt.fallback {
				t.Errorf("expected decision %s, got %s", tt.fallback, resp.Decision)
			}
		})
	}
}

func TestDialogPromptProvider_Prompt_ContextCancellation(t *testing.T) {
	skipIfDialogAvailable(t)

	provider := NewDialogPromptProvider(UserDecisionDenyOnce)

	req := ApprovalRequest{
		ID:          "test-request",
		ProcessName: "test-app",
		PID:         1000,
		Target:      "example.com",
		Port:        80,
		Protocol:    "tcp",
		ExpiresAt:   time.Now().Add(10 * time.Second),
	}

	// Create already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resp, err := provider.Prompt(ctx, req)

	// Either error is returned or fallback is used
	if err == nil {
		// If no error, fallback should be used
		if resp.Decision != UserDecisionDenyOnce {
			t.Errorf("expected fallback decision, got %s", resp.Decision)
		}
	}
}

func TestDialogPromptProvider_Prompt_ExpiredRequest(t *testing.T) {
	skipIfDialogAvailable(t)

	provider := NewDialogPromptProvider(UserDecisionDenyOnce)

	// Request that has already expired
	req := ApprovalRequest{
		ID:          "expired-request",
		ProcessName: "test-app",
		PID:         1000,
		Target:      "example.com",
		Port:        80,
		Protocol:    "tcp",
		ExpiresAt:   time.Now().Add(-1 * time.Second), // Already expired
	}

	ctx := context.Background()
	resp, _ := provider.Prompt(ctx, req)

	// Should return fallback for expired/timed out request
	if resp.Decision != UserDecisionDenyOnce {
		t.Errorf("expected fallback decision for expired request, got %s", resp.Decision)
	}
}

func TestDialogPromptProvider_Prompt_ResponseTimestamp(t *testing.T) {
	skipIfDialogAvailable(t)

	provider := NewDialogPromptProvider(UserDecisionSkip)

	req := ApprovalRequest{
		ID:          "timestamp-test",
		ProcessName: "test-app",
		PID:         1000,
		Target:      "example.com",
		Port:        80,
		Protocol:    "tcp",
		ExpiresAt:   time.Now().Add(10 * time.Second),
	}

	before := time.Now().UTC()
	ctx := context.Background()
	resp, _ := provider.Prompt(ctx, req)
	after := time.Now().UTC()

	// Response timestamp should be between before and after
	if resp.At.Before(before) || resp.At.After(after) {
		t.Errorf("response timestamp %v not between %v and %v", resp.At, before, after)
	}
}

func TestDialogPromptProvider_Prompt_ReasonOnFallback(t *testing.T) {
	skipIfDialogAvailable(t)

	provider := NewDialogPromptProvider(UserDecisionDenyOnce)

	req := ApprovalRequest{
		ID:          "reason-test",
		ProcessName: "test-app",
		PID:         1000,
		Target:      "example.com",
		Port:        80,
		Protocol:    "tcp",
		ExpiresAt:   time.Now().Add(10 * time.Second),
	}

	ctx := context.Background()
	resp, _ := provider.Prompt(ctx, req)

	// When fallback is used, reason should be set
	if resp.Reason == "" {
		t.Error("expected reason to be set when using fallback")
	}
}
