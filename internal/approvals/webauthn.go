package approvals

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/agentsh/agentsh/internal/auth"
	"github.com/go-webauthn/webauthn/protocol"
)

// WebAuthnChallenge represents a pending WebAuthn approval challenge.
type WebAuthnChallenge struct {
	ApprovalID string                        `json:"approval_id"`
	SessionID  string                        `json:"session_id"`
	Challenge  *protocol.CredentialAssertion `json:"challenge"`
	ExpiresAt  time.Time                     `json:"expires_at"`
}

// WebAuthnApprover handles WebAuthn-based approvals.
type WebAuthnApprover struct {
	service *auth.WebAuthnService
}

// NewWebAuthnApprover creates a new WebAuthn approver.
func NewWebAuthnApprover(service *auth.WebAuthnService) *WebAuthnApprover {
	return &WebAuthnApprover{service: service}
}

// CreateChallenge generates a WebAuthn challenge for an approval request.
func (w *WebAuthnApprover) CreateChallenge(ctx context.Context, req Request, userID string) (*WebAuthnChallenge, error) {
	assertion, err := w.service.BeginAuthentication(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("begin authentication: %w", err)
	}

	return &WebAuthnChallenge{
		ApprovalID: req.ID,
		SessionID:  req.SessionID,
		Challenge:  assertion,
		ExpiresAt:  req.ExpiresAt,
	}, nil
}

// VerifyResponse validates a WebAuthn assertion response.
func (w *WebAuthnApprover) VerifyResponse(ctx context.Context, userID string, responseJSON []byte) error {
	var response protocol.CredentialAssertionResponse
	if err := json.Unmarshal(responseJSON, &response); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	parsed, err := response.Parse()
	if err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	return w.service.FinishAuthentication(ctx, userID, parsed)
}
