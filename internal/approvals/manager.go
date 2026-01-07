package approvals

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type Emitter interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	Publish(ev types.Event)
}

type Request struct {
	ID        string         `json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	SessionID string         `json:"session_id"`
	CommandID string         `json:"command_id,omitempty"`
	Kind      string         `json:"kind"` // "command" | "file" | "network"
	Target    string         `json:"target,omitempty"`
	Rule      string         `json:"rule,omitempty"`
	Message   string         `json:"message,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
}

type Resolution struct {
	Approved bool      `json:"approved"`
	Reason   string    `json:"reason,omitempty"`
	At       time.Time `json:"at"`
}

type Manager struct {
	mode    string
	timeout time.Duration
	emit    Emitter

	// prompt is factored for testability; defaults to promptTTY.
	prompt func(ctx context.Context, req Request) (Resolution, error)

	// totpSecretLookup retrieves the TOTP secret for a session (TOTP mode only)
	totpSecretLookup func(sessionID string) string

	// webauthnApprover handles WebAuthn approval challenges (webauthn mode only)
	webauthnApprover *WebAuthnApprover

	mu      sync.Mutex
	pending map[string]*pending

	promptMu sync.Mutex

	// Rate limiting: track requests per session
	rateMu        sync.Mutex
	sessionCounts map[string]int // session -> active approval count
	maxPerSession int            // max concurrent approvals per session (0 = unlimited)
}

type pending struct {
	req Request
	ch  chan Resolution
}

func New(mode string, timeout time.Duration, emit Emitter) *Manager {
	if mode == "" {
		mode = "local_tty"
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	m := &Manager{
		mode:          mode,
		timeout:       timeout,
		emit:          emit,
		pending:       make(map[string]*pending),
		sessionCounts: make(map[string]int),
		maxPerSession: 10, // Default: max 10 concurrent approvals per session
	}
	switch mode {
	case "totp":
		m.prompt = m.promptTOTP
	default:
		m.prompt = m.promptTTY
	}
	return m
}

// SetTOTPSecretLookup sets the callback for retrieving TOTP secrets by session ID.
// Required when using TOTP approval mode.
func (m *Manager) SetTOTPSecretLookup(lookup func(sessionID string) string) {
	m.totpSecretLookup = lookup
}

// SetWebAuthnApprover sets the WebAuthn approver (required for webauthn mode).
func (m *Manager) SetWebAuthnApprover(approver *WebAuthnApprover) {
	m.webauthnApprover = approver
}

// GetWebAuthnChallenge returns a WebAuthn challenge for an approval request.
func (m *Manager) GetWebAuthnChallenge(ctx context.Context, approvalID, userID string) (*WebAuthnChallenge, error) {
	if m.mode != "webauthn" {
		return nil, fmt.Errorf("webauthn mode not enabled")
	}
	if m.webauthnApprover == nil {
		return nil, fmt.Errorf("webauthn approver not configured")
	}

	m.mu.Lock()
	p, ok := m.pending[approvalID]
	m.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("approval not found: %s", approvalID)
	}

	return m.webauthnApprover.CreateChallenge(ctx, p.req, userID)
}

// ResolveWithWebAuthn resolves an approval using WebAuthn assertion.
func (m *Manager) ResolveWithWebAuthn(ctx context.Context, approvalID, userID string, responseJSON []byte) error {
	if m.webauthnApprover == nil {
		return fmt.Errorf("webauthn approver not configured")
	}

	if err := m.webauthnApprover.VerifyResponse(ctx, userID, responseJSON); err != nil {
		m.Resolve(approvalID, false, "webauthn verification failed: "+err.Error())
		return err
	}

	m.Resolve(approvalID, true, "webauthn verified")
	return nil
}

func (m *Manager) ListPending() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Request, 0, len(m.pending))
	now := time.Now().UTC()
	for _, p := range m.pending {
		if p.req.ExpiresAt.Before(now) {
			continue
		}
		out = append(out, p.req)
	}
	return out
}

func (m *Manager) Resolve(id string, approved bool, reason string) bool {
	m.mu.Lock()
	p, ok := m.pending[id]
	if ok {
		delete(m.pending, id)
	}
	m.mu.Unlock()
	if !ok {
		return false
	}
	res := Resolution{Approved: approved, Reason: reason, At: time.Now().UTC()}
	select {
	case p.ch <- res:
	default:
	}
	return true
}

func (m *Manager) RequestApproval(ctx context.Context, req Request) (Resolution, error) {
	// Rate limiting: check concurrent approval count per session
	if m.maxPerSession > 0 {
		m.rateMu.Lock()
		count := m.sessionCounts[req.SessionID]
		if count >= m.maxPerSession {
			m.rateMu.Unlock()
			return Resolution{Approved: false, Reason: "rate limit exceeded", At: time.Now().UTC()},
				fmt.Errorf("too many pending approvals for session %s (max %d)", req.SessionID, m.maxPerSession)
		}
		m.sessionCounts[req.SessionID] = count + 1
		m.rateMu.Unlock()
	}

	// Decrement rate limit counter when done
	decrementRate := func() {
		if m.maxPerSession > 0 {
			m.rateMu.Lock()
			m.sessionCounts[req.SessionID]--
			if m.sessionCounts[req.SessionID] <= 0 {
				delete(m.sessionCounts, req.SessionID)
			}
			m.rateMu.Unlock()
		}
	}

	now := time.Now().UTC()
	if req.ID == "" {
		req.ID = "approval-" + uuid.NewString()
	}
	req.CreatedAt = now
	req.ExpiresAt = now.Add(m.timeout)

	p := &pending{req: req, ch: make(chan Resolution, 1)}

	m.mu.Lock()
	m.pending[req.ID] = p
	m.mu.Unlock()

	m.emitEvent(ctx, "approval_requested", req, nil)

	var cancelPrompt context.CancelFunc
	promptCtx := ctx
	if m.mode == "local_tty" {
		promptCtx, cancelPrompt = context.WithCancel(ctx)
		go func() {
			res, err := m.prompt(promptCtx, req)
			if err != nil {
				_ = m.Resolve(req.ID, false, err.Error())
				return
			}
			_ = m.Resolve(req.ID, res.Approved, res.Reason)
		}()
	}

	if m.mode == "local_tty" {
		// Fall through to select; prompt resolution will deliver on p.ch.
	}

	timeout := time.Until(req.ExpiresAt)
	if timeout < 0 {
		timeout = 0
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	defer decrementRate() // Always decrement on exit

	select {
	case res := <-p.ch:
		if cancelPrompt != nil {
			cancelPrompt()
		}
		m.emitEvent(ctx, "approval_resolved", req, &res)
		return res, nil
	case <-ctx.Done():
		if cancelPrompt != nil {
			cancelPrompt()
		}
		m.Resolve(req.ID, false, "context canceled")
		m.emitEvent(ctx, "approval_resolved", req, &Resolution{Approved: false, Reason: "context canceled", At: time.Now().UTC()})
		return Resolution{Approved: false, Reason: "context canceled", At: time.Now().UTC()}, ctx.Err()
	case <-timer.C:
		if cancelPrompt != nil {
			cancelPrompt()
		}
		m.Resolve(req.ID, false, "approval timeout")
		m.emitEvent(ctx, "approval_resolved", req, &Resolution{Approved: false, Reason: "approval timeout", At: time.Now().UTC()})
		return Resolution{Approved: false, Reason: "approval timeout", At: time.Now().UTC()}, fmt.Errorf("approval timeout")
	}
}

func (m *Manager) emitEvent(ctx context.Context, evType string, req Request, res *Resolution) {
	if m.emit == nil {
		return
	}
	fields := map[string]any{
		"approval_id": req.ID,
		"kind":        req.Kind,
		"target":      req.Target,
		"rule":        req.Rule,
		"message":     req.Message,
	}
	for k, v := range req.Fields {
		fields[k] = v
	}
	if res != nil {
		fields["approved"] = res.Approved
		fields["reason"] = res.Reason
		fields["resolved_at"] = res.At.Format(time.RFC3339Nano)
	}
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      evType,
		SessionID: req.SessionID,
		CommandID: req.CommandID,
		Fields:    fields,
	}
	_ = m.emit.AppendEvent(ctx, ev)
	m.emit.Publish(ev)
}

func (m *Manager) promptTTY(ctx context.Context, req Request) (Resolution, error) {
	m.promptMu.Lock()
	defer m.promptMu.Unlock()

	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return Resolution{}, fmt.Errorf("open /dev/tty: %w", err)
	}

	// Use sync.Once to ensure we only close the file once
	var closeOnce sync.Once
	closeFile := func() { closeOnce.Do(func() { _ = f.Close() }) }
	defer closeFile()

	// Close the tty if the context is cancelled to unblock reads.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeFile()
		case <-done:
		}
	}()
	defer close(done)

	reader := bufio.NewReader(f)
	readLineCtx := func(prompt string) (string, error) {
		if _, err := fmt.Fprint(f, prompt); err != nil {
			return "", err
		}
		lineCh := make(chan struct {
			line string
			err  error
		}, 1)
		go func() {
			line, err := reader.ReadString('\n')
			lineCh <- struct {
				line string
				err  error
			}{line: line, err: err}
		}()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case res := <-lineCh:
			if res.err != nil {
				return "", res.err
			}
			return strings.TrimSpace(res.line), nil
		}
	}

	a, b := challenge()
	fmt.Fprintf(f, "\n=== APPROVAL REQUIRED ===\n")
	fmt.Fprintf(f, "ID: %s\nSession: %s\nCommand: %s\nKind: %s\nTarget: %s\nRule: %s\nMessage: %s\n",
		req.ID, req.SessionID, req.CommandID, req.Kind, req.Target, req.Rule, req.Message)

	answer, err := readLineCtx(fmt.Sprintf("To approve, solve: %d + %d = ?\n> ", a, b))
	if err != nil {
		return Resolution{}, err
	}
	if answer != fmt.Sprintf("%d", a+b) {
		return Resolution{Approved: false, Reason: "challenge failed", At: time.Now().UTC()}, nil
	}

	choice, err := readLineCtx("Approve? type 'yes' to approve: ")
	if err != nil {
		return Resolution{}, err
	}
	choice = strings.ToLower(strings.TrimSpace(choice))
	if choice == "yes" || choice == "y" {
		return Resolution{Approved: true, Reason: "local tty", At: time.Now().UTC()}, nil
	}
	return Resolution{Approved: false, Reason: "denied", At: time.Now().UTC()}, nil
}

func (m *Manager) promptTOTP(ctx context.Context, req Request) (Resolution, error) {
	m.promptMu.Lock()
	defer m.promptMu.Unlock()

	// Get the TOTP secret for this session
	if m.totpSecretLookup == nil {
		return Resolution{Approved: false, Reason: "TOTP not configured", At: time.Now().UTC()},
			fmt.Errorf("TOTP secret lookup not configured")
	}
	secret := m.totpSecretLookup(req.SessionID)
	if secret == "" {
		return Resolution{Approved: false, Reason: "no TOTP secret", At: time.Now().UTC()},
			fmt.Errorf("no TOTP secret for session %s", req.SessionID)
	}

	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return Resolution{}, fmt.Errorf("open /dev/tty: %w", err)
	}

	var closeOnce sync.Once
	closeFile := func() { closeOnce.Do(func() { _ = f.Close() }) }
	defer closeFile()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeFile()
		case <-done:
		}
	}()
	defer close(done)

	reader := bufio.NewReader(f)
	readLineCtx := func(prompt string) (string, error) {
		if _, err := fmt.Fprint(f, prompt); err != nil {
			return "", err
		}
		lineCh := make(chan struct {
			line string
			err  error
		}, 1)
		go func() {
			line, err := reader.ReadString('\n')
			lineCh <- struct {
				line string
				err  error
			}{line: line, err: err}
		}()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case res := <-lineCh:
			if res.err != nil {
				return "", res.err
			}
			return strings.TrimSpace(res.line), nil
		}
	}

	// Display approval request
	fmt.Fprintf(f, "\n=== APPROVAL REQUIRED (TOTP) ===\n")
	fmt.Fprintf(f, "Session: %s\nCommand: %s\nKind: %s\nTarget: %s\nRule: %s\nMessage: %s\n\n",
		req.SessionID, req.CommandID, req.Kind, req.Target, req.Rule, req.Message)

	// Prompt for TOTP code
	code, err := readLineCtx("Enter 6-digit TOTP code: ")
	if err != nil {
		return Resolution{}, err
	}

	// Validate the code
	if ValidateTOTPCode(code, secret) {
		return Resolution{Approved: true, Reason: "totp verified", At: time.Now().UTC()}, nil
	}

	return Resolution{Approved: false, Reason: "invalid code", At: time.Now().UTC()}, nil
}

func challenge() (int, int) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	n := binary.LittleEndian.Uint64(b[:])
	a := int(n%50) + 10
	bb := int((n/50)%50) + 10
	return a, bb
}
