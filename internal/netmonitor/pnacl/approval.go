package pnacl

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ApprovalMode determines how network access approval is handled.
type ApprovalMode string

const (
	// ApprovalModeApprove blocks connection and prompts immediately.
	ApprovalModeApprove ApprovalMode = "approve"
	// ApprovalModeAllowOnceThenApprove allows first connection, then prompts.
	ApprovalModeAllowOnceThenApprove ApprovalMode = "allow_once_then_approve"
	// ApprovalModeAudit allows all and logs for review.
	ApprovalModeAudit ApprovalMode = "audit"
)

// UserDecision represents what action the user chose.
type UserDecision string

const (
	// UserDecisionAllowOnce allows this connection only (session-scoped).
	UserDecisionAllowOnce UserDecision = "allow_once"
	// UserDecisionAllowPermanent allows and persists rule to config.
	UserDecisionAllowPermanent UserDecision = "allow_permanent"
	// UserDecisionDenyOnce denies this connection only (session-scoped).
	UserDecisionDenyOnce UserDecision = "deny_once"
	// UserDecisionDenyForever denies and persists rule to config.
	UserDecisionDenyForever UserDecision = "deny_forever"
	// UserDecisionSkip skips without decision (uses default/timeout behavior).
	UserDecisionSkip UserDecision = "skip"
	// UserDecisionTimeout indicates no response within timeout.
	UserDecisionTimeout UserDecision = "timeout"
)

// ApprovalRequest represents a network access approval request.
type ApprovalRequest struct {
	ID          string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ProcessName string
	ProcessPath string
	PID         int
	ParentPID   int
	Target      string // hostname or IP
	Port        int
	Protocol    string // tcp/udp
	IP          net.IP
}

// ApprovalResponse contains the user's decision for an approval request.
type ApprovalResponse struct {
	RequestID  string
	Decision   UserDecision
	At         time.Time
	Reason     string
	Persistent bool // Whether to persist to config
}

// NetworkACLEvent represents an event emitted for network access decisions.
type NetworkACLEvent struct {
	Timestamp   time.Time
	ProcessName string
	ProcessPath string
	PID         int
	ParentPID   int
	Target      string // hostname or IP
	Port        int
	Protocol    string // tcp/udp
	Decision    string // allow/deny/approve
	RuleSource  string // which rule matched
	UserAction  string // if prompted, what user chose
}

// ApprovalConfig configures the approval provider.
type ApprovalConfig struct {
	// Mode determines the approval behavior.
	Mode ApprovalMode
	// Timeout is how long to wait for user approval.
	Timeout time.Duration
	// TimeoutFallback is the action when approval times out.
	// Valid values: deny, allow, use_default.
	// When use_default is specified, the DefaultDecisionFn is called to get the decision.
	TimeoutFallback Decision // deny, allow, or use_default
	// ConfigPath is the path to persist permanent rules.
	ConfigPath string
	// DefaultDecisionFn is called when TimeoutFallback is use_default to get the
	// appropriate default decision from the policy engine. This allows timeout
	// handling to respect the global or process-specific default from the config.
	// If nil and TimeoutFallback is use_default, falls back to DecisionDeny.
	DefaultDecisionFn func() Decision
}

// DefaultApprovalConfig returns sensible defaults.
func DefaultApprovalConfig() *ApprovalConfig {
	return &ApprovalConfig{
		Mode:            ApprovalModeApprove,
		Timeout:         30 * time.Second,
		TimeoutFallback: DecisionDeny,
		ConfigPath:      "",
	}
}

// EventEmitter is the interface for emitting PNACL events.
type EventEmitter interface {
	// EmitNetworkACLEvent emits a network ACL event.
	EmitNetworkACLEvent(ctx context.Context, event NetworkACLEvent) error
}

// RulePersister is the interface for persisting rules to config.
type RulePersister interface {
	// AddRule adds a rule to the configuration file.
	// comment is included as a YAML comment above the rule.
	AddRule(processName string, target NetworkTarget, comment string) error
}

// PromptProvider is the interface for delivering approval prompts.
type PromptProvider interface {
	// Prompt displays an approval request and waits for user response.
	Prompt(ctx context.Context, req ApprovalRequest) (ApprovalResponse, error)
}

// ApprovalProvider handles network access approvals for PNACL.
type ApprovalProvider struct {
	config *ApprovalConfig
	emit   EventEmitter
	persist RulePersister
	prompt  PromptProvider

	mu      sync.Mutex
	pending map[string]*pendingApproval
}

type pendingApproval struct {
	req ApprovalRequest
	ch  chan ApprovalResponse
}

// NewApprovalProvider creates a new approval provider.
func NewApprovalProvider(config *ApprovalConfig) *ApprovalProvider {
	if config == nil {
		config = DefaultApprovalConfig()
	}
	ap := &ApprovalProvider{
		config:  config,
		pending: make(map[string]*pendingApproval),
	}
	// Default to TTY prompt
	ap.prompt = &TTYPromptProvider{}
	return ap
}

// SetEventEmitter sets the event emitter.
func (ap *ApprovalProvider) SetEventEmitter(emit EventEmitter) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	ap.emit = emit
}

// SetRulePersister sets the rule persister.
func (ap *ApprovalProvider) SetRulePersister(persist RulePersister) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	ap.persist = persist
}

// SetPromptProvider sets the prompt provider.
func (ap *ApprovalProvider) SetPromptProvider(prompt PromptProvider) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	ap.prompt = prompt
}

// RequestApproval handles a network access approval request.
// Returns the final decision (allow/deny) based on user response or timeout.
func (ap *ApprovalProvider) RequestApproval(ctx context.Context, req ApprovalRequest) (Decision, UserDecision, error) {
	if req.ID == "" {
		req.ID = "pnacl-" + uuid.NewString()
	}
	now := time.Now().UTC()
	req.CreatedAt = now
	req.ExpiresAt = now.Add(ap.config.Timeout)

	// Create pending entry
	pending := &pendingApproval{
		req: req,
		ch:  make(chan ApprovalResponse, 1),
	}

	ap.mu.Lock()
	ap.pending[req.ID] = pending
	ap.mu.Unlock()

	defer func() {
		ap.mu.Lock()
		delete(ap.pending, req.ID)
		ap.mu.Unlock()
	}()

	// Emit approval_requested event
	ap.emitEvent(ctx, req, "approval_requested", "", "")

	// Start prompt in goroutine
	ap.mu.Lock()
	promptProvider := ap.prompt
	ap.mu.Unlock()

	var promptCancel context.CancelFunc
	promptCtx, promptCancel := context.WithCancel(ctx)
	defer promptCancel()

	go func() {
		resp, err := promptProvider.Prompt(promptCtx, req)
		if err != nil {
			select {
			case pending.ch <- ApprovalResponse{
				RequestID: req.ID,
				Decision:  UserDecisionSkip,
				At:        time.Now().UTC(),
				Reason:    err.Error(),
			}:
			default:
			}
			return
		}
		select {
		case pending.ch <- resp:
		default:
		}
	}()

	// Wait for response or timeout
	timer := time.NewTimer(time.Until(req.ExpiresAt))
	defer timer.Stop()

	select {
	case resp := <-pending.ch:
		promptCancel()
		return ap.handleResponse(ctx, req, resp)

	case <-timer.C:
		promptCancel()
		return ap.handleTimeout(ctx, req)

	case <-ctx.Done():
		promptCancel()
		ap.emitEvent(ctx, req, "approval_cancelled", "", "context_cancelled")
		return DecisionDeny, UserDecisionSkip, ctx.Err()
	}
}

// handleResponse processes a user response and optionally persists rules.
func (ap *ApprovalProvider) handleResponse(ctx context.Context, req ApprovalRequest, resp ApprovalResponse) (Decision, UserDecision, error) {
	var decision Decision
	userAction := string(resp.Decision)

	switch resp.Decision {
	case UserDecisionAllowOnce:
		decision = DecisionAllow
		ap.emitEvent(ctx, req, "approval_granted", "allow_once", userAction)

	case UserDecisionAllowPermanent:
		decision = DecisionAllow
		ap.emitEvent(ctx, req, "approval_granted", "allow_permanent", userAction)
		// Persist rule
		if err := ap.persistRule(req, DecisionAllow); err != nil {
			// Log but don't fail the approval
			ap.emitEvent(ctx, req, "rule_persist_failed", "", err.Error())
		}

	case UserDecisionDenyOnce:
		decision = DecisionDeny
		ap.emitEvent(ctx, req, "approval_denied", "deny_once", userAction)

	case UserDecisionDenyForever:
		decision = DecisionDeny
		ap.emitEvent(ctx, req, "approval_denied", "deny_forever", userAction)
		// Persist rule
		if err := ap.persistRule(req, DecisionDeny); err != nil {
			ap.emitEvent(ctx, req, "rule_persist_failed", "", err.Error())
		}

	case UserDecisionSkip:
		decision = ap.resolveFallbackDecision()
		ap.emitEvent(ctx, req, "approval_skipped", "", userAction)

	default:
		decision = ap.resolveFallbackDecision()
		ap.emitEvent(ctx, req, "approval_unknown", "", userAction)
	}

	return decision, resp.Decision, nil
}

// handleTimeout handles approval timeout.
func (ap *ApprovalProvider) handleTimeout(ctx context.Context, req ApprovalRequest) (Decision, UserDecision, error) {
	decision := ap.resolveFallbackDecision()
	ap.emitEvent(ctx, req, "approval_timeout", "", "timeout")
	return decision, UserDecisionTimeout, fmt.Errorf("approval timeout after %v", ap.config.Timeout)
}

// resolveFallbackDecision returns the actual decision to use for timeout/skip cases.
// If TimeoutFallback is use_default, it calls DefaultDecisionFn to get the policy default.
func (ap *ApprovalProvider) resolveFallbackDecision() Decision {
	fallback := ap.config.TimeoutFallback
	if fallback == DecisionUseDefault {
		if ap.config.DefaultDecisionFn != nil {
			return ap.config.DefaultDecisionFn()
		}
		// No DefaultDecisionFn configured, fall back to deny for safety
		return DecisionDeny
	}
	return fallback
}

// persistRule persists a rule to the configuration file.
func (ap *ApprovalProvider) persistRule(req ApprovalRequest, decision Decision) error {
	ap.mu.Lock()
	persister := ap.persist
	ap.mu.Unlock()

	if persister == nil {
		return nil // No persister configured
	}

	target := NetworkTarget{
		Host:     req.Target,
		Port:     fmt.Sprintf("%d", req.Port),
		Protocol: req.Protocol,
		Decision: decision,
	}

	// If target looks like an IP, use IP field instead
	if ip := net.ParseIP(req.Target); ip != nil {
		target.IP = req.Target
		target.Host = ""
	}

	comment := fmt.Sprintf("Auto-added %s via PNACL prompt (process: %s, pid: %d)",
		time.Now().Format("2006-01-02"), req.ProcessName, req.PID)

	return persister.AddRule(req.ProcessName, target, comment)
}

// emitEvent emits a network ACL event.
func (ap *ApprovalProvider) emitEvent(ctx context.Context, req ApprovalRequest, eventType, ruleSource, userAction string) {
	ap.mu.Lock()
	emitter := ap.emit
	ap.mu.Unlock()

	if emitter == nil {
		return
	}

	event := NetworkACLEvent{
		Timestamp:   time.Now().UTC(),
		ProcessName: req.ProcessName,
		ProcessPath: req.ProcessPath,
		PID:         req.PID,
		ParentPID:   req.ParentPID,
		Target:      req.Target,
		Port:        req.Port,
		Protocol:    req.Protocol,
		Decision:    eventType,
		RuleSource:  ruleSource,
		UserAction:  userAction,
	}

	_ = emitter.EmitNetworkACLEvent(ctx, event)
}

// ListPending returns all pending approval requests.
func (ap *ApprovalProvider) ListPending() []ApprovalRequest {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	now := time.Now().UTC()
	result := make([]ApprovalRequest, 0, len(ap.pending))
	for _, p := range ap.pending {
		if p.req.ExpiresAt.After(now) {
			result = append(result, p.req)
		}
	}
	return result
}

// Resolve resolves a pending approval request by ID.
func (ap *ApprovalProvider) Resolve(id string, decision UserDecision, reason string) bool {
	ap.mu.Lock()
	p, ok := ap.pending[id]
	ap.mu.Unlock()

	if !ok {
		return false
	}

	resp := ApprovalResponse{
		RequestID:  id,
		Decision:   decision,
		At:         time.Now().UTC(),
		Reason:     reason,
		Persistent: decision == UserDecisionAllowPermanent || decision == UserDecisionDenyForever,
	}

	select {
	case p.ch <- resp:
		return true
	default:
		return false
	}
}

// TTYPromptProvider implements PromptProvider for TTY-based prompts.
//
// Design Decision: Standalone vs. internal/approvals integration
//
// This TTYPromptProvider is intentionally separate from internal/approvals/Manager
// because PNACL network approval has fundamentally different requirements:
//
// 1. Decision granularity: PNACL needs 5 decision types (allow_once, allow_permanent,
//    deny_once, deny_forever, skip) with different persistence behaviors.
//    internal/approvals uses binary approved/denied.
//
// 2. Request context: PNACL prompts for network connections (process, host, port, protocol).
//    internal/approvals prompts for session commands (SessionID, CommandID, Rule).
//
// 3. UX requirements: PNACL needs sub-second single-key responses for real-time network
//    decisions. internal/approvals uses challenge-response (math, TOTP, WebAuthn).
//
// 4. Timeout semantics: PNACL supports configurable fallback (deny, allow, use_default).
//    internal/approvals always denies on timeout.
//
// Integration would require significant abstraction overhead without clear benefit
// since the systems serve different security domains (network ACL vs. command approval).
type TTYPromptProvider struct {
	mu sync.Mutex
}

// Prompt displays an approval request on TTY and waits for user response.
func (p *TTYPromptProvider) Prompt(ctx context.Context, req ApprovalRequest) (ApprovalResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return ApprovalResponse{}, fmt.Errorf("open /dev/tty: %w", err)
	}

	var closeOnce sync.Once
	closeFile := func() { closeOnce.Do(func() { _ = f.Close() }) }
	defer closeFile()

	// Close TTY if context is cancelled to unblock reads
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

	// Display prompt
	fmt.Fprintf(f, "\n")
	fmt.Fprintf(f, "[PNACL] %s → %s:%d (%s)\n", req.ProcessName, req.Target, req.Port, req.Protocol)
	fmt.Fprintf(f, "Process: %s (pid: %d)\n", req.ProcessPath, req.PID)
	fmt.Fprintf(f, "Action: [A]llow once | Allow [P]ermanent | [D]eny once | Deny [F]orever | [S]kip\n")
	fmt.Fprintf(f, "> ")

	// Read response
	lineCh := make(chan struct {
		line string
		err  error
	}, 1)
	// Note: If context is cancelled, this goroutine may block on ReadString until
	// the TTY is closed. The deferred f.Close() ensures the goroutine eventually
	// unblocks and terminates when the function returns.
	go func() {
		line, err := reader.ReadString('\n')
		lineCh <- struct {
			line string
			err  error
		}{line: line, err: err}
	}()

	select {
	case <-ctx.Done():
		return ApprovalResponse{}, ctx.Err()
	case result := <-lineCh:
		if result.err != nil {
			return ApprovalResponse{}, result.err
		}

		input := strings.ToLower(strings.TrimSpace(result.line))
		var decision UserDecision

		switch input {
		case "a", "allow", "allow once":
			decision = UserDecisionAllowOnce
		case "p", "permanent", "allow permanent":
			decision = UserDecisionAllowPermanent
		case "d", "deny", "deny once":
			decision = UserDecisionDenyOnce
		case "f", "forever", "deny forever":
			decision = UserDecisionDenyForever
		case "s", "skip", "":
			decision = UserDecisionSkip
		default:
			// Unknown input treated as skip
			decision = UserDecisionSkip
		}

		return ApprovalResponse{
			RequestID:  req.ID,
			Decision:   decision,
			At:         time.Now().UTC(),
			Persistent: decision == UserDecisionAllowPermanent || decision == UserDecisionDenyForever,
		}, nil
	}
}

// NotificationPromptProvider implements PromptProvider for desktop notifications.
// This is a stub that can be implemented with platform-specific notification APIs.
type NotificationPromptProvider struct {
	// Fallback is the decision to use when notification is dismissed or unavailable.
	Fallback UserDecision
}

// Prompt sends a desktop notification and waits for response.
// Note: This is a stub implementation. Real implementation would use
// platform-specific notification APIs (D-Bus on Linux, etc.)
func (p *NotificationPromptProvider) Prompt(ctx context.Context, req ApprovalRequest) (ApprovalResponse, error) {
	// TODO: Implement platform-specific notification delivery
	// For now, return the fallback decision
	return ApprovalResponse{
		RequestID: req.ID,
		Decision:  p.Fallback,
		At:        time.Now().UTC(),
		Reason:    "notification not implemented",
	}, nil
}

// RemoteAPIPromptProvider implements PromptProvider for remote API approval.
// This allows forwarding approval requests to an external service.
type RemoteAPIPromptProvider struct {
	// Endpoint is the URL of the remote approval service.
	Endpoint string
	// Fallback is the decision to use when the remote API is unavailable.
	Fallback UserDecision
}

// Prompt sends the approval request to a remote API and waits for response.
// Note: This is a stub implementation. Real implementation would make HTTP calls.
func (p *RemoteAPIPromptProvider) Prompt(ctx context.Context, req ApprovalRequest) (ApprovalResponse, error) {
	// TODO: Implement HTTP-based remote approval
	// For now, return the fallback decision
	return ApprovalResponse{
		RequestID: req.ID,
		Decision:  p.Fallback,
		At:        time.Now().UTC(),
		Reason:    "remote API not implemented",
	}, nil
}
