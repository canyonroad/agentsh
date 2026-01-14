package pnacl

import (
	"context"
	"sync"
	"testing"
	"time"
)

// MockPromptProvider is a mock implementation of PromptProvider for testing.
type MockPromptProvider struct {
	mu        sync.Mutex
	response  ApprovalResponse
	err       error
	delay     time.Duration
	calls     []ApprovalRequest
	onPrompt  func(req ApprovalRequest) (ApprovalResponse, error)
}

func (m *MockPromptProvider) Prompt(ctx context.Context, req ApprovalRequest) (ApprovalResponse, error) {
	m.mu.Lock()
	m.calls = append(m.calls, req)
	response := m.response
	err := m.err
	delay := m.delay
	onPrompt := m.onPrompt
	m.mu.Unlock()

	if onPrompt != nil {
		return onPrompt(req)
	}

	select {
	case <-ctx.Done():
		return ApprovalResponse{}, ctx.Err()
	case <-time.After(delay):
	}

	if err != nil {
		return ApprovalResponse{}, err
	}
	response.RequestID = req.ID
	response.At = time.Now().UTC()
	return response, nil
}

func (m *MockPromptProvider) GetCalls() []ApprovalRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// MockEventEmitter is a mock implementation of EventEmitter for testing.
type MockEventEmitter struct {
	mu     sync.Mutex
	events []NetworkACLEvent
}

func (m *MockEventEmitter) EmitNetworkACLEvent(ctx context.Context, event NetworkACLEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *MockEventEmitter) GetEvents() []NetworkACLEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.events
}

func TestApprovalProvider_AllowOnce(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 5 * time.Second

	ap := NewApprovalProvider(config)

	mockPrompt := &MockPromptProvider{
		response: ApprovalResponse{
			Decision:   UserDecisionAllowOnce,
			Persistent: false,
		},
		delay: 10 * time.Millisecond,
	}
	ap.SetPromptProvider(mockPrompt)

	mockEmitter := &MockEventEmitter{}
	ap.SetEventEmitter(mockEmitter)

	ctx := context.Background()
	req := ApprovalRequest{
		ProcessName: "test-process",
		ProcessPath: "/usr/bin/test",
		PID:         1234,
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	decision, userDecision, err := ap.RequestApproval(ctx, req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != DecisionAllow {
		t.Errorf("expected decision Allow, got %s", decision)
	}
	if userDecision != UserDecisionAllowOnce {
		t.Errorf("expected user decision AllowOnce, got %s", userDecision)
	}

	// Verify events were emitted
	events := mockEmitter.GetEvents()
	if len(events) < 2 {
		t.Errorf("expected at least 2 events, got %d", len(events))
	}
}

func TestApprovalProvider_AllowPermanent_PersistsRule(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 5 * time.Second

	ap := NewApprovalProvider(config)

	mockPrompt := &MockPromptProvider{
		response: ApprovalResponse{
			Decision:   UserDecisionAllowPermanent,
			Persistent: true,
		},
		delay: 10 * time.Millisecond,
	}
	ap.SetPromptProvider(mockPrompt)

	mockPersister := NewInMemoryRulePersister()
	ap.SetRulePersister(mockPersister)

	mockEmitter := &MockEventEmitter{}
	ap.SetEventEmitter(mockEmitter)

	ctx := context.Background()
	req := ApprovalRequest{
		ProcessName: "test-process",
		ProcessPath: "/usr/bin/test",
		PID:         1234,
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	decision, userDecision, err := ap.RequestApproval(ctx, req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != DecisionAllow {
		t.Errorf("expected decision Allow, got %s", decision)
	}
	if userDecision != UserDecisionAllowPermanent {
		t.Errorf("expected user decision AllowPermanent, got %s", userDecision)
	}

	// Verify rule was persisted
	rules := mockPersister.GetRules("test-process")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule persisted, got %d", len(rules))
	}
	if rules[0].Host != "api.example.com" {
		t.Errorf("expected host api.example.com, got %s", rules[0].Host)
	}
	if rules[0].Port != "443" {
		t.Errorf("expected port 443, got %s", rules[0].Port)
	}
	if rules[0].Decision != DecisionAllow {
		t.Errorf("expected decision Allow, got %s", rules[0].Decision)
	}
}

func TestApprovalProvider_DenyOnce(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 5 * time.Second

	ap := NewApprovalProvider(config)

	mockPrompt := &MockPromptProvider{
		response: ApprovalResponse{
			Decision: UserDecisionDenyOnce,
		},
		delay: 10 * time.Millisecond,
	}
	ap.SetPromptProvider(mockPrompt)

	mockEmitter := &MockEventEmitter{}
	ap.SetEventEmitter(mockEmitter)

	ctx := context.Background()
	req := ApprovalRequest{
		ProcessName: "test-process",
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	decision, userDecision, err := ap.RequestApproval(ctx, req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != DecisionDeny {
		t.Errorf("expected decision Deny, got %s", decision)
	}
	if userDecision != UserDecisionDenyOnce {
		t.Errorf("expected user decision DenyOnce, got %s", userDecision)
	}
}

func TestApprovalProvider_DenyForever_PersistsRule(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 5 * time.Second

	ap := NewApprovalProvider(config)

	mockPrompt := &MockPromptProvider{
		response: ApprovalResponse{
			Decision:   UserDecisionDenyForever,
			Persistent: true,
		},
		delay: 10 * time.Millisecond,
	}
	ap.SetPromptProvider(mockPrompt)

	mockPersister := NewInMemoryRulePersister()
	ap.SetRulePersister(mockPersister)

	ctx := context.Background()
	req := ApprovalRequest{
		ProcessName: "test-process",
		Target:      "malicious.example.com",
		Port:        80,
		Protocol:    "tcp",
	}

	decision, _, err := ap.RequestApproval(ctx, req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != DecisionDeny {
		t.Errorf("expected decision Deny, got %s", decision)
	}

	// Verify rule was persisted
	rules := mockPersister.GetRules("test-process")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule persisted, got %d", len(rules))
	}
	if rules[0].Decision != DecisionDeny {
		t.Errorf("expected decision Deny, got %s", rules[0].Decision)
	}
}

func TestApprovalProvider_Timeout(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 100 * time.Millisecond
	config.TimeoutFallback = DecisionDeny

	ap := NewApprovalProvider(config)

	mockPrompt := &MockPromptProvider{
		delay: 1 * time.Second, // Longer than timeout
		response: ApprovalResponse{
			Decision: UserDecisionAllowOnce,
		},
	}
	ap.SetPromptProvider(mockPrompt)

	mockEmitter := &MockEventEmitter{}
	ap.SetEventEmitter(mockEmitter)

	ctx := context.Background()
	req := ApprovalRequest{
		ProcessName: "test-process",
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	decision, userDecision, err := ap.RequestApproval(ctx, req)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if decision != DecisionDeny {
		t.Errorf("expected decision Deny on timeout, got %s", decision)
	}
	if userDecision != UserDecisionTimeout {
		t.Errorf("expected user decision Timeout, got %s", userDecision)
	}

	// Verify timeout event was emitted
	events := mockEmitter.GetEvents()
	found := false
	for _, e := range events {
		if e.Decision == "approval_timeout" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected approval_timeout event")
	}
}

func TestApprovalProvider_Timeout_AllowFallback(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 100 * time.Millisecond
	config.TimeoutFallback = DecisionAllow

	ap := NewApprovalProvider(config)

	mockPrompt := &MockPromptProvider{
		delay: 1 * time.Second,
	}
	ap.SetPromptProvider(mockPrompt)

	ctx := context.Background()
	req := ApprovalRequest{
		ProcessName: "test-process",
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	decision, _, err := ap.RequestApproval(ctx, req)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if decision != DecisionAllow {
		t.Errorf("expected decision Allow on timeout fallback, got %s", decision)
	}
}

func TestApprovalProvider_ContextCancellation(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 5 * time.Second

	ap := NewApprovalProvider(config)

	mockPrompt := &MockPromptProvider{
		delay: 100 * time.Second, // Very long delay
	}
	ap.SetPromptProvider(mockPrompt)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	req := ApprovalRequest{
		ProcessName: "test-process",
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	_, _, err := ap.RequestApproval(ctx, req)

	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

func TestApprovalProvider_Skip(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 5 * time.Second
	config.TimeoutFallback = DecisionDeny

	ap := NewApprovalProvider(config)

	mockPrompt := &MockPromptProvider{
		response: ApprovalResponse{
			Decision: UserDecisionSkip,
		},
		delay: 10 * time.Millisecond,
	}
	ap.SetPromptProvider(mockPrompt)

	ctx := context.Background()
	req := ApprovalRequest{
		ProcessName: "test-process",
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	decision, userDecision, err := ap.RequestApproval(ctx, req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != DecisionDeny {
		t.Errorf("expected decision Deny (fallback), got %s", decision)
	}
	if userDecision != UserDecisionSkip {
		t.Errorf("expected user decision Skip, got %s", userDecision)
	}
}

func TestApprovalProvider_ListPending(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 5 * time.Second

	ap := NewApprovalProvider(config)

	// Use a prompt that blocks
	blockCh := make(chan struct{})
	mockPrompt := &MockPromptProvider{
		onPrompt: func(req ApprovalRequest) (ApprovalResponse, error) {
			<-blockCh
			return ApprovalResponse{Decision: UserDecisionAllowOnce}, nil
		},
	}
	ap.SetPromptProvider(mockPrompt)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := ApprovalRequest{
		ProcessName: "test-process",
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	// Start approval in goroutine
	done := make(chan struct{})
	go func() {
		ap.RequestApproval(ctx, req)
		close(done)
	}()

	// Wait a bit for the request to be pending
	time.Sleep(50 * time.Millisecond)

	pending := ap.ListPending()
	if len(pending) != 1 {
		t.Errorf("expected 1 pending, got %d", len(pending))
	}
	if len(pending) > 0 && pending[0].ProcessName != "test-process" {
		t.Errorf("expected process name test-process, got %s", pending[0].ProcessName)
	}

	// Unblock and wait
	close(blockCh)
	<-done
}

func TestApprovalProvider_Resolve(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 5 * time.Second

	ap := NewApprovalProvider(config)

	// Use a prompt that blocks
	blockCh := make(chan struct{})
	mockPrompt := &MockPromptProvider{
		onPrompt: func(req ApprovalRequest) (ApprovalResponse, error) {
			<-blockCh
			return ApprovalResponse{}, context.Canceled
		},
	}
	ap.SetPromptProvider(mockPrompt)

	ctx := context.Background()
	req := ApprovalRequest{
		ProcessName: "test-process",
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	var decision Decision
	var userDecision UserDecision
	done := make(chan struct{})
	go func() {
		decision, userDecision, _ = ap.RequestApproval(ctx, req)
		close(done)
	}()

	// Wait for pending
	time.Sleep(50 * time.Millisecond)

	// Get the pending ID and resolve it
	pending := ap.ListPending()
	if len(pending) == 0 {
		close(blockCh)
		t.Fatal("expected pending request")
	}

	ok := ap.Resolve(pending[0].ID, UserDecisionAllowPermanent, "test reason")
	if !ok {
		close(blockCh)
		t.Fatal("expected Resolve to return true")
	}

	close(blockCh)
	<-done

	if decision != DecisionAllow {
		t.Errorf("expected decision Allow, got %s", decision)
	}
	if userDecision != UserDecisionAllowPermanent {
		t.Errorf("expected user decision AllowPermanent, got %s", userDecision)
	}
}

func TestApprovalProvider_IPTarget_PersistsAsIP(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 5 * time.Second

	ap := NewApprovalProvider(config)

	mockPrompt := &MockPromptProvider{
		response: ApprovalResponse{
			Decision:   UserDecisionAllowPermanent,
			Persistent: true,
		},
		delay: 10 * time.Millisecond,
	}
	ap.SetPromptProvider(mockPrompt)

	mockPersister := NewInMemoryRulePersister()
	ap.SetRulePersister(mockPersister)

	ctx := context.Background()
	req := ApprovalRequest{
		ProcessName: "test-process",
		Target:      "192.168.1.100", // IP address, not hostname
		Port:        8080,
		Protocol:    "tcp",
	}

	_, _, err := ap.RequestApproval(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify rule was persisted with IP field
	rules := mockPersister.GetRules("test-process")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].IP != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %s", rules[0].IP)
	}
	if rules[0].Host != "" {
		t.Errorf("expected empty Host, got %s", rules[0].Host)
	}
}

func TestApprovalProvider_ConcurrentRequests(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 5 * time.Second

	ap := NewApprovalProvider(config)

	var callCount int
	var mu sync.Mutex

	mockPrompt := &MockPromptProvider{
		onPrompt: func(req ApprovalRequest) (ApprovalResponse, error) {
			mu.Lock()
			callCount++
			mu.Unlock()
			time.Sleep(50 * time.Millisecond)
			return ApprovalResponse{
				RequestID: req.ID,
				Decision:  UserDecisionAllowOnce,
				At:        time.Now().UTC(),
			}, nil
		},
	}
	ap.SetPromptProvider(mockPrompt)

	ctx := context.Background()
	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := ApprovalRequest{
				ProcessName: "test-process",
				Target:      "api.example.com",
				Port:        443 + i,
				Protocol:    "tcp",
			}
			decision, _, err := ap.RequestApproval(ctx, req)
			if err != nil {
				t.Errorf("request %d: unexpected error: %v", i, err)
			}
			if decision != DecisionAllow {
				t.Errorf("request %d: expected Allow, got %s", i, decision)
			}
		}(i)
	}

	wg.Wait()

	mu.Lock()
	if callCount != 5 {
		t.Errorf("expected 5 prompt calls, got %d", callCount)
	}
	mu.Unlock()
}

func TestApprovalProvider_Timeout_UseDefaultFallback(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 100 * time.Millisecond
	config.TimeoutFallback = DecisionUseDefault
	// Simulate policy engine returning allow as the default
	config.DefaultDecisionFn = func() Decision {
		return DecisionAllow
	}

	ap := NewApprovalProvider(config)

	mockPrompt := &MockPromptProvider{
		delay: 1 * time.Second, // Longer than timeout
	}
	ap.SetPromptProvider(mockPrompt)

	mockEmitter := &MockEventEmitter{}
	ap.SetEventEmitter(mockEmitter)

	ctx := context.Background()
	req := ApprovalRequest{
		ProcessName: "test-process",
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	decision, userDecision, err := ap.RequestApproval(ctx, req)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	// Should use the value from DefaultDecisionFn (allow)
	if decision != DecisionAllow {
		t.Errorf("expected decision Allow from use_default, got %s", decision)
	}
	if userDecision != UserDecisionTimeout {
		t.Errorf("expected user decision Timeout, got %s", userDecision)
	}
}

func TestApprovalProvider_Timeout_UseDefaultFallback_NilFn(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 100 * time.Millisecond
	config.TimeoutFallback = DecisionUseDefault
	// DefaultDecisionFn is nil - should fall back to deny for safety

	ap := NewApprovalProvider(config)

	mockPrompt := &MockPromptProvider{
		delay: 1 * time.Second,
	}
	ap.SetPromptProvider(mockPrompt)

	ctx := context.Background()
	req := ApprovalRequest{
		ProcessName: "test-process",
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	decision, _, err := ap.RequestApproval(ctx, req)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	// With nil DefaultDecisionFn, should fall back to deny
	if decision != DecisionDeny {
		t.Errorf("expected decision Deny when DefaultDecisionFn is nil, got %s", decision)
	}
}

func TestApprovalProvider_Skip_UseDefaultFallback(t *testing.T) {
	config := DefaultApprovalConfig()
	config.Timeout = 5 * time.Second
	config.TimeoutFallback = DecisionUseDefault
	// Simulate policy engine returning audit as the default
	config.DefaultDecisionFn = func() Decision {
		return DecisionAudit
	}

	ap := NewApprovalProvider(config)

	mockPrompt := &MockPromptProvider{
		response: ApprovalResponse{
			Decision: UserDecisionSkip,
		},
		delay: 10 * time.Millisecond,
	}
	ap.SetPromptProvider(mockPrompt)

	ctx := context.Background()
	req := ApprovalRequest{
		ProcessName: "test-process",
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	decision, userDecision, err := ap.RequestApproval(ctx, req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Skip should also use DefaultDecisionFn
	if decision != DecisionAudit {
		t.Errorf("expected decision Audit from use_default on skip, got %s", decision)
	}
	if userDecision != UserDecisionSkip {
		t.Errorf("expected user decision Skip, got %s", userDecision)
	}
}
