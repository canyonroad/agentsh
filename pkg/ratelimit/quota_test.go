package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNewQuotaManager(t *testing.T) {
	cfg := DefaultConfig()
	qm := NewQuotaManager(cfg)

	if qm == nil {
		t.Fatal("NewQuotaManager returned nil")
	}
}

func TestQuotaManager_GetSessionLimiter(t *testing.T) {
	cfg := DefaultConfig()
	qm := NewQuotaManager(cfg)

	l1 := qm.GetSessionLimiter("sess-1", ResourceFileOps)
	if l1 == nil {
		t.Fatal("GetSessionLimiter returned nil")
	}

	// Same session/resource should return same limiter
	l2 := qm.GetSessionLimiter("sess-1", ResourceFileOps)
	if l1 != l2 {
		t.Error("GetSessionLimiter should return same instance for same session/resource")
	}

	// Different resource should return different limiter
	l3 := qm.GetSessionLimiter("sess-1", ResourceNetworkConns)
	if l1 == l3 {
		t.Error("GetSessionLimiter should return different instance for different resource")
	}
}

func TestQuotaManager_CheckRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Session.FileOpsPerSecond = 5
	cfg.Session.BurstMultiplier = 2
	qm := NewQuotaManager(cfg)

	// Should allow within burst
	for i := 0; i < 10; i++ {
		allowed, _ := qm.CheckRateLimit("sess-1", ResourceFileOps)
		if !allowed {
			t.Logf("Denied at attempt %d (expected around burst limit)", i+1)
			break
		}
	}
}

func TestQuotaManager_CheckRateLimit_Action(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Session.FileOpsPerSecond = 1
	cfg.Session.BurstMultiplier = 1
	cfg.Actions.FileOps = LimitAction{
		Action:  ActionThrottle,
		DelayMs: 100,
	}
	qm := NewQuotaManager(cfg)

	// Exhaust burst
	qm.CheckRateLimit("sess-1", ResourceFileOps)

	// Next should return action
	allowed, action := qm.CheckRateLimit("sess-1", ResourceFileOps)
	if allowed {
		t.Error("Should not be allowed after burst exhausted")
	}
	if action.Action != ActionThrottle {
		t.Errorf("Action = %v, want throttle", action.Action)
	}
	if action.DelayMs != 100 {
		t.Errorf("DelayMs = %d, want 100", action.DelayMs)
	}
}

func TestQuotaManager_WaitForRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Session.FileOpsPerSecond = 1000
	cfg.Session.BurstMultiplier = 1
	cfg.Actions.FileOps = LimitAction{
		Action:  ActionThrottle,
		DelayMs: 10,
	}
	qm := NewQuotaManager(cfg)

	ctx := context.Background()

	// First should be immediate
	err := qm.WaitForRateLimit(ctx, "sess-1", ResourceFileOps)
	if err != nil {
		t.Errorf("First WaitForRateLimit error: %v", err)
	}

	// Second should wait (throttle)
	start := time.Now()
	err = qm.WaitForRateLimit(ctx, "sess-1", ResourceFileOps)
	if err != nil {
		t.Errorf("Second WaitForRateLimit error: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 5*time.Millisecond {
		t.Logf("Elapsed = %v (expected some delay from throttle)", elapsed)
	}
}

func TestQuotaManager_WaitForRateLimit_Block(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Session.NetworkConnsPerSecond = 1
	cfg.Session.BurstMultiplier = 1
	cfg.Actions.NetworkConns = LimitAction{
		Action:  ActionBlock,
		Message: "blocked",
	}
	qm := NewQuotaManager(cfg)

	ctx := context.Background()

	// First should succeed
	err := qm.WaitForRateLimit(ctx, "sess-1", ResourceNetworkConns)
	if err != nil {
		t.Errorf("First WaitForRateLimit error: %v", err)
	}

	// Second should be blocked
	err = qm.WaitForRateLimit(ctx, "sess-1", ResourceNetworkConns)
	if err == nil {
		t.Error("Second WaitForRateLimit should return error for block action")
	}
}

func TestQuotaManager_GetQuota(t *testing.T) {
	cfg := DefaultConfig()
	qm := NewQuotaManager(cfg)

	q := qm.GetQuota("agent", "agent-1", ResourceOperations)
	if q == nil {
		t.Fatal("GetQuota returned nil")
	}
	if q.Limit != cfg.Agent.MaxTotalOperationsPerHour {
		t.Errorf("Limit = %d, want %d", q.Limit, cfg.Agent.MaxTotalOperationsPerHour)
	}
}

func TestQuotaManager_CheckAndConsume(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.MaxTotalOperationsPerHour = 100
	qm := NewQuotaManager(cfg)

	ctx := context.Background()

	// Should succeed
	err := qm.CheckAndConsume(ctx, "agent", "agent-1", ResourceOperations, 50)
	if err != nil {
		t.Errorf("CheckAndConsume error: %v", err)
	}

	// Check usage
	used, limit, pct := qm.GetUsage("agent", "agent-1", ResourceOperations)
	if used != 50 {
		t.Errorf("used = %d, want 50", used)
	}
	if limit != 100 {
		t.Errorf("limit = %d, want 100", limit)
	}
	if pct != 50 {
		t.Errorf("percentage = %v, want 50", pct)
	}
}

func TestQuotaManager_CheckAndConsume_Exceed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.MaxTotalOperationsPerHour = 100
	qm := NewQuotaManager(cfg)

	ctx := context.Background()

	// Use 80
	qm.CheckAndConsume(ctx, "agent", "agent-1", ResourceOperations, 80)

	// Try to use 30 more (would exceed)
	err := qm.CheckAndConsume(ctx, "agent", "agent-1", ResourceOperations, 30)
	if err == nil {
		t.Error("CheckAndConsume should return error when exceeding quota")
	}

	qerr, ok := err.(*QuotaExceededError)
	if !ok {
		t.Fatalf("expected QuotaExceededError, got %T", err)
	}
	if qerr.Limit != 100 {
		t.Errorf("Limit = %d, want 100", qerr.Limit)
	}
	if qerr.Used != 80 {
		t.Errorf("Used = %d, want 80", qerr.Used)
	}
	if qerr.Requested != 30 {
		t.Errorf("Requested = %d, want 30", qerr.Requested)
	}
}

func TestQuotaManager_WarningCallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.MaxTotalOperationsPerHour = 100
	qm := NewQuotaManager(cfg)

	var warned bool
	var warnedPct float64
	qm.OnWarning(func(id string, resource ResourceType, pct float64) {
		warned = true
		warnedPct = pct
	})

	ctx := context.Background()

	// Use 81% (should trigger warning)
	qm.CheckAndConsume(ctx, "agent", "agent-1", ResourceOperations, 81)

	if !warned {
		t.Error("Warning callback should have been called")
	}
	if warnedPct != 81 {
		t.Errorf("Warning percentage = %v, want 81", warnedPct)
	}
}

func TestQuotaManager_ResetQuota(t *testing.T) {
	cfg := DefaultConfig()
	qm := NewQuotaManager(cfg)

	ctx := context.Background()
	qm.CheckAndConsume(ctx, "agent", "agent-1", ResourceOperations, 50)

	qm.ResetQuota("agent", "agent-1", ResourceOperations)

	used, _, _ := qm.GetUsage("agent", "agent-1", ResourceOperations)
	if used != 0 {
		t.Errorf("used = %d, want 0 after reset", used)
	}
}

func TestQuotaExceededError_Error(t *testing.T) {
	err := &QuotaExceededError{
		Resource:  ResourceOperations,
		Limit:     100,
		Used:      80,
		Requested: 30,
	}

	msg := err.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
}

func TestNewSessionCounter(t *testing.T) {
	cfg := DefaultConfig()
	c := NewSessionCounter(cfg)

	if c == nil {
		t.Fatal("NewSessionCounter returned nil")
	}
}

func TestSessionCounter_TryAcquireSession(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.MaxConcurrentSessions = 2
	cfg.Tenant.MaxConcurrentSessions = 3
	cfg.Global.MaxConcurrentSessions = 5
	c := NewSessionCounter(cfg)

	// Should succeed
	err := c.TryAcquireSession("agent-1", "tenant-1")
	if err != nil {
		t.Errorf("TryAcquireSession error: %v", err)
	}

	// Should succeed again
	err = c.TryAcquireSession("agent-1", "tenant-1")
	if err != nil {
		t.Errorf("TryAcquireSession error: %v", err)
	}

	// Third should fail (agent limit = 2)
	err = c.TryAcquireSession("agent-1", "tenant-1")
	if err == nil {
		t.Error("TryAcquireSession should fail when agent limit exceeded")
	}
}

func TestSessionCounter_ReleaseSession(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.MaxConcurrentSessions = 1
	c := NewSessionCounter(cfg)

	c.TryAcquireSession("agent-1", "tenant-1")

	// Should fail (limit reached)
	err := c.TryAcquireSession("agent-1", "tenant-1")
	if err == nil {
		t.Error("Should fail when limit reached")
	}

	// Release
	c.ReleaseSession("agent-1", "tenant-1")

	// Should succeed now
	err = c.TryAcquireSession("agent-1", "tenant-1")
	if err != nil {
		t.Errorf("TryAcquireSession after release error: %v", err)
	}
}

func TestSessionCounter_GetCounts(t *testing.T) {
	cfg := DefaultConfig()
	c := NewSessionCounter(cfg)

	c.TryAcquireSession("agent-1", "tenant-1")
	c.TryAcquireSession("agent-1", "tenant-1")
	c.TryAcquireSession("agent-2", "tenant-1")

	global, agent, tenant := c.GetCounts()

	if global["global"] != 3 {
		t.Errorf("global = %d, want 3", global["global"])
	}
	if agent["agent-1"] != 2 {
		t.Errorf("agent-1 = %d, want 2", agent["agent-1"])
	}
	if agent["agent-2"] != 1 {
		t.Errorf("agent-2 = %d, want 1", agent["agent-2"])
	}
	if tenant["tenant-1"] != 3 {
		t.Errorf("tenant-1 = %d, want 3", tenant["tenant-1"])
	}
}

func TestNewApprovalLimiter(t *testing.T) {
	a := NewApprovalLimiter(10)

	if a == nil {
		t.Fatal("NewApprovalLimiter returned nil")
	}
	if a.MaxPending() != 10 {
		t.Errorf("MaxPending() = %d, want 10", a.MaxPending())
	}
}

func TestApprovalLimiter_TryAcquire(t *testing.T) {
	a := NewApprovalLimiter(2)

	if !a.TryAcquire() {
		t.Error("First TryAcquire should succeed")
	}
	if !a.TryAcquire() {
		t.Error("Second TryAcquire should succeed")
	}
	if a.TryAcquire() {
		t.Error("Third TryAcquire should fail (limit = 2)")
	}
}

func TestApprovalLimiter_Release(t *testing.T) {
	a := NewApprovalLimiter(1)

	a.TryAcquire()
	if a.TryAcquire() {
		t.Error("Should fail when limit reached")
	}

	a.Release()
	if !a.TryAcquire() {
		t.Error("Should succeed after release")
	}
}

func TestApprovalLimiter_Pending(t *testing.T) {
	a := NewApprovalLimiter(10)

	if a.Pending() != 0 {
		t.Errorf("Pending() = %d, want 0", a.Pending())
	}

	a.TryAcquire()
	a.TryAcquire()

	if a.Pending() != 2 {
		t.Errorf("Pending() = %d, want 2", a.Pending())
	}
}

func TestQuotaManager_Concurrent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.MaxTotalOperationsPerHour = 10000
	qm := NewQuotaManager(cfg)

	ctx := context.Background()
	var wg sync.WaitGroup

	// Concurrent consumption
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			qm.CheckAndConsume(ctx, "agent", "agent-1", ResourceOperations, 10)
		}()
	}

	wg.Wait()

	used, _, _ := qm.GetUsage("agent", "agent-1", ResourceOperations)
	if used != 1000 {
		t.Errorf("used = %d, want 1000", used)
	}
}
