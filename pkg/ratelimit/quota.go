package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// QuotaManager manages resource quotas across sessions, agents, and tenants.
type QuotaManager struct {
	config   Config
	limiters map[string]*Limiter
	quotas   map[string]*ResourceQuota
	mu       sync.RWMutex

	// Callbacks
	onWarning func(id string, resource ResourceType, percentage float64)
	onExceed  func(id string, resource ResourceType, err *QuotaExceededError)
}

// ResourceQuota tracks usage of a resource.
type ResourceQuota struct {
	Resource   ResourceType `json:"resource"`
	Limit      int64        `json:"limit"`
	Used       int64        `json:"used"`
	ResetAt    time.Time    `json:"reset_at"`
	Percentage float64      `json:"percentage"`
	mu         sync.Mutex
}

// QuotaExceededError is returned when a quota is exceeded.
type QuotaExceededError struct {
	Resource  ResourceType
	Limit     int64
	Used      int64
	Requested int64
}

func (e *QuotaExceededError) Error() string {
	return fmt.Sprintf("quota exceeded for %s: limit=%d, used=%d, requested=%d",
		e.Resource, e.Limit, e.Used, e.Requested)
}

// NewQuotaManager creates a new quota manager.
func NewQuotaManager(config Config) *QuotaManager {
	return &QuotaManager{
		config:   config,
		limiters: make(map[string]*Limiter),
		quotas:   make(map[string]*ResourceQuota),
	}
}

// OnWarning sets a callback for quota warnings (approaching limit).
func (q *QuotaManager) OnWarning(fn func(id string, resource ResourceType, percentage float64)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.onWarning = fn
}

// OnExceed sets a callback for quota exceeded events.
func (q *QuotaManager) OnExceed(fn func(id string, resource ResourceType, err *QuotaExceededError)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.onExceed = fn
}

// GetSessionLimiter returns a rate limiter for a session and resource type.
func (q *QuotaManager) GetSessionLimiter(sessionID string, resource ResourceType) *Limiter {
	key := fmt.Sprintf("session:%s:%s", sessionID, resource)

	q.mu.RLock()
	limiter, exists := q.limiters[key]
	q.mu.RUnlock()

	if exists {
		return limiter
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists = q.limiters[key]; exists {
		return limiter
	}

	// Create new limiter based on resource type
	var rate float64
	var burst int

	switch resource {
	case ResourceFileOps:
		rate = q.config.Session.FileOpsPerSecond
		burst = int(rate * q.config.Session.BurstMultiplier)
	case ResourceNetworkConns:
		rate = q.config.Session.NetworkConnsPerSecond
		burst = int(rate * q.config.Session.BurstMultiplier)
	case ResourceDNSQueries:
		rate = q.config.Session.DNSQueriesPerSecond
		burst = int(rate * q.config.Session.BurstMultiplier)
	default:
		rate = 100
		burst = 500
	}

	if burst < 1 {
		burst = 1
	}

	limiter = NewLimiter(rate, burst)
	q.limiters[key] = limiter

	return limiter
}

// CheckRateLimit checks if an operation is allowed by rate limits.
func (q *QuotaManager) CheckRateLimit(sessionID string, resource ResourceType) (allowed bool, action LimitAction) {
	limiter := q.GetSessionLimiter(sessionID, resource)

	if limiter.Allow() {
		return true, LimitAction{}
	}

	// Get action for this resource
	switch resource {
	case ResourceFileOps:
		action = q.config.Actions.FileOps
	case ResourceNetworkConns:
		action = q.config.Actions.NetworkConns
	case ResourceDNSQueries:
		action = q.config.Actions.DNSQueries
	default:
		action = LimitAction{Action: ActionBlock}
	}

	return false, action
}

// WaitForRateLimit waits until an operation is allowed by rate limits.
func (q *QuotaManager) WaitForRateLimit(ctx context.Context, sessionID string, resource ResourceType) error {
	limiter := q.GetSessionLimiter(sessionID, resource)

	// Check if we can proceed immediately
	if limiter.Allow() {
		return nil
	}

	// Get action for this resource
	var action LimitAction
	switch resource {
	case ResourceFileOps:
		action = q.config.Actions.FileOps
	case ResourceNetworkConns:
		action = q.config.Actions.NetworkConns
	case ResourceDNSQueries:
		action = q.config.Actions.DNSQueries
	default:
		action = LimitAction{Action: ActionBlock}
	}

	switch action.Action {
	case ActionBlock:
		return fmt.Errorf("rate limit exceeded: %s", action.Message)
	case ActionThrottle:
		delay := time.Duration(action.DelayMs) * time.Millisecond
		select {
		case <-time.After(delay):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	case ActionAlert:
		// Alert but allow
		return nil
	}

	return nil
}

// getQuotaKey returns the storage key for a quota.
func getQuotaKey(scope, id string, resource ResourceType) string {
	return fmt.Sprintf("%s:%s:%s", scope, id, resource)
}

// GetQuota returns the current quota for a resource.
func (q *QuotaManager) GetQuota(scope, id string, resource ResourceType) *ResourceQuota {
	key := getQuotaKey(scope, id, resource)

	q.mu.RLock()
	quota, exists := q.quotas[key]
	q.mu.RUnlock()

	if exists {
		return quota
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// Double-check
	if quota, exists = q.quotas[key]; exists {
		return quota
	}

	// Create new quota based on scope and resource
	var limit int64
	var resetDuration time.Duration

	switch scope {
	case "agent":
		switch resource {
		case ResourceOperations:
			limit = q.config.Agent.MaxTotalOperationsPerHour
			resetDuration = time.Hour
		default:
			limit = 1000000
			resetDuration = time.Hour
		}
	case "tenant":
		switch resource {
		case ResourceStorage:
			limit = q.config.Tenant.MaxStorageBytes
			resetDuration = 0 // Never resets
		case ResourceNetworkBytes:
			limit = q.config.Tenant.MaxNetworkBytesPerDay
			resetDuration = 24 * time.Hour
		default:
			limit = 1000000000
			resetDuration = 24 * time.Hour
		}
	default:
		limit = 1000000
		resetDuration = time.Hour
	}

	resetAt := time.Time{}
	if resetDuration > 0 {
		resetAt = time.Now().Add(resetDuration)
	}

	quota = &ResourceQuota{
		Resource: resource,
		Limit:    limit,
		Used:     0,
		ResetAt:  resetAt,
	}

	q.quotas[key] = quota
	return quota
}

// CheckAndConsume checks if quota allows consumption and consumes if so.
func (q *QuotaManager) CheckAndConsume(ctx context.Context, scope, id string, resource ResourceType, amount int64) error {
	quota := q.GetQuota(scope, id, resource)

	quota.mu.Lock()
	defer quota.mu.Unlock()

	// Check if quota has reset
	if !quota.ResetAt.IsZero() && time.Now().After(quota.ResetAt) {
		quota.Used = 0
		// Calculate next reset time
		switch resource {
		case ResourceOperations:
			quota.ResetAt = time.Now().Add(time.Hour)
		case ResourceNetworkBytes:
			quota.ResetAt = time.Now().Add(24 * time.Hour)
		}
	}

	// Check if consumption would exceed limit
	if quota.Used+amount > quota.Limit {
		err := &QuotaExceededError{
			Resource:  resource,
			Limit:     quota.Limit,
			Used:      quota.Used,
			Requested: amount,
		}

		q.mu.RLock()
		onExceed := q.onExceed
		q.mu.RUnlock()

		if onExceed != nil {
			onExceed(id, resource, err)
		}

		return err
	}

	// Consume quota
	oldPct := quota.Percentage
	quota.Used += amount
	quota.Percentage = float64(quota.Used) / float64(quota.Limit) * 100

	// Alert if crossing 80% threshold
	if quota.Percentage > 80 && oldPct <= 80 {
		q.mu.RLock()
		onWarning := q.onWarning
		q.mu.RUnlock()

		if onWarning != nil {
			onWarning(id, resource, quota.Percentage)
		}
	}

	return nil
}

// GetUsage returns the current usage for a quota.
func (q *QuotaManager) GetUsage(scope, id string, resource ResourceType) (used, limit int64, percentage float64) {
	quota := q.GetQuota(scope, id, resource)

	quota.mu.Lock()
	defer quota.mu.Unlock()

	return quota.Used, quota.Limit, quota.Percentage
}

// ResetQuota resets a quota to zero usage.
func (q *QuotaManager) ResetQuota(scope, id string, resource ResourceType) {
	quota := q.GetQuota(scope, id, resource)

	quota.mu.Lock()
	defer quota.mu.Unlock()

	quota.Used = 0
	quota.Percentage = 0
}

// SessionCounter tracks concurrent session counts.
type SessionCounter struct {
	config  Config
	counts  map[string]int // key -> count
	mu      sync.Mutex
}

// NewSessionCounter creates a new session counter.
func NewSessionCounter(config Config) *SessionCounter {
	return &SessionCounter{
		config: config,
		counts: make(map[string]int),
	}
}

// TryAcquireSession attempts to acquire a session slot.
func (c *SessionCounter) TryAcquireSession(agentID, tenantID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check global limit
	globalKey := "global"
	if c.counts[globalKey] >= c.config.Global.MaxConcurrentSessions {
		return fmt.Errorf("global session limit exceeded: %d", c.config.Global.MaxConcurrentSessions)
	}

	// Check agent limit
	agentKey := "agent:" + agentID
	if c.counts[agentKey] >= c.config.Agent.MaxConcurrentSessions {
		return fmt.Errorf("agent session limit exceeded: %d", c.config.Agent.MaxConcurrentSessions)
	}

	// Check tenant limit
	tenantKey := "tenant:" + tenantID
	if c.counts[tenantKey] >= c.config.Tenant.MaxConcurrentSessions {
		return fmt.Errorf("tenant session limit exceeded: %d", c.config.Tenant.MaxConcurrentSessions)
	}

	// Acquire slots
	c.counts[globalKey]++
	c.counts[agentKey]++
	c.counts[tenantKey]++

	return nil
}

// ReleaseSession releases a session slot.
func (c *SessionCounter) ReleaseSession(agentID, tenantID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	globalKey := "global"
	if c.counts[globalKey] > 0 {
		c.counts[globalKey]--
	}

	agentKey := "agent:" + agentID
	if c.counts[agentKey] > 0 {
		c.counts[agentKey]--
	}

	tenantKey := "tenant:" + tenantID
	if c.counts[tenantKey] > 0 {
		c.counts[tenantKey]--
	}
}

// GetCounts returns current session counts.
func (c *SessionCounter) GetCounts() (global, agent, tenant map[string]int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	global = map[string]int{"global": c.counts["global"]}
	agent = make(map[string]int)
	tenant = make(map[string]int)

	for k, v := range c.counts {
		if len(k) > 6 && k[:6] == "agent:" {
			agent[k[6:]] = v
		} else if len(k) > 7 && k[:7] == "tenant:" {
			tenant[k[7:]] = v
		}
	}

	return
}

// ApprovalLimiter limits the number of pending approvals.
type ApprovalLimiter struct {
	maxPending int
	pending    int
	mu         sync.Mutex
}

// NewApprovalLimiter creates a new approval limiter.
func NewApprovalLimiter(maxPending int) *ApprovalLimiter {
	return &ApprovalLimiter{
		maxPending: maxPending,
	}
}

// TryAcquire attempts to acquire a pending approval slot.
func (a *ApprovalLimiter) TryAcquire() bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.pending >= a.maxPending {
		return false
	}

	a.pending++
	return true
}

// Release releases a pending approval slot.
func (a *ApprovalLimiter) Release() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.pending > 0 {
		a.pending--
	}
}

// Pending returns the current number of pending approvals.
func (a *ApprovalLimiter) Pending() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pending
}

// MaxPending returns the maximum allowed pending approvals.
func (a *ApprovalLimiter) MaxPending() int {
	return a.maxPending
}
