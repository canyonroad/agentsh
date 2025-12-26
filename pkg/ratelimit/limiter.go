// Package ratelimit provides rate limiting and quota management for agentsh.
package ratelimit

import (
	"sync"
	"time"
)

// Config defines rate limit configuration.
type Config struct {
	// Session limits
	Session SessionLimits `json:"session" yaml:"session"`

	// Agent limits (across all sessions)
	Agent AgentLimits `json:"agent" yaml:"agent"`

	// Tenant limits
	Tenant TenantLimits `json:"tenant" yaml:"tenant"`

	// Global limits
	Global GlobalLimits `json:"global" yaml:"global"`

	// Actions when limits exceeded
	Actions ActionConfig `json:"actions" yaml:"actions"`
}

// SessionLimits defines per-session rate limits.
type SessionLimits struct {
	FileOpsPerSecond     float64 `json:"file_ops_per_second" yaml:"file_ops_per_second"`
	NetworkConnsPerSecond float64 `json:"network_conns_per_second" yaml:"network_conns_per_second"`
	DNSQueriesPerSecond  float64 `json:"dns_queries_per_second" yaml:"dns_queries_per_second"`
	BurstMultiplier      float64 `json:"burst_multiplier" yaml:"burst_multiplier"`
}

// AgentLimits defines per-agent limits.
type AgentLimits struct {
	MaxConcurrentSessions    int   `json:"max_concurrent_sessions" yaml:"max_concurrent_sessions"`
	MaxTotalOperationsPerHour int64 `json:"max_total_operations_per_hour" yaml:"max_total_operations_per_hour"`
}

// TenantLimits defines per-tenant limits.
type TenantLimits struct {
	MaxConcurrentSessions int   `json:"max_concurrent_sessions" yaml:"max_concurrent_sessions"`
	MaxStorageBytes       int64 `json:"max_storage_bytes" yaml:"max_storage_bytes"`
	MaxNetworkBytesPerDay int64 `json:"max_network_bytes_per_day" yaml:"max_network_bytes_per_day"`
}

// GlobalLimits defines global limits.
type GlobalLimits struct {
	MaxConcurrentSessions int `json:"max_concurrent_sessions" yaml:"max_concurrent_sessions"`
	MaxPendingApprovals   int `json:"max_pending_approvals" yaml:"max_pending_approvals"`
}

// ActionConfig defines actions when limits are exceeded.
type ActionConfig struct {
	FileOps     LimitAction `json:"file_ops" yaml:"file_ops"`
	NetworkConns LimitAction `json:"network_conns" yaml:"network_conns"`
	DNSQueries  LimitAction `json:"dns_queries" yaml:"dns_queries"`
}

// LimitAction defines what happens when a limit is exceeded.
type LimitAction struct {
	Action  ActionType `json:"action" yaml:"action"`
	DelayMs int        `json:"delay_ms,omitempty" yaml:"delay_ms,omitempty"`
	Message string     `json:"message,omitempty" yaml:"message,omitempty"`
}

// ActionType represents the type of action to take.
type ActionType string

const (
	ActionThrottle ActionType = "throttle"
	ActionBlock    ActionType = "block"
	ActionAlert    ActionType = "alert"
)

// DefaultConfig returns sensible default rate limit configuration.
func DefaultConfig() Config {
	return Config{
		Session: SessionLimits{
			FileOpsPerSecond:      1000,
			NetworkConnsPerSecond: 100,
			DNSQueriesPerSecond:   50,
			BurstMultiplier:       5,
		},
		Agent: AgentLimits{
			MaxConcurrentSessions:    10,
			MaxTotalOperationsPerHour: 1000000,
		},
		Tenant: TenantLimits{
			MaxConcurrentSessions: 100,
			MaxStorageBytes:       10 * 1024 * 1024 * 1024, // 10GB
			MaxNetworkBytesPerDay: 100 * 1024 * 1024 * 1024, // 100GB
		},
		Global: GlobalLimits{
			MaxConcurrentSessions: 1000,
			MaxPendingApprovals:   100,
		},
		Actions: ActionConfig{
			FileOps: LimitAction{
				Action:  ActionThrottle,
				DelayMs: 100,
			},
			NetworkConns: LimitAction{
				Action:  ActionBlock,
				Message: "Connection rate limit exceeded",
			},
			DNSQueries: LimitAction{
				Action:  ActionThrottle,
				DelayMs: 50,
			},
		},
	}
}

// ResourceType identifies the type of resource being rate limited.
type ResourceType string

const (
	ResourceFileOps     ResourceType = "file_ops"
	ResourceNetworkConns ResourceType = "network_conns"
	ResourceDNSQueries  ResourceType = "dns_queries"
	ResourceOperations  ResourceType = "operations"
	ResourceStorage     ResourceType = "storage"
	ResourceNetworkBytes ResourceType = "network_bytes"
)

// Limiter provides token bucket rate limiting.
type Limiter struct {
	rate      float64 // tokens per second
	burst     int     // maximum burst size
	tokens    float64
	lastTime  time.Time
	mu        sync.Mutex
}

// NewLimiter creates a new rate limiter.
func NewLimiter(rate float64, burst int) *Limiter {
	return &Limiter{
		rate:     rate,
		burst:    burst,
		tokens:   float64(burst),
		lastTime: time.Now(),
	}
}

// Allow checks if an operation is allowed and consumes a token if so.
func (l *Limiter) Allow() bool {
	return l.AllowN(1)
}

// AllowN checks if n operations are allowed and consumes n tokens if so.
func (l *Limiter) AllowN(n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastTime).Seconds()
	l.lastTime = now

	// Add tokens based on elapsed time
	l.tokens += elapsed * l.rate
	if l.tokens > float64(l.burst) {
		l.tokens = float64(l.burst)
	}

	// Check if we have enough tokens
	if l.tokens >= float64(n) {
		l.tokens -= float64(n)
		return true
	}

	return false
}

// Wait waits until a token is available and consumes it.
func (l *Limiter) Wait() time.Duration {
	return l.WaitN(1)
}

// WaitN waits until n tokens are available, consumes them, and returns the wait duration.
func (l *Limiter) WaitN(n int) time.Duration {
	l.mu.Lock()

	now := time.Now()
	elapsed := now.Sub(l.lastTime).Seconds()
	l.lastTime = now

	// Add tokens based on elapsed time
	l.tokens += elapsed * l.rate
	if l.tokens > float64(l.burst) {
		l.tokens = float64(l.burst)
	}

	// Check if we have enough tokens
	if l.tokens >= float64(n) {
		l.tokens -= float64(n)
		l.mu.Unlock()
		return 0
	}

	// Calculate wait time
	needed := float64(n) - l.tokens
	waitDuration := time.Duration(needed / l.rate * float64(time.Second))

	l.tokens = 0 // Will be replenished when we wake up
	l.mu.Unlock()

	time.Sleep(waitDuration)

	l.mu.Lock()
	l.tokens = float64(n) - needed // Account for replenishment during sleep
	l.tokens -= float64(n)
	if l.tokens < 0 {
		l.tokens = 0
	}
	l.lastTime = time.Now()
	l.mu.Unlock()

	return waitDuration
}

// Tokens returns the current number of available tokens.
func (l *Limiter) Tokens() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastTime).Seconds()

	tokens := l.tokens + elapsed*l.rate
	if tokens > float64(l.burst) {
		tokens = float64(l.burst)
	}

	return tokens
}

// Rate returns the token refill rate per second.
func (l *Limiter) Rate() float64 {
	return l.rate
}

// Burst returns the maximum burst size.
func (l *Limiter) Burst() int {
	return l.burst
}

// SetRate updates the rate limit.
func (l *Limiter) SetRate(rate float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rate = rate
}

// SetBurst updates the burst limit.
func (l *Limiter) SetBurst(burst int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.burst = burst
	if l.tokens > float64(burst) {
		l.tokens = float64(burst)
	}
}
