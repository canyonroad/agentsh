package events

import (
	"context"
	"strconv"
	"sync"
	"time"

	dbservice "github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

const bypassDedupeWindow = 60 * time.Second

// AuditEmitter is the durable audit event surface used by bypass attempts.
type AuditEmitter interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	Publish(ev types.Event)
}

// BypassAttempt carries the runtime denial context for a possible DB bypass.
type BypassAttempt struct {
	Engine          *policy.Engine
	SessionID       string
	CommandID       string
	ProcessID       int
	ProcessIdentity string
	RuleName        string
	Reason          string
}

type BypassEmitterOption func(*BypassEmitter)

func WithBypassNow(now func() time.Time) BypassEmitterOption {
	return func(b *BypassEmitter) {
		if now != nil {
			b.now = now
		}
	}
}

type BypassEmitter struct {
	emit AuditEmitter
	now  func() time.Time

	mu      sync.Mutex
	windows map[bypassKey]bypassState
	nextGen uint64
}

type bypassKey struct {
	sessionID       string
	processIdentity string
	destination     string
}

type bypassState struct {
	windowStart time.Time
	suppressed  int
	generation  uint64
}

type bypassSnapshot struct {
	existed             bool
	state               bypassState
	installedGeneration uint64
}

func NewBypassEmitter(emit AuditEmitter, opts ...BypassEmitterOption) *BypassEmitter {
	b := &BypassEmitter{
		emit:    emit,
		now:     func() time.Time { return time.Now().UTC() },
		windows: make(map[bypassKey]bypassState),
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

func (b *BypassEmitter) EmitIfDBUnavoidabilityDeny(ctx context.Context, in BypassAttempt) bool {
	if b == nil || b.emit == nil || in.Engine == nil || in.SessionID == "" || in.RuleName == "" {
		return false
	}
	meta, ok := RuleMetadataFor(in.Engine, in.RuleName)
	if !ok || meta.Source != dbservice.RuleSourceDBUnavoidability {
		return false
	}

	now := b.now().UTC()
	processIdentity := processIdentityFor(in.ProcessIdentity, in.ProcessID)
	key := bypassKey{
		sessionID:       in.SessionID,
		processIdentity: processIdentity,
		destination:     meta.Destination,
	}
	suppressedCount, shouldEmit, snapshot := b.record(key, now)
	if !shouldEmit {
		return false
	}

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: now,
		Type:      "db_bypass_attempt",
		SessionID: in.SessionID,
		CommandID: in.CommandID,
		PID:       in.ProcessID,
		Fields: map[string]any{
			"process_id":       in.ProcessID,
			"process_identity": processIdentity,
			"db_service":       meta.DBService,
			"rule_name":        meta.RuleName,
			"bypass_mode":      meta.BypassMode,
			"destination":      meta.Destination,
			"reason":           in.Reason,
			"suppressed_count": suppressedCount,
		},
		Policy: &types.PolicyInfo{
			Decision:          types.DecisionDeny,
			EffectiveDecision: types.DecisionDeny,
			Rule:              in.RuleName,
		},
	}
	if err := b.emit.AppendEvent(ctx, ev); err != nil {
		b.restore(key, snapshot)
		return false
	}
	b.emit.Publish(ev)
	return true
}

func processIdentityFor(identity string, pid int) string {
	if identity != "" {
		return identity
	}
	if pid > 0 {
		return "pid:" + strconv.Itoa(pid)
	}
	return "unknown"
}

func (b *BypassEmitter) record(key bypassKey, now time.Time) (int, bool, bypassSnapshot) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.pruneLocked(now)
	state, ok := b.windows[key]
	snapshot := bypassSnapshot{existed: ok, state: state}
	if ok && now.Sub(state.windowStart) < bypassDedupeWindow {
		state.suppressed++
		b.windows[key] = state
		return 0, false, snapshot
	}

	suppressed := 0
	if ok {
		suppressed = state.suppressed
	}
	b.nextGen++
	installed := bypassState{windowStart: now, generation: b.nextGen}
	b.windows[key] = installed
	snapshot.installedGeneration = installed.generation
	return suppressed, true, snapshot
}

func (b *BypassEmitter) restore(key bypassKey, snapshot bypassSnapshot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	current, ok := b.windows[key]
	if !ok || current.generation != snapshot.installedGeneration {
		return
	}
	if snapshot.existed {
		b.windows[key] = snapshot.state
		return
	}
	delete(b.windows, key)
}

func (b *BypassEmitter) pruneLocked(now time.Time) {
	for key, state := range b.windows {
		if now.Sub(state.windowStart) > 2*bypassDedupeWindow {
			delete(b.windows, key)
		}
	}
}

func RuleMetadataFor(engine *policy.Engine, ruleName string) (policy.RuleMetadata, bool) {
	if engine == nil || ruleName == "" {
		return policy.RuleMetadata{}, false
	}
	pol := engine.Policy()
	if pol == nil {
		return policy.RuleMetadata{}, false
	}
	for _, meta := range pol.Metadata {
		if meta.RuleName == ruleName {
			return meta, true
		}
	}
	return policy.RuleMetadata{}, false
}
