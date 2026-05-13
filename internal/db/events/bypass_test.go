package events

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	dbservice "github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

type captureAuditEmitter struct {
	appendErr error
	events    []types.Event
	published []types.Event
}

func (c *captureAuditEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	if c.appendErr != nil {
		return c.appendErr
	}
	c.events = append(c.events, ev)
	return nil
}

func (c *captureAuditEmitter) Publish(ev types.Event) {
	c.published = append(c.published, ev)
}

type blockingFirstAppendEmitter struct {
	mu           sync.Mutex
	firstStarted chan struct{}
	releaseFirst chan struct{}
	firstErr     error
	appendCount  int
	events       []types.Event
	published    []types.Event
}

func newBlockingFirstAppendEmitter(firstErr error) *blockingFirstAppendEmitter {
	return &blockingFirstAppendEmitter{
		firstStarted: make(chan struct{}),
		releaseFirst: make(chan struct{}),
		firstErr:     firstErr,
	}
}

func (c *blockingFirstAppendEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	c.mu.Lock()
	c.appendCount++
	count := c.appendCount
	c.mu.Unlock()

	if count == 1 {
		close(c.firstStarted)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.releaseFirst:
			return c.firstErr
		}
	}

	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
	return nil
}

func (c *blockingFirstAppendEmitter) Publish(ev types.Event) {
	c.mu.Lock()
	c.published = append(c.published, ev)
	c.mu.Unlock()
}

func testBypassEngine(t *testing.T, metadata ...policy.RuleMetadata) *policy.Engine {
	t.Helper()
	if metadata == nil {
		metadata = []policy.RuleMetadata{{
			RuleName:    "db-appdb-deny-direct",
			Source:      dbservice.RuleSourceDBUnavoidability,
			DBService:   "appdb",
			BypassMode:  dbservice.BypassModeTCPDirect,
			Destination: "db.internal:5432",
		}}
	}
	p := &policy.Policy{
		Version:  1,
		Name:     "test",
		Metadata: metadata,
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestBypassEmitter_EmitsDBUnavoidabilityDeny(t *testing.T) {
	capture := &captureAuditEmitter{}
	now := time.Date(2026, 5, 13, 12, 0, 0, 123, time.FixedZone("offset", 3600))
	emitter := NewBypassEmitter(capture, WithBypassNow(func() time.Time { return now }))

	emitted := emitter.EmitIfDBUnavoidabilityDeny(context.Background(), BypassAttempt{
		Engine:          testBypassEngine(t),
		SessionID:       "session-1",
		CommandID:       "cmd-1",
		ProcessID:       4242,
		ProcessIdentity: "psql:/usr/bin/psql",
		RuleName:        "db-appdb-deny-direct",
		Reason:          "direct database egress is blocked",
	})
	if !emitted {
		t.Fatal("EmitIfDBUnavoidabilityDeny returned false, want true")
	}
	if len(capture.events) != 1 {
		t.Fatalf("events len = %d, want 1", len(capture.events))
	}
	if len(capture.published) != 1 {
		t.Fatalf("published len = %d, want 1", len(capture.published))
	}

	ev := capture.events[0]
	if ev.ID == "" {
		t.Fatal("event ID is empty")
	}
	if ev.Timestamp.Location() != time.UTC || !ev.Timestamp.Equal(now.UTC()) {
		t.Fatalf("timestamp = %v, want UTC %v", ev.Timestamp, now.UTC())
	}
	if ev.Type != "db_bypass_attempt" || ev.SessionID != "session-1" || ev.CommandID != "cmd-1" || ev.PID != 4242 {
		t.Fatalf("unexpected event identity: %+v", ev)
	}
	if ev.Policy == nil || ev.Policy.Decision != types.DecisionDeny || ev.Policy.EffectiveDecision != types.DecisionDeny || ev.Policy.Rule != "db-appdb-deny-direct" {
		t.Fatalf("unexpected policy info: %+v", ev.Policy)
	}
	if ev.Fields["process_id"] != 4242 || ev.Fields["process_identity"] != "psql:/usr/bin/psql" {
		t.Fatalf("unexpected process fields: %+v", ev.Fields)
	}
	if ev.Fields["db_service"] != "appdb" || ev.Fields["rule_name"] != "db-appdb-deny-direct" || ev.Fields["bypass_mode"] != dbservice.BypassModeTCPDirect {
		t.Fatalf("unexpected rule fields: %+v", ev.Fields)
	}
	if ev.Fields["destination"] != "db.internal:5432" || ev.Fields["reason"] != "direct database egress is blocked" || ev.Fields["suppressed_count"] != 0 {
		t.Fatalf("unexpected detail fields: %+v", ev.Fields)
	}
}

func TestBypassEmitter_IgnoresInvalidInputs(t *testing.T) {
	capture := &captureAuditEmitter{}
	engine := testBypassEngine(t)

	tests := []struct {
		name    string
		emitter *BypassEmitter
		attempt BypassAttempt
	}{
		{
			name:    "nil emitter",
			emitter: nil,
			attempt: BypassAttempt{
				Engine:    engine,
				SessionID: "session-1",
				RuleName:  "db-appdb-deny-direct",
			},
		},
		{
			name:    "nil audit emitter",
			emitter: NewBypassEmitter(nil),
			attempt: BypassAttempt{
				Engine:    engine,
				SessionID: "session-1",
				RuleName:  "db-appdb-deny-direct",
			},
		},
		{
			name:    "nil engine",
			emitter: NewBypassEmitter(capture),
			attempt: BypassAttempt{
				SessionID: "session-1",
				RuleName:  "db-appdb-deny-direct",
			},
		},
		{
			name:    "empty session",
			emitter: NewBypassEmitter(capture),
			attempt: BypassAttempt{
				Engine:   engine,
				RuleName: "db-appdb-deny-direct",
			},
		},
		{
			name:    "empty rule",
			emitter: NewBypassEmitter(capture),
			attempt: BypassAttempt{
				Engine:    engine,
				SessionID: "session-1",
			},
		},
		{
			name:    "metadata absent",
			emitter: NewBypassEmitter(capture),
			attempt: BypassAttempt{
				Engine:    testBypassEngine(t, []policy.RuleMetadata{}...),
				SessionID: "session-1",
				RuleName:  "db-appdb-deny-direct",
			},
		},
		{
			name:    "metadata not db unavoidability",
			emitter: NewBypassEmitter(capture),
			attempt: BypassAttempt{
				Engine: testBypassEngine(t, policy.RuleMetadata{
					RuleName:    "ordinary-deny",
					Source:      "manual",
					DBService:   "appdb",
					BypassMode:  dbservice.BypassModeTCPDirect,
					Destination: "db.internal:5432",
				}),
				SessionID: "session-1",
				RuleName:  "ordinary-deny",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.emitter.EmitIfDBUnavoidabilityDeny(context.Background(), tt.attempt) {
				t.Fatal("EmitIfDBUnavoidabilityDeny returned true, want false")
			}
		})
	}
	if len(capture.events) != 0 {
		t.Fatalf("events len = %d, want 0", len(capture.events))
	}
	if len(capture.published) != 0 {
		t.Fatalf("published len = %d, want 0", len(capture.published))
	}
}

func TestBypassEmitter_DedupesForWindow(t *testing.T) {
	capture := &captureAuditEmitter{}
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	emitter := NewBypassEmitter(capture, WithBypassNow(func() time.Time { return now }))
	engine := testBypassEngine(t)

	attempt := BypassAttempt{
		Engine:          engine,
		SessionID:       "session-1",
		ProcessID:       4242,
		ProcessIdentity: "pid:4242",
		RuleName:        "db-appdb-deny-direct",
	}
	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("first event suppressed")
	}
	if emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("duplicate inside window emitted")
	}
	now = now.Add(61 * time.Second)
	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("event after window suppressed")
	}
	if len(capture.events) != 2 {
		t.Fatalf("events len = %d, want 2", len(capture.events))
	}
	if got := capture.events[1].Fields["suppressed_count"]; got != 1 {
		t.Fatalf("second suppressed_count = %v, want 1", got)
	}
}

func TestBypassEmitter_DedupeKeyIncludesSessionIdentityAndDestination(t *testing.T) {
	capture := &captureAuditEmitter{}
	emitter := NewBypassEmitter(capture)
	engine := testBypassEngine(t, policy.RuleMetadata{
		RuleName:    "db-appdb-deny-direct",
		Source:      dbservice.RuleSourceDBUnavoidability,
		DBService:   "appdb",
		BypassMode:  dbservice.BypassModeTCPDirect,
		Destination: "db.internal:5432",
	}, policy.RuleMetadata{
		RuleName:    "db-warehouse-deny-direct",
		Source:      dbservice.RuleSourceDBUnavoidability,
		DBService:   "warehouse",
		BypassMode:  dbservice.BypassModeTCPDirect,
		Destination: "warehouse.internal:5432",
	})
	attempt := BypassAttempt{
		Engine:          engine,
		SessionID:       "session-1",
		ProcessIdentity: "pid:1",
		RuleName:        "db-appdb-deny-direct",
	}

	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("first event suppressed")
	}
	attempt.SessionID = "session-2"
	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("different session suppressed")
	}
	attempt.SessionID = "session-1"
	attempt.ProcessIdentity = "pid:2"
	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("different process identity suppressed")
	}
	attempt.ProcessIdentity = "pid:1"
	attempt.RuleName = "db-warehouse-deny-direct"
	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("different destination suppressed")
	}
	if len(capture.events) != 4 {
		t.Fatalf("events len = %d, want 4", len(capture.events))
	}
}

func TestBypassEmitter_PrunesOldWindows(t *testing.T) {
	capture := &captureAuditEmitter{}
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	emitter := NewBypassEmitter(capture, WithBypassNow(func() time.Time { return now }))
	engine := testBypassEngine(t, policy.RuleMetadata{
		RuleName:    "db-old-deny-direct",
		Source:      dbservice.RuleSourceDBUnavoidability,
		DBService:   "old",
		BypassMode:  dbservice.BypassModeTCPDirect,
		Destination: "old.internal:5432",
	}, policy.RuleMetadata{
		RuleName:    "db-new-deny-direct",
		Source:      dbservice.RuleSourceDBUnavoidability,
		DBService:   "new",
		BypassMode:  dbservice.BypassModeTCPDirect,
		Destination: "new.internal:5432",
	})

	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), BypassAttempt{
		Engine:          engine,
		SessionID:       "session-1",
		ProcessIdentity: "pid:1",
		RuleName:        "db-old-deny-direct",
	}) {
		t.Fatal("old window first event suppressed")
	}
	now = now.Add(2*bypassDedupeWindow + time.Nanosecond)
	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), BypassAttempt{
		Engine:          engine,
		SessionID:       "session-1",
		ProcessIdentity: "pid:2",
		RuleName:        "db-new-deny-direct",
	}) {
		t.Fatal("new window event suppressed")
	}

	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	if _, ok := emitter.windows[bypassKey{
		sessionID:       "session-1",
		processIdentity: "pid:1",
		destination:     "old.internal:5432",
	}]; ok {
		t.Fatal("old dedupe window was not pruned")
	}
	if _, ok := emitter.windows[bypassKey{
		sessionID:       "session-1",
		processIdentity: "pid:2",
		destination:     "new.internal:5432",
	}]; !ok {
		t.Fatal("new dedupe window missing after prune")
	}
}

func TestBypassEmitter_DerivesProcessIdentity(t *testing.T) {
	capture := &captureAuditEmitter{}
	emitter := NewBypassEmitter(capture)
	engine := testBypassEngine(t)

	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), BypassAttempt{
		Engine:    engine,
		SessionID: "session-1",
		ProcessID: 4242,
		RuleName:  "db-appdb-deny-direct",
	}) {
		t.Fatal("event with pid fallback suppressed")
	}
	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), BypassAttempt{
		Engine:    engine,
		SessionID: "session-2",
		ProcessID: 0,
		RuleName:  "db-appdb-deny-direct",
	}) {
		t.Fatal("event with unknown fallback suppressed")
	}
	if got := capture.events[0].Fields["process_identity"]; got != "pid:4242" {
		t.Fatalf("process_identity = %v, want pid:4242", got)
	}
	if got := capture.events[1].Fields["process_identity"]; got != "unknown" {
		t.Fatalf("process_identity = %v, want unknown", got)
	}
}

func TestBypassEmitter_AppendErrorDoesNotPublishOrDedupe(t *testing.T) {
	capture := &captureAuditEmitter{appendErr: errors.New("append failed")}
	emitter := NewBypassEmitter(capture)
	attempt := BypassAttempt{
		Engine:          testBypassEngine(t),
		SessionID:       "session-1",
		ProcessID:       4242,
		ProcessIdentity: "pid:4242",
		RuleName:        "db-appdb-deny-direct",
	}

	if emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("EmitIfDBUnavoidabilityDeny returned true on append error")
	}
	if len(capture.events) != 0 {
		t.Fatalf("events len = %d, want 0", len(capture.events))
	}
	if len(capture.published) != 0 {
		t.Fatalf("published len = %d, want 0", len(capture.published))
	}

	capture.appendErr = nil
	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("successful retry after append error was suppressed")
	}
	if len(capture.events) != 1 {
		t.Fatalf("events len = %d, want 1", len(capture.events))
	}
	if len(capture.published) != 1 {
		t.Fatalf("published len = %d, want 1", len(capture.published))
	}
	if got := capture.events[0].Fields["suppressed_count"]; got != 0 {
		t.Fatalf("suppressed_count = %v, want 0", got)
	}
}

func TestBypassEmitter_AppendErrorRestoreDoesNotClobberNewerWindow(t *testing.T) {
	capture := newBlockingFirstAppendEmitter(errors.New("append failed"))
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	emitter := NewBypassEmitter(capture, WithBypassNow(func() time.Time { return now }))
	attempt := BypassAttempt{
		Engine:          testBypassEngine(t),
		SessionID:       "session-1",
		ProcessID:       4242,
		ProcessIdentity: "pid:4242",
		RuleName:        "db-appdb-deny-direct",
	}

	firstDone := make(chan bool, 1)
	go func() {
		firstDone <- emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt)
	}()

	select {
	case <-capture.firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first append did not start")
	}

	now = now.Add(bypassDedupeWindow + time.Second)
	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("newer window event suppressed")
	}

	close(capture.releaseFirst)
	select {
	case emitted := <-firstDone:
		if emitted {
			t.Fatal("first append returned emitted=true despite append error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first append did not finish")
	}

	if emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("duplicate inside newer window emitted after stale rollback")
	}
	if len(capture.events) != 1 {
		t.Fatalf("events len = %d, want only newer successful event", len(capture.events))
	}
	if len(capture.published) != 1 {
		t.Fatalf("published len = %d, want only newer successful event", len(capture.published))
	}
}
