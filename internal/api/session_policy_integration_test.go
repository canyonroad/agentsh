package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
)

// newEngineDenyingOnly returns a *policy.Engine with a single explicit
// deny rule for the named command. The rule name embeds the command so
// tests can tell which engine produced the decision (distinguishing it
// from a default-deny fallback or from an engine built by
// newEngineAllowingCommand in session_policy_test.go).
func newEngineDenyingOnly(t *testing.T, cmdName string) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "global-deny-" + cmdName,
		CommandRules: []policy.CommandRule{
			{
				Name:     "global-deny-" + cmdName,
				Commands: []string{cmdName},
				Decision: string(types.DecisionDeny),
				Message:  "denied by global policy",
			},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// TestExecInSessionCore_PrecheckConsultsSessionPolicy is the regression
// test for #191. It constructs an App whose global policy denies "widget"
// and whose session policy allows "widget", then calls execInSessionCore
// and asserts the emitted command_precheck event reflects the session
// policy's ALLOW decision — not the global policy's DENY.
//
// newEngineAllowingCommand comes from session_policy_test.go (same package).
func TestExecInSessionCore_PrecheckConsultsSessionPolicy(t *testing.T) {
	// Use a guaranteed-missing path under t.TempDir() so the command
	// cannot possibly exist/block on the runner, regardless of what's
	// installed on PATH. Lowercased to match the engine's internal
	// normalization in CheckCommand (see internal/policy/engine.go).
	// filepath.ToSlash normalizes backslashes to forward slashes on
	// Windows so the policy engine compiles the rule as a full path
	// (it only treats "/" as a path separator — see engine.go ~line 196).
	cmdPath := strings.ToLower(filepath.ToSlash(filepath.Join(t.TempDir(), "agentsh191-nonexistent")))

	globalEngine := newEngineDenyingOnly(t, cmdPath)
	sessionEngine := newEngineAllowingCommand(t, "session-allow-widget", cmdPath)

	mgr := session.NewManager(5)
	captured := &capturingEventStore{}
	store := composite.New(captured, nil)
	broker := events.NewBroker()

	cfg := &config.Config{}
	app := NewApp(cfg, mgr, store, globalEngine, broker, nil, nil, nil, nil, nil)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.SetPolicyEngine(sessionEngine)

	// We don't care whether the command actually runs — we only care which
	// engine the precheck consulted. The precheck event is emitted BEFORE
	// the command would be run, so even if runCommandWithResources errors
	// later (no ptrace tracer, binary doesn't exist), the captured event
	// tells us what we need. A bounded context is used as a safety net so
	// this test can never hang if something downstream were to block.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, _ = app.execInSessionCore(ctx, s.ID, types.ExecRequest{
		Command: cmdPath,
	})

	ev := captured.firstCommandPrecheck()
	if ev == nil {
		t.Fatal("no command_precheck event was emitted")
	}
	if ev.Policy == nil {
		t.Fatal("command_precheck event has nil Policy")
	}
	if ev.Policy.Rule != "session-allow-widget" {
		t.Errorf("precheck consulted the wrong engine: event rule = %q, want %q. "+
			"This means the precheck is still using a.policy instead of the session engine.",
			ev.Policy.Rule, "session-allow-widget")
	}
	if ev.Policy.EffectiveDecision != types.DecisionAllow {
		t.Errorf("precheck should have returned allow, got %v", ev.Policy.EffectiveDecision)
	}
}

// capturingEventStore is a minimal store.EventStore implementation that
// records every AppendEvent call so tests can inspect what was emitted.
// It satisfies the same interface as mockEventStore (see policies_test.go)
// but, unlike that one, keeps the events so we can assert on them.
type capturingEventStore struct {
	events []types.Event
}

func (c *capturingEventStore) AppendEvent(_ context.Context, ev types.Event) error {
	c.events = append(c.events, ev)
	return nil
}

func (c *capturingEventStore) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, nil
}

func (c *capturingEventStore) Close() error { return nil }

func (c *capturingEventStore) firstCommandPrecheck() *types.Event {
	for i := range c.events {
		if c.events[i].Operation == "command_precheck" {
			return &c.events[i]
		}
	}
	return nil
}

// sessionPolicyFixture bundles the common per-entry-point regression test
// fixture: a global-deny engine, a session-allow engine, an App wired up
// with a capturing event store, and a session whose PolicyEngine has been
// set to the session-allow engine. Consumed by every
// Test*_PrecheckConsultsSessionPolicy case so they share the exact same
// setup and only differ in how they invoke the exec entry point.
type sessionPolicyFixture struct {
	cmdPath  string
	app      *App
	session  *session.Session
	captured *capturingEventStore
}

func newSessionPolicyFixture(t *testing.T) *sessionPolicyFixture {
	t.Helper()

	// Same pattern as TestExecInSessionCore_PrecheckConsultsSessionPolicy:
	// lowercased forward-slash TempDir path so the policy engine normalises
	// the rule as a full path on both Linux and Windows, and so the command
	// is guaranteed-missing on any runner.
	cmdPath := strings.ToLower(filepath.ToSlash(filepath.Join(t.TempDir(), "agentsh191-nonexistent")))

	globalEngine := newEngineDenyingOnly(t, cmdPath)
	sessionEngine := newEngineAllowingCommand(t, "session-allow-widget", cmdPath)

	mgr := session.NewManager(5)
	captured := &capturingEventStore{}
	store := composite.New(captured, nil)
	broker := events.NewBroker()

	cfg := &config.Config{}
	app := NewApp(cfg, mgr, store, globalEngine, broker, nil, nil, nil, nil, nil)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.SetPolicyEngine(sessionEngine)

	return &sessionPolicyFixture{
		cmdPath:  cmdPath,
		app:      app,
		session:  s,
		captured: captured,
	}
}

// assertSessionPolicyPrecheck asserts that the first captured
// command_precheck event came from the session-allow engine (by rule
// name) and produced an allow decision. This is the shared oracle for
// every per-entry-point regression test.
func (f *sessionPolicyFixture) assertSessionPolicyPrecheck(t *testing.T) {
	t.Helper()
	ev := f.captured.firstCommandPrecheck()
	if ev == nil {
		t.Fatal("no command_precheck event was emitted")
	}
	if ev.Policy == nil {
		t.Fatal("command_precheck event has nil Policy")
	}
	if ev.Policy.Rule != "session-allow-widget" {
		t.Errorf("precheck consulted the wrong engine: event rule = %q, want %q. "+
			"This means the precheck is still using a.policy instead of the session engine.",
			ev.Policy.Rule, "session-allow-widget")
	}
	if ev.Policy.EffectiveDecision != types.DecisionAllow {
		t.Errorf("precheck should have returned allow, got %v", ev.Policy.EffectiveDecision)
	}
}

// TestExecInSessionStream_PrecheckConsultsSessionPolicy is the #191
// regression test for the HTTP streaming exec entry point. It calls
// execInSessionStream directly with a chi URL param set, then asserts
// the captured command_precheck event came from the session engine's
// allow rule — proving the handler routes through policyEngineFor(sess)
// rather than hitting a.policy directly.
func TestExecInSessionStream_PrecheckConsultsSessionPolicy(t *testing.T) {
	f := newSessionPolicyFixture(t)

	body, err := json.Marshal(types.ExecRequest{Command: f.cmdPath})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req := httptest.NewRequestWithContext(ctx, "POST", "/api/v1/sessions/"+f.session.ID+"/exec/stream", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", f.session.ID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()

	// The precheck event is emitted before any command execution, so even
	// though the downstream exec will fail (missing binary), the captured
	// event already tells us which engine was consulted. The bounded
	// context is a safety net against anything downstream hanging.
	f.app.execInSessionStream(rr, req)

	f.assertSessionPolicyPrecheck(t)
}

// TestStartPTY_PrecheckConsultsSessionPolicy is the #191 regression
// test for the PTY start entry point. It calls startPTY directly — the
// precheck event fires before PTY creation, so even though pty.New().Start
// will fail on a missing binary, the captured event proves the handler
// consulted policyEngineFor(sess) rather than a.policy.
func TestStartPTY_PrecheckConsultsSessionPolicy(t *testing.T) {
	f := newSessionPolicyFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Return values are intentionally discarded: PTY creation will fail
	// (the binary does not exist), but the precheck event is already
	// emitted and captured before the PTY.Start call.
	_, _, _ = f.app.startPTY(ctx, f.session.ID, ptyStartParams{Command: f.cmdPath})

	f.assertSessionPolicyPrecheck(t)
}

// captureServerStream is a minimal grpc.ServerStream test double. It
// supplies a context (needed by the grpc ExecStream handler for event
// storage and downstream calls) and no-ops every other method. SendMsg
// returns an error so the handler bails out of the streaming loop
// quickly — the precheck event is already captured before any Send is
// attempted.
type captureServerStream struct {
	ctx context.Context
}

func (s *captureServerStream) Context() context.Context { return s.ctx }
func (s *captureServerStream) SetHeader(metadata.MD) error {
	return nil
}
func (s *captureServerStream) SendHeader(metadata.MD) error {
	return nil
}
func (s *captureServerStream) SetTrailer(metadata.MD) {}
func (s *captureServerStream) SendMsg(m interface{}) error {
	// Return nil — the ExecStream handler only calls SendMsg from its
	// emit func after runCommandWithResourcesStreamingEmit starts the
	// process. By then, the precheck event is long since captured.
	return nil
}
func (s *captureServerStream) RecvMsg(m interface{}) error {
	return nil
}

var _ grpc.ServerStream = (*captureServerStream)(nil)

// TestGRPCExecStream_PrecheckConsultsSessionPolicy is the #191
// regression test for the gRPC ExecStream entry point. It builds a
// grpcServer wrapping the App, hands it a structpb request, and calls
// ExecStream directly with a captureServerStream double. The precheck
// fires and emits its event before setupSeccompWrapper runs, so even
// though the downstream command will fail with a missing binary, the
// captured event proves the handler consulted policyEngineFor(sess).
func TestGRPCExecStream_PrecheckConsultsSessionPolicy(t *testing.T) {
	f := newSessionPolicyFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	in, err := structpb.NewStruct(map[string]any{
		"session_id": f.session.ID,
		"command":    f.cmdPath,
	})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}

	stream := &captureServerStream{ctx: ctx}
	gs := &grpcServer{app: f.app}

	// The handler may return a non-nil error (the command doesn't exist,
	// so runCommandWithResourcesStreamingEmit will fail with exit 127),
	// but we only care about the captured precheck event.
	_ = gs.ExecStream(in, stream)

	f.assertSessionPolicyPrecheck(t)
}

// TestWrap_LandlockDerivationUsesSessionPolicy is the regression test for the
// wrap.go:167-170 half of #191. It asserts that when a session has a custom
// policy engine with an extra allow_read path, Landlock derivation reads from
// the session engine's policy, not from a.policy.
//
// This test does not actually launch a wrapper (which requires a real seccomp
// capable environment); it calls a small helper that exercises just the
// derivation branch. If wrap.go is refactored so that derivation moves out of
// wrapInitCore, this test should move with it.
func TestWrap_LandlockDerivationUsesSessionPolicy(t *testing.T) {
	globalEngine := newEngineAllowingCommand(t, "global", "ls")
	sessionPol := &policy.Policy{
		Version: 1,
		Name:    "session-with-extra-read",
		CommandRules: []policy.CommandRule{
			{Name: "allow-ls", Commands: []string{"ls"}, Decision: string(types.DecisionAllow)},
		},
		FileRules: []policy.FileRule{
			{
				Name:       "allow-read-project",
				Paths:      []string{"/srv/project"},
				Operations: []string{"read"},
				Decision:   string(types.DecisionAllow),
			},
		},
	}
	sessionEngine, err := policy.NewEngine(sessionPol, false, true)
	if err != nil {
		t.Fatalf("NewEngine session: %v", err)
	}

	mgr := session.NewManager(5)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.SetPolicyEngine(sessionEngine)

	app := &App{policy: globalEngine}

	// Direct helper exercise: the engine we get for this session must be the
	// session engine, and its Policy() must contain the file rule that only
	// exists in the session policy. The fix at wrap.go:167-170 calls through
	// the same helper, so this assertion covers the wrap path transitively.
	pol := app.policyEngineFor(s).Policy()
	foundSessionRule := false
	for _, fr := range pol.FileRules {
		if fr.Name == "allow-read-project" {
			foundSessionRule = true
			break
		}
	}
	if !foundSessionRule {
		t.Errorf("Landlock derivation would miss the session's file rule: "+
			"policyEngineFor(s).Policy() has %d file rules, none named allow-read-project",
			len(pol.FileRules))
	}
}
