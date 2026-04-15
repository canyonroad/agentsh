package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
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
	app := NewApp(cfg, mgr, store, globalEngine, broker, nil, nil, nil, nil, nil, nil)

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
	app := NewApp(cfg, mgr, store, globalEngine, broker, nil, nil, nil, nil, nil, nil)

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
// wrap.go Landlock derivation half of #191. It exercises
// (*App).deriveLandlockAllowPaths directly — the same helper wrapInitCore
// calls — and asserts that the derived allow-path lists come from the
// session's policy engine (not the global engine) when one is attached.
//
// The two engines are built with DISJOINT file rules:
//
//   - global engine has an allow-read rule for /global-only/*
//   - session engine has an allow-read rule for /session-only/*
//
// If the helper consults the session engine, the derived read paths will
// contain /session-only and NOT /global-only. If the helper regresses back
// to reading a.policy.Policy() (the #191 bug), the assertion inverts and
// the test fails loudly. Distinguishing by disjoint content is what the
// previous characterization test lacked — it only re-asserted that
// policyEngineFor returned the session engine, which is already covered by
// TestPolicyEngineFor_* in session_policy_test.go.
//
// A sub-test also exercises the fallback path: when no per-session engine
// is set, the helper must return paths derived from the global engine.
func TestWrap_LandlockDerivationUsesSessionPolicy(t *testing.T) {
	// extractBaseDir strips everything from the first glob char onward and
	// trims the trailing slash, so "/global-only/*" -> "/global-only" and
	// "/session-only/*" -> "/session-only". Using a glob keeps the derived
	// path equal to the rule's intent rather than filepath.Dir(path), which
	// would land one directory above the intended mount point.
	globalPol := &policy.Policy{
		Version: 1,
		Name:    "global-with-read",
		FileRules: []policy.FileRule{
			{
				Name:       "allow-read-global",
				Paths:      []string{"/global-only/*"},
				Operations: []string{"read"},
				Decision:   string(types.DecisionAllow),
			},
		},
	}
	globalEngine, err := policy.NewEngine(globalPol, false, true)
	if err != nil {
		t.Fatalf("NewEngine global: %v", err)
	}

	sessionPol := &policy.Policy{
		Version: 1,
		Name:    "session-with-read",
		FileRules: []policy.FileRule{
			{
				Name:       "allow-read-session",
				Paths:      []string{"/session-only/*"},
				Operations: []string{"read"},
				Decision:   string(types.DecisionAllow),
			},
		},
	}
	sessionEngine, err := policy.NewEngine(sessionPol, false, true)
	if err != nil {
		t.Fatalf("NewEngine session: %v", err)
	}

	app := &App{policy: globalEngine}
	mgr := session.NewManager(5)

	t.Run("uses_session_engine", func(t *testing.T) {
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		s.SetPolicyEngine(sessionEngine)

		_, read, _ := app.deriveLandlockAllowPaths(s)

		if !containsPath(read, "/session-only") {
			t.Errorf("deriveLandlockAllowPaths did not include the session engine's "+
				"/session-only read path; got read=%v. This means wrap.go regressed "+
				"to reading a.policy.Policy() instead of policyEngineFor(s).Policy().",
				read)
		}
		if containsPath(read, "/global-only") {
			t.Errorf("deriveLandlockAllowPaths leaked the global engine's /global-only "+
				"read path when a session engine was set; got read=%v. This means "+
				"wrap.go is consulting a.policy instead of the session engine.",
				read)
		}
	})

	t.Run("falls_back_to_global", func(t *testing.T) {
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		// Intentionally do NOT call SetPolicyEngine — the helper must fall
		// back to app.policy (the global engine).

		_, read, _ := app.deriveLandlockAllowPaths(s)

		if !containsPath(read, "/global-only") {
			t.Errorf("deriveLandlockAllowPaths did not include the global engine's "+
				"/global-only read path when the session had no engine set; got read=%v",
				read)
		}
		if containsPath(read, "/session-only") {
			t.Errorf("deriveLandlockAllowPaths leaked the session engine's "+
				"/session-only read path when no session engine was set; got read=%v",
				read)
		}
	})
}

// containsPath reports whether s appears in paths. Used by the Landlock
// derivation regression test to assert set membership without requiring a
// stable slice order (DeriveReadPathsFromPolicy iterates a map).
func containsPath(paths []string, s string) bool {
	for _, p := range paths {
		if p == s {
			return true
		}
	}
	return false
}

// newEngineWithCommandTimeout builds a *policy.Engine whose
// ResourceLimits.CommandTimeout equals the given duration. Uses
// policy.LoadFromBytes because the underlying `duration` wrapper on
// ResourceLimits is unexported, so callers cannot construct one directly
// from another package.
func newEngineWithCommandTimeout(t *testing.T, name string, timeout time.Duration) *policy.Engine {
	t.Helper()
	yamlDoc := []byte(
		"version: 1\n" +
			"name: " + name + "\n" +
			"resource_limits:\n" +
			"  command_timeout: " + timeout.String() + "\n",
	)
	p, err := policy.LoadFromBytes(yamlDoc)
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// TestExecInSessionCore_LimitsHonorSessionPolicy is a helper-level
// characterization test for the Limits() regression in #191. Both
// core.go and exec_stream.go call a.policyEngineFor(s).Limits() to
// derive a command timeout; this test builds two engines whose
// CommandTimeout values differ, installs the session engine on the
// session, and asserts that app.policyEngineFor(s).Limits() returns the
// session engine's value — not the global engine's.
//
// The production call sites go through the same helper, so routing
// them via policyEngineFor is enough to guarantee the per-session
// timeout is honored. Invoking execInSessionCore directly and
// observing a real timeout would be flaky and slow.
func TestExecInSessionCore_LimitsHonorSessionPolicy(t *testing.T) {
	globalEngine := newEngineWithCommandTimeout(t, "global-limits", 7*time.Second)
	sessionEngine := newEngineWithCommandTimeout(t, "session-limits", 13*time.Second)

	mgr := session.NewManager(5)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.SetPolicyEngine(sessionEngine)

	app := &App{policy: globalEngine}

	limits := app.policyEngineFor(s).Limits()
	if limits.CommandTimeout != 13*time.Second {
		t.Errorf("policyEngineFor(s).Limits().CommandTimeout = %s, want 13s. "+
			"This means core.go / exec_stream.go regressed to reading "+
			"a.policy.Limits() instead of policyEngineFor(s).Limits().",
			limits.CommandTimeout)
	}

	fallback := app.policyEngineFor(nil).Limits()
	if fallback.CommandTimeout != 7*time.Second {
		t.Errorf("policyEngineFor(nil).Limits().CommandTimeout = %s, want 7s "+
			"(global fallback)", fallback.CommandTimeout)
	}
}

// TestPolicyTest_HonorsSessionID is the #191 regression test for the
// /v1/policy/test HTTP endpoint. Before this fix, policyTest read
// a.policy directly and ignored req.SessionID, which meant per-session
// policy overrides were invisible to the test endpoint.
//
// The two engines consulted here have disjoint write rules:
//
//   - globalEngine has no rules; unrecognized writes default to deny
//     (see engine.CheckFile: "default-deny-files").
//   - sessionEngine has an explicit allow-write rule for /only-session/*
//
// With session_id supplied, the handler must consult the session
// engine and return allow. Without it, the handler must fall through
// to the global engine and return deny.
func TestPolicyTest_HonorsSessionID(t *testing.T) {
	globalPol := &policy.Policy{
		Version: 1,
		Name:    "global-no-rules",
	}
	globalEngine, err := policy.NewEngine(globalPol, false, true)
	if err != nil {
		t.Fatalf("NewEngine global: %v", err)
	}

	sessionPol := &policy.Policy{
		Version: 1,
		Name:    "session-allow-write",
		FileRules: []policy.FileRule{
			{
				Name:       "allow-write-only-session",
				Paths:      []string{"/only-session/*"},
				Operations: []string{"write"},
				Decision:   string(types.DecisionAllow),
			},
		},
	}
	sessionEngine, err := policy.NewEngine(sessionPol, false, true)
	if err != nil {
		t.Fatalf("NewEngine session: %v", err)
	}

	mgr := session.NewManager(5)
	captured := &capturingEventStore{}
	store := composite.New(captured, nil)
	broker := events.NewBroker()
	cfg := &config.Config{}
	app := NewApp(cfg, mgr, store, globalEngine, broker, nil, nil, nil, nil, nil, nil)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.SetPolicyEngine(sessionEngine)

	// Helper to POST a policy-test request and return the parsed
	// "decision" string and the HTTP status code.
	doRequest := func(t *testing.T, body map[string]any) (string, int) {
		t.Helper()
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req := httptest.NewRequest("POST", "/api/v1/policy/test", bytes.NewReader(buf))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		app.policyTest(rr, req)

		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v (body=%s)", err, rr.Body.String())
		}
		dec, _ := resp["decision"].(string)
		return dec, rr.Code
	}

	t.Run("with_session_id_allows", func(t *testing.T) {
		dec, code := doRequest(t, map[string]any{
			"session_id": s.ID,
			"operation":  "file_write",
			"path":       "/only-session/secret",
		})
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if dec != string(types.DecisionAllow) {
			t.Errorf("decision = %q, want %q. The handler did not consult the "+
				"session engine — it still reads a.policy directly.",
				dec, types.DecisionAllow)
		}
	})

	t.Run("without_session_id_denies", func(t *testing.T) {
		dec, code := doRequest(t, map[string]any{
			"operation": "file_write",
			"path":      "/only-session/secret",
		})
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if dec == string(types.DecisionAllow) {
			t.Errorf("decision = %q: global engine unexpectedly allowed "+
				"write to /only-session/secret — test fixture is not discriminating.",
				dec)
		}
	})
}

// TestGRPCPolicyTest_HonorsSessionID is the #191 regression test for the
// gRPC PolicyTest RPC. Before this fix, the handler read s.app.policy
// directly and ignored session_id, so per-session policy overrides were
// invisible to gRPC callers (even though the HTTP path honored session_id).
//
// Mirrors the engine setup from TestPolicyTest_HonorsSessionID (disjoint
// write rules: global has no rules and defaults to deny; session has an
// explicit allow-write for /only-session/*) but drives through
// grpcServer.PolicyTest with a structpb request and parses the returned
// *structpb.Struct to extract the "decision" field.
func TestGRPCPolicyTest_HonorsSessionID(t *testing.T) {
	globalPol := &policy.Policy{
		Version: 1,
		Name:    "global-no-rules",
	}
	globalEngine, err := policy.NewEngine(globalPol, false, true)
	if err != nil {
		t.Fatalf("NewEngine global: %v", err)
	}

	sessionPol := &policy.Policy{
		Version: 1,
		Name:    "session-allow-write",
		FileRules: []policy.FileRule{
			{
				Name:       "allow-write-only-session",
				Paths:      []string{"/only-session/*"},
				Operations: []string{"write"},
				Decision:   string(types.DecisionAllow),
			},
		},
	}
	sessionEngine, err := policy.NewEngine(sessionPol, false, true)
	if err != nil {
		t.Fatalf("NewEngine session: %v", err)
	}

	mgr := session.NewManager(5)
	captured := &capturingEventStore{}
	store := composite.New(captured, nil)
	broker := events.NewBroker()
	cfg := &config.Config{}
	app := NewApp(cfg, mgr, store, globalEngine, broker, nil, nil, nil, nil, nil, nil)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.SetPolicyEngine(sessionEngine)

	gs := &grpcServer{app: app}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Helper to build a structpb request, call PolicyTest, and return
	// the parsed "decision" string.
	doRequest := func(t *testing.T, body map[string]any) string {
		t.Helper()
		in, err := structpb.NewStruct(body)
		if err != nil {
			t.Fatalf("NewStruct: %v", err)
		}
		out, err := gs.PolicyTest(ctx, in)
		if err != nil {
			t.Fatalf("PolicyTest: %v", err)
		}
		m := out.AsMap()
		dec, _ := m["decision"].(string)
		return dec
	}

	t.Run("with_session_id_allows", func(t *testing.T) {
		dec := doRequest(t, map[string]any{
			"session_id": s.ID,
			"operation":  "file_write",
			"path":       "/only-session/secret",
		})
		if dec != string(types.DecisionAllow) {
			t.Errorf("decision = %q, want %q. The gRPC handler did not "+
				"consult the session engine — it still reads s.app.policy "+
				"directly and ignores session_id.",
				dec, types.DecisionAllow)
		}
	})

	t.Run("without_session_id_denies", func(t *testing.T) {
		dec := doRequest(t, map[string]any{
			"operation": "file_write",
			"path":      "/only-session/secret",
		})
		if dec == string(types.DecisionAllow) {
			t.Errorf("decision = %q: global engine unexpectedly allowed "+
				"write to /only-session/secret — test fixture is not "+
				"discriminating.", dec)
		}
	})
}

// TestWrap_SignalFilterUsesSessionPolicy is the #191 regression test for
// wrap.go's signal-filter gate and startSignalHandlerForWrap. Before this
// fix, the gate read a.policy.SignalEngine() directly, so a session with a
// custom policy file that defined signal rules could not enable signal
// filtering under the wrap path.
//
// The test builds two engines:
//   - globalEngine has no signal rules (SignalEngine() == nil)
//   - sessionEngine has one signal rule (SignalEngine() != nil)
//
// It then exercises (*App).signalFilterEnabled directly — the same helper
// wrapInitCore calls — and asserts that the gate reflects the session
// engine's rules (not the global engine's). Going through the helper
// catches a regression where wrap.go reads a.policy.SignalEngine() again
// instead of routing via policyEngineFor, because the helper IS the
// routing boundary.
//
// Skipped on Windows because compileSignalRules is a stub there and
// always returns a nil signal engine.
func TestWrap_SignalFilterUsesSessionPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signal handling not supported on Windows")
	}

	globalPol := &policy.Policy{
		Version: 1,
		Name:    "global-no-signals",
	}
	globalEngine, err := policy.NewEngine(globalPol, false, true)
	if err != nil {
		t.Fatalf("NewEngine global: %v", err)
	}
	if globalEngine.SignalEngine() != nil {
		t.Fatalf("global engine unexpectedly has a signal engine — test "+
			"fixture is not discriminating. Got %v", globalEngine.SignalEngine())
	}

	sessionPol := &policy.Policy{
		Version: 1,
		Name:    "session-with-signals",
		SignalRules: []policy.SignalRule{
			{
				Name:     "deny-kill-external",
				Signals:  []string{"SIGKILL"},
				Target:   policy.SignalTargetSpec{Type: "external"},
				Decision: "deny",
			},
		},
	}
	sessionEngine, err := policy.NewEngine(sessionPol, false, true)
	if err != nil {
		t.Fatalf("NewEngine session: %v", err)
	}
	if sessionEngine.SignalEngine() == nil {
		t.Fatalf("session engine has nil signal engine despite having a " +
			"signal rule — cannot discriminate between global and session.")
	}

	app := &App{policy: globalEngine}
	mgr := session.NewManager(16)

	t.Run("uses_session_engine", func(t *testing.T) {
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		s.SetPolicyEngine(sessionEngine)

		if !app.signalFilterEnabled(s, false) {
			t.Error("signalFilterEnabled(s, false) = false; expected true " +
				"because the session engine defines a signal rule. This " +
				"means wrap.go regressed to reading a.policy.SignalEngine() " +
				"instead of routing through policyEngineFor(s).")
		}
	})

	t.Run("falls_back_to_global_no_rules", func(t *testing.T) {
		// Session has no engine attached — helper falls back to the global
		// engine, which has no signal rules, so the gate must be closed.
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		if app.signalFilterEnabled(s, false) {
			t.Error("signalFilterEnabled(s, false) = true for a session " +
				"with no engine attached and a global engine that has no " +
				"signal rules; expected false.")
		}
	})

	t.Run("disabled_by_execve", func(t *testing.T) {
		// Even when the session engine has signal rules, execve
		// interception must override the gate (stacking USER_NOTIF
		// filters breaks notification delivery — see comment in
		// wrapInitCore).
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		s.SetPolicyEngine(sessionEngine)

		if app.signalFilterEnabled(s, true) {
			t.Error("signalFilterEnabled(s, true) = true; expected false " +
				"because execveEnabled must always disable the signal " +
				"filter gate (seccomp USER_NOTIF filter stacking).")
		}
	})

	t.Run("disabled_by_unix_socket_monitor", func(t *testing.T) {
		// Unix socket monitoring installs ActNotify rules in the main
		// seccomp filter. Stacking the signal filter on top causes the
		// same USER_NOTIF delivery failure observed with execve — see
		// TestAlpineEnvInject_BashBuiltinDisabled for the reproducer.
		cfgApp := &App{
			policy: globalEngine,
			cfg: &config.Config{
				Sandbox: config.SandboxConfig{
					Seccomp: config.SandboxSeccompConfig{
						UnixSocket: config.SandboxSeccompUnixConfig{Enabled: true},
					},
				},
			},
		}
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		s.SetPolicyEngine(sessionEngine)

		if cfgApp.signalFilterEnabled(s, false) {
			t.Error("signalFilterEnabled(s, false) = true with unix socket " +
				"monitoring enabled; expected false because stacking two " +
				"USER_NOTIF filters breaks notification delivery.")
		}
	})

	t.Run("disabled_by_file_monitor", func(t *testing.T) {
		// file_monitor traps openat/unlinkat/etc. via ActNotify. Same
		// stacking hazard as unix sockets.
		trueVal := true
		cfgApp := &App{
			policy: globalEngine,
			cfg: &config.Config{
				Sandbox: config.SandboxConfig{
					Seccomp: config.SandboxSeccompConfig{
						FileMonitor: config.SandboxSeccompFileMonitorConfig{
							Enabled: &trueVal,
						},
					},
				},
			},
		}
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		s.SetPolicyEngine(sessionEngine)

		if cfgApp.signalFilterEnabled(s, false) {
			t.Error("signalFilterEnabled(s, false) = true with file_monitor " +
				"enabled; expected false because stacking two USER_NOTIF " +
				"filters breaks notification delivery.")
		}
	})

	t.Run("disabled_by_intercept_metadata", func(t *testing.T) {
		// intercept_metadata traps stat-family syscalls via ActNotify.
		// Same stacking hazard as the other notify features.
		trueVal := true
		cfgApp := &App{
			policy: globalEngine,
			cfg: &config.Config{
				Sandbox: config.SandboxConfig{
					Seccomp: config.SandboxSeccompConfig{
						FileMonitor: config.SandboxSeccompFileMonitorConfig{
							InterceptMetadata: &trueVal,
						},
					},
				},
			},
		}
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		s.SetPolicyEngine(sessionEngine)

		if cfgApp.signalFilterEnabled(s, false) {
			t.Error("signalFilterEnabled(s, false) = true with " +
				"intercept_metadata enabled; expected false because " +
				"stacking two USER_NOTIF filters breaks notification delivery.")
		}
	})

	t.Run("enabled_when_no_main_notify", func(t *testing.T) {
		// With no USER_NOTIF features on the main filter, the signal
		// filter can be installed safely. This is the happy path: a
		// session with signal rules and a wrapper that only does
		// Landlock / blocked-syscalls without notify.
		falseVal := false
		cfgApp := &App{
			policy: globalEngine,
			cfg: &config.Config{
				Sandbox: config.SandboxConfig{
					Seccomp: config.SandboxSeccompConfig{
						UnixSocket: config.SandboxSeccompUnixConfig{Enabled: false},
						FileMonitor: config.SandboxSeccompFileMonitorConfig{
							Enabled:           &falseVal,
							InterceptMetadata: &falseVal,
						},
					},
				},
			},
		}
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		s.SetPolicyEngine(sessionEngine)

		if !cfgApp.signalFilterEnabled(s, false) {
			t.Error("signalFilterEnabled(s, false) = false with no main " +
				"filter notify features; expected true (happy path).")
		}
	})

	t.Run("disabled_by_onblock_log", func(t *testing.T) {
		// on_block=log installs ActNotify rules on block-listed syscalls,
		// so stacking the signal filter on top would cause the same
		// USER_NOTIF delivery failure observed with unix sockets and
		// file_monitor. See mainFilterUsesUserNotify.
		cfgApp := &App{
			policy: globalEngine,
			cfg: &config.Config{
				Sandbox: config.SandboxConfig{
					Seccomp: config.SandboxSeccompConfig{
						Syscalls: config.SandboxSeccompSyscallConfig{
							Block:   []string{"ptrace"},
							OnBlock: "log",
						},
					},
				},
			},
		}
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		s.SetPolicyEngine(sessionEngine)

		if cfgApp.signalFilterEnabled(s, false) {
			t.Error("signalFilterEnabled(s, false) = true with on_block=log " +
				"and a non-empty block-list; expected false because the " +
				"block-list installs ActNotify rules and stacking the " +
				"signal filter breaks notification delivery.")
		}
	})

	t.Run("disabled_by_onblock_log_and_kill", func(t *testing.T) {
		// Same stacking hazard as on_block=log: ActNotify rules are
		// installed on block-listed syscalls, so the signal filter
		// must not be layered on top.
		cfgApp := &App{
			policy: globalEngine,
			cfg: &config.Config{
				Sandbox: config.SandboxConfig{
					Seccomp: config.SandboxSeccompConfig{
						Syscalls: config.SandboxSeccompSyscallConfig{
							Block:   []string{"mount"},
							OnBlock: "log_and_kill",
						},
					},
				},
			},
		}
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		s.SetPolicyEngine(sessionEngine)

		if cfgApp.signalFilterEnabled(s, false) {
			t.Error("signalFilterEnabled(s, false) = true with " +
				"on_block=log_and_kill and a non-empty block-list; " +
				"expected false because ActNotify rules are installed " +
				"and stacking USER_NOTIF filters breaks delivery.")
		}
	})

	t.Run("enabled_when_onblock_errno_with_block", func(t *testing.T) {
		// on_block=errno installs SCMP_ACT_ERRNO rules — a kernel-side
		// return, no USER_NOTIF involvement — so the signal filter is
		// still safe to install. This locks in that we don't
		// over-gate.
		cfgApp := &App{
			policy: globalEngine,
			cfg: &config.Config{
				Sandbox: config.SandboxConfig{
					Seccomp: config.SandboxSeccompConfig{
						Syscalls: config.SandboxSeccompSyscallConfig{
							Block:   []string{"ptrace"},
							OnBlock: "errno",
						},
					},
				},
			},
		}
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		s.SetPolicyEngine(sessionEngine)

		if !cfgApp.signalFilterEnabled(s, false) {
			t.Error("signalFilterEnabled(s, false) = false with " +
				"on_block=errno and a block-list; expected true because " +
				"errno rules do not install USER_NOTIF and the signal " +
				"filter can coexist.")
		}
	})

	t.Run("enabled_when_onblock_log_but_empty_block", func(t *testing.T) {
		// on_block=log with no block-list installs zero ActNotify rules
		// (the action is a no-op without syscalls to attach to), so the
		// signal filter is still safe.
		cfgApp := &App{
			policy: globalEngine,
			cfg: &config.Config{
				Sandbox: config.SandboxConfig{
					Seccomp: config.SandboxSeccompConfig{
						Syscalls: config.SandboxSeccompSyscallConfig{
							Block:   nil,
							OnBlock: "log",
						},
					},
				},
			},
		}
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		s.SetPolicyEngine(sessionEngine)

		if !cfgApp.signalFilterEnabled(s, false) {
			t.Error("signalFilterEnabled(s, false) = false with " +
				"on_block=log but empty block-list; expected true because " +
				"no ActNotify rules are installed.")
		}
	})
}
