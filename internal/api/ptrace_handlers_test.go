//go:build linux

package api

import (
	"context"
	"fmt"
	"syscall"
	"testing"

	dbevents "github.com/agentsh/agentsh/internal/db/events"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/ptrace"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

type captureBypassEmitter struct {
	events    []types.Event
	published []types.Event
}

func (c *captureBypassEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	c.events = append(c.events, ev)
	return nil
}

func (c *captureBypassEmitter) Publish(ev types.Event) {
	c.published = append(c.published, ev)
}

func newTestRouter(t *testing.T, trashPath string) (*ptraceHandlerRouter, *session.Manager) {
	t.Helper()
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	router := &ptraceHandlerRouter{
		sessions:  mgr,
		store:     store,
		broker:    broker,
		trashPath: trashPath,
	}
	return router, mgr
}

func newSoftDeleteEngine(t *testing.T, workspace string) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "test-soft-delete",
		FileRules: []policy.FileRule{
			{
				Name:       "soft-delete-workspace",
				Paths:      []string{workspace + "/**"},
				Operations: []string{"delete", "read", "write", "rmdir"},
				Decision:   "soft_delete",
				Message:    "Deletions go to trash",
			},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func newDBUnavoidabilityEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "test-db-unavoidability",
		Metadata: []policy.RuleMetadata{
			{
				RuleName:    "db-appdb-deny-direct",
				Source:      dbservice.RuleSourceDBUnavoidability,
				DBService:   "appdb",
				BypassMode:  dbservice.BypassModeTCPDirect,
				Destination: "db.internal:5432",
			},
			{
				RuleName:    "db-bypass-ssh-forward",
				Source:      dbservice.RuleSourceDBUnavoidability,
				DBService:   "*",
				BypassMode:  dbservice.BypassModePortForwardTool,
				Destination: "db-service-ports",
			},
		},
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "db-appdb-deny-direct",
				Domains:  []string{"db.internal"},
				Ports:    []int{5432},
				Decision: "deny",
				Message:  "Direct database egress is blocked; use the AgentSH DB proxy",
			},
		},
		CommandRules: []policy.CommandRule{
			{
				Name:         "db-bypass-ssh-forward",
				Commands:     []string{"ssh"},
				ArgsPatterns: []string{`(^|\s)-L(\s|[^\s]*:).*:(5432)(\s|$)`},
				Decision:     "deny",
				Message:      "DB port forwarding is blocked by AgentSH DB unavoidability",
			},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestHandleNetwork_DBUnavoidabilityDenyEmitsBypassAttempt(t *testing.T) {
	router, mgr := newTestRouter(t, "")
	capture := &captureBypassEmitter{}
	router.dbBypass = dbevents.NewBypassEmitter(capture)

	sess, err := mgr.CreateWithID("test-db-network-deny", t.TempDir(), "")
	if err != nil {
		t.Fatalf("CreateWithID: %v", err)
	}
	sess.SetPolicyEngine(newDBUnavoidabilityEngine(t))

	result := router.HandleNetwork(context.Background(), ptrace.NetworkContext{
		SessionID: sess.ID,
		PID:       4321,
		Operation: "connect",
		Address:   "db.internal",
		Port:      5432,
	})

	if result.Action != "deny" || result.Allow {
		t.Fatalf("HandleNetwork result = %+v, want deny", result)
	}
	if len(capture.events) != 1 {
		t.Fatalf("bypass events len = %d, want 1", len(capture.events))
	}
	if len(capture.published) != 1 {
		t.Fatalf("published len = %d, want 1", len(capture.published))
	}
	ev := capture.events[0]
	if ev.Type != "db_bypass_attempt" || ev.SessionID != sess.ID || ev.PID != 4321 {
		t.Fatalf("unexpected bypass event identity: %+v", ev)
	}
	if ev.Fields["process_identity"] != "pid:4321" || ev.Fields["db_service"] != "appdb" {
		t.Fatalf("unexpected bypass process/service fields: %+v", ev.Fields)
	}
	if ev.Fields["rule_name"] != "db-appdb-deny-direct" || ev.Fields["bypass_mode"] != dbservice.BypassModeTCPDirect {
		t.Fatalf("unexpected bypass rule fields: %+v", ev.Fields)
	}
	if ev.Fields["destination"] != "db.internal:5432" || ev.Fields["reason"] != "Direct database egress is blocked; use the AgentSH DB proxy" {
		t.Fatalf("unexpected bypass detail fields: %+v", ev.Fields)
	}
}

func TestHandleExecve_DBUnavoidabilityDenyEmitsBypassAttempt(t *testing.T) {
	router, mgr := newTestRouter(t, "")
	capture := &captureBypassEmitter{}
	router.dbBypass = dbevents.NewBypassEmitter(capture)

	sess, err := mgr.CreateWithID("test-db-exec-deny", t.TempDir(), "")
	if err != nil {
		t.Fatalf("CreateWithID: %v", err)
	}
	sess.SetPolicyEngine(newDBUnavoidabilityEngine(t))

	result := router.HandleExecve(context.Background(), ptrace.ExecContext{
		SessionID: sess.ID,
		PID:       6789,
		Filename:  "/usr/bin/ssh",
		Argv:      []string{"ssh", "-L", "15432:db.internal:5432", "bastion"},
	})

	if result.Action != "deny" || result.Allow {
		t.Fatalf("HandleExecve result = %+v, want deny", result)
	}
	if len(capture.events) != 1 {
		t.Fatalf("bypass events len = %d, want 1", len(capture.events))
	}
	ev := capture.events[0]
	if ev.Type != "db_bypass_attempt" || ev.SessionID != sess.ID || ev.PID != 6789 {
		t.Fatalf("unexpected bypass event identity: %+v", ev)
	}
	if ev.Fields["process_identity"] != "pid:6789" || ev.Fields["db_service"] != "*" {
		t.Fatalf("unexpected bypass process/service fields: %+v", ev.Fields)
	}
	if ev.Fields["rule_name"] != "db-bypass-ssh-forward" || ev.Fields["bypass_mode"] != dbservice.BypassModePortForwardTool {
		t.Fatalf("unexpected bypass rule fields: %+v", ev.Fields)
	}
	if ev.Fields["destination"] != "db-service-ports" || ev.Fields["reason"] != "DB port forwarding is blocked by AgentSH DB unavoidability" {
		t.Fatalf("unexpected bypass detail fields: %+v", ev.Fields)
	}
}

// TestHandleExecve_SessionlessPIDAttachAllows verifies the legitimate
// attach_mode=pid sessionless path (PR #312 review concern B):
// initPtraceTracer calls tr.AttachPID(pid) without WithSessionID, so
// the attached root and its descendants are sessionless by design --
// the wrapper / session layer governs enforcement above the tracer.
// HandleExecve must let those execve's pass through with rule
// "sessionless_pid_attach".
func TestHandleExecve_SessionlessPIDAttachAllows(t *testing.T) {
	router, _ := newTestRouter(t, "")
	res := router.HandleExecve(context.Background(), ptrace.ExecContext{
		PID:                  4242,
		Filename:             "/bin/true",
		SessionID:            "",
		SessionlessPIDAttach: true,
	})
	if !res.Allow {
		t.Fatalf("SessionlessPIDAttach execve must allow; got Allow=false")
	}
	if res.Action != "allow" {
		t.Fatalf("Action=%q; want %q", res.Action, "allow")
	}
	if res.Rule != "sessionless_pid_attach" {
		t.Fatalf("Rule=%q; want %q", res.Rule, "sessionless_pid_attach")
	}
	if res.Errno != 0 {
		t.Fatalf("Errno=%d; want 0 (no errno on allow)", res.Errno)
	}
}

// TestHandleExecve_NonEmptyUnknownSessionDenies covers the other half
// of the PR #312 review split: a non-empty SessionID that the session
// manager does not know about is a real session-accounting bug, not
// the legitimate sessionless-pid-attach case. Must fail closed with
// rule "unknown_session" so the bug is visible rather than silently
// allowed.
func TestHandleExecve_NonEmptyUnknownSessionDenies(t *testing.T) {
	router, _ := newTestRouter(t, "")
	res := router.HandleExecve(context.Background(), ptrace.ExecContext{
		PID:                  4242,
		Filename:             "/bin/true",
		SessionID:            "session-that-does-not-exist",
		SessionlessPIDAttach: false,
	})
	if res.Allow {
		t.Fatalf("non-empty unknown SessionID must deny; got Allow=true")
	}
	if res.Action != "deny" {
		t.Fatalf("Action=%q; want %q", res.Action, "deny")
	}
	if res.Rule != "unknown_session" {
		t.Fatalf("Rule=%q; want %q", res.Rule, "unknown_session")
	}
	if res.Errno != int32(syscall.EACCES) {
		t.Fatalf("Errno=%d; want EACCES (%d)", res.Errno, syscall.EACCES)
	}
}

func TestHandleFile_SoftDelete(t *testing.T) {
	workspace := t.TempDir()

	tests := []struct {
		name       string
		trashPath  string
		workspace  string
		operation  string
		path       string
		wantAction string
		wantAllow  bool
		wantErrno  int32
	}{
		{
			name:       "delete with configured trash returns soft-delete",
			trashPath:  ".agentsh_trash",
			workspace:  workspace,
			operation:  "delete",
			path:       workspace + "/file.txt",
			wantAction: "soft-delete",
		},
		{
			name:       "rmdir with configured trash returns soft-delete",
			trashPath:  ".agentsh_trash",
			workspace:  workspace,
			operation:  "rmdir",
			path:       workspace + "/subdir",
			wantAction: "soft-delete",
		},
		{
			name:       "non-delete op with soft_delete policy falls through to allow",
			trashPath:  ".agentsh_trash",
			workspace:  workspace,
			operation:  "read",
			path:       workspace + "/file.txt",
			wantAction: "allow",
			wantAllow:  true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, mgr := newTestRouter(t, tt.trashPath)
			sessID := fmt.Sprintf("test-session-%d", i)
			sess, err := mgr.CreateWithID(sessID, tt.workspace, "")
			if err != nil {
				t.Fatalf("CreateWithID: %v", err)
			}
			sess.SetPolicyEngine(newSoftDeleteEngine(t, tt.workspace))

			result := router.HandleFile(context.Background(), ptrace.FileContext{
				SessionID: sess.ID,
				PID:       1234,
				Path:      tt.path,
				Operation: tt.operation,
			})

			if result.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", result.Action, tt.wantAction)
			}
			if tt.wantErrno != 0 && result.Errno != tt.wantErrno {
				t.Errorf("Errno = %d, want %d", result.Errno, tt.wantErrno)
			}
			if result.Allow != tt.wantAllow {
				t.Errorf("Allow = %v, want %v", result.Allow, tt.wantAllow)
			}
		})
	}
}

func newDnsRedirectEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "test-dns-redirect",
		DnsRedirectRules: []policy.DnsRedirectRule{
			{
				Name:       "redirect-test",
				Match:      `redirectme\.example\.com`,
				ResolveTo:  "127.0.0.1",
				Visibility: "audit_only",
				OnFailure:  "fail_closed",
			},
		},
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "allow-all",
				Domains:  []string{"*"},
				Decision: "allow",
			},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestHandleNetwork_DnsRedirect(t *testing.T) {
	router, mgr := newTestRouter(t, "")
	sess, err := mgr.CreateWithID("test-dns-redirect", t.TempDir(), "")
	if err != nil {
		t.Fatalf("CreateWithID: %v", err)
	}
	sess.SetPolicyEngine(newDnsRedirectEngine(t))

	// Matching domain should return synthetic records.
	result := router.HandleNetwork(context.Background(), ptrace.NetworkContext{
		SessionID: sess.ID,
		PID:       1234,
		Operation: "dns",
		Domain:    "redirectme.example.com",
		Port:      53,
	})
	if result.Action != "redirect" {
		t.Errorf("Action = %q, want %q", result.Action, "redirect")
	}
	if len(result.Records) != 1 {
		t.Fatalf("Records len = %d, want 1", len(result.Records))
	}
	if result.Records[0].Type != 1 {
		t.Errorf("Record type = %d, want 1 (A)", result.Records[0].Type)
	}
	if result.Records[0].Value != "127.0.0.1" {
		t.Errorf("Record value = %q, want %q", result.Records[0].Value, "127.0.0.1")
	}

	// Non-matching domain should fall through to normal network policy (no synthetic records).
	result = router.HandleNetwork(context.Background(), ptrace.NetworkContext{
		SessionID: sess.ID,
		PID:       1234,
		Operation: "dns",
		Domain:    "github.com",
		Port:      53,
	})
	if result.Action == "redirect" {
		t.Errorf("non-matching: Action = %q, should not be redirect", result.Action)
	}
	if len(result.Records) != 0 {
		t.Errorf("non-matching: Records len = %d, want 0", len(result.Records))
	}
}

func TestHandleFile_SoftDeleteNoTrashDir(t *testing.T) {
	// When trash path resolves to empty (no workspace), soft-delete denies.
	router, mgr := newTestRouter(t, "")
	workspace := t.TempDir()
	sess, err := mgr.CreateWithID("test-no-trash", workspace, "")
	if err != nil {
		t.Fatalf("CreateWithID: %v", err)
	}
	// Set workspace to empty after creation to simulate missing workspace.
	sess.Workspace = ""
	sess.SetPolicyEngine(newSoftDeleteEngine(t, workspace))

	result := router.HandleFile(context.Background(), ptrace.FileContext{
		SessionID: sess.ID,
		PID:       1234,
		Path:      workspace + "/file.txt",
		Operation: "delete",
	})

	if result.Action != "deny" {
		t.Errorf("Action = %q, want deny", result.Action)
	}
	if result.Errno != int32(syscall.EACCES) {
		t.Errorf("Errno = %d, want %d", result.Errno, int32(syscall.EACCES))
	}
}
