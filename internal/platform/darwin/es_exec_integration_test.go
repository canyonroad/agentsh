//go:build integration

package darwin

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/platform/darwin/xpc"
	"github.com/agentsh/agentsh/internal/policy"
)

func init() {
	// Integration tests use Unix sockets which require linux or darwin.
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		// Tests will be skipped individually below.
	}
}

// integrationPolicyChecker adapts a policy.Engine to ESExecPolicyChecker.
// This bridges the real policy engine with the ESExecHandler for integration tests.
type integrationPolicyChecker struct {
	engine *policy.Engine
}

func (c *integrationPolicyChecker) CheckCommand(cmd string, args []string) ESExecPolicyResult {
	dec := c.engine.CheckCommand(cmd, args)
	return ESExecPolicyResult{
		Decision:          string(dec.PolicyDecision),
		EffectiveDecision: string(dec.EffectiveDecision),
		Rule:              dec.Rule,
		Message:           dec.Message,
	}
}

// waitForIntegrationServer waits for the XPC server to be ready.
func waitForIntegrationServer(t *testing.T, srv *xpc.Server) {
	t.Helper()
	select {
	case <-srv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("server did not become ready within 5s")
	}
}

func TestESExecHandler_XPCIntegration(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("integration tests require Unix sockets (linux or darwin)")
	}

	// Create a policy with various command rules.
	p := &policy.Policy{
		Version: 1,
		Name:    "exec-integration-test",
		CommandRules: []policy.CommandRule{
			{Name: "deny-rm", Commands: []string{"rm"}, Decision: "deny"},
			{Name: "audit-curl", Commands: []string{"curl"}, Decision: "audit"},
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	// Create the real ESExecHandler wired to a policy checker.
	checker := &integrationPolicyChecker{engine: engine}
	execHandler := NewESExecHandler(checker, "")

	// Create XPC server with PolicyAdapter as PolicyHandler
	// and ESExecHandler as ExecHandler.
	sockPath := filepath.Join(t.TempDir(), "policy.sock")
	adapter := xpc.NewPolicyAdapter(engine, nil)
	srv := xpc.NewServer(sockPath, adapter)
	srv.SetExecHandler(execHandler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	waitForIntegrationServer(t, srv)

	// Test: allowed command flows through ESExecHandler
	t.Run("allow_through_pipeline", func(t *testing.T) {
		resp := sendExecRequest(t, sockPath, xpc.PolicyRequest{
			Type:      xpc.RequestTypeExecCheck,
			Path:      "/usr/bin/ls",
			Args:      []string{"-la"},
			PID:       1234,
			ParentPID: 1,
			SessionID: "sess-1",
		})
		if !resp.Allow {
			t.Error("expected Allow=true")
		}
		if resp.Action != "continue" {
			t.Errorf("action: got %q, want %q", resp.Action, "continue")
		}
		if resp.ExecDecision != "allow" {
			t.Errorf("exec_decision: got %q, want %q", resp.ExecDecision, "allow")
		}
		if resp.Rule != "allow-all" {
			t.Errorf("rule: got %q, want %q", resp.Rule, "allow-all")
		}
	})

	// Test: denied command flows through ESExecHandler
	t.Run("deny_through_pipeline", func(t *testing.T) {
		resp := sendExecRequest(t, sockPath, xpc.PolicyRequest{
			Type:      xpc.RequestTypeExecCheck,
			Path:      "rm",
			Args:      []string{"-rf", "/"},
			PID:       5678,
			ParentPID: 1,
			SessionID: "sess-1",
		})
		if resp.Allow {
			t.Error("expected Allow=false")
		}
		if resp.Action != "deny" {
			t.Errorf("action: got %q, want %q", resp.Action, "deny")
		}
		if resp.ExecDecision != "deny" {
			t.Errorf("exec_decision: got %q, want %q", resp.ExecDecision, "deny")
		}
		if resp.Rule != "deny-rm" {
			t.Errorf("rule: got %q, want %q", resp.Rule, "deny-rm")
		}
	})

	// Test: audit decision continues but records the decision
	t.Run("audit_through_pipeline", func(t *testing.T) {
		resp := sendExecRequest(t, sockPath, xpc.PolicyRequest{
			Type:      xpc.RequestTypeExecCheck,
			Path:      "curl",
			Args:      []string{"https://example.com"},
			PID:       2222,
			ParentPID: 1,
			SessionID: "sess-1",
		})
		if !resp.Allow {
			t.Error("expected Allow=true for audit")
		}
		if resp.Action != "continue" {
			t.Errorf("action: got %q, want %q", resp.Action, "continue")
		}
		if resp.ExecDecision != "audit" {
			t.Errorf("exec_decision: got %q, want %q", resp.ExecDecision, "audit")
		}
		if resp.Rule != "audit-curl" {
			t.Errorf("rule: got %q, want %q", resp.Rule, "audit-curl")
		}
	})

	// Test: regular file/command requests still work alongside exec handler
	t.Run("command_request_still_works", func(t *testing.T) {
		resp := sendExecRequest(t, sockPath, xpc.PolicyRequest{
			Type: xpc.RequestTypeCommand,
			Path: "/usr/bin/ls",
			Args: []string{"-la"},
			PID:  1234,
		})
		if !resp.Allow {
			t.Error("expected Allow=true for command request")
		}
	})
}

func TestESExecHandler_XPCIntegration_EnforcedApprove(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("integration tests require Unix sockets (linux or darwin)")
	}

	// Create a policy with approve rule in enforced mode.
	p := &policy.Policy{
		Version: 1,
		Name:    "exec-approve-test",
		CommandRules: []policy.CommandRule{
			{Name: "approve-sudo", Commands: []string{"sudo"}, Decision: "approve"},
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
	}
	// enforceApprovals=true so EffectiveDecision matches PolicyDecision
	engine, err := policy.NewEngine(p, true)
	if err != nil {
		t.Fatal(err)
	}

	checker := &integrationPolicyChecker{engine: engine}
	execHandler := NewESExecHandler(checker, "")

	sockPath := filepath.Join(t.TempDir(), "policy.sock")
	adapter := xpc.NewPolicyAdapter(engine, nil)
	srv := xpc.NewServer(sockPath, adapter)
	srv.SetExecHandler(execHandler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	waitForIntegrationServer(t, srv)

	// In enforced mode, approve decision should trigger redirect action
	t.Run("approve_enforced_redirects", func(t *testing.T) {
		resp := sendExecRequest(t, sockPath, xpc.PolicyRequest{
			Type:      xpc.RequestTypeExecCheck,
			Path:      "sudo",
			Args:      []string{"ls"},
			PID:       3333,
			ParentPID: 1,
			SessionID: "sess-1",
		})
		if resp.Allow {
			t.Error("expected Allow=false for enforced approve (redirect)")
		}
		if resp.Action != "redirect" {
			t.Errorf("action: got %q, want %q", resp.Action, "redirect")
		}
		if resp.ExecDecision != "approve" {
			t.Errorf("exec_decision: got %q, want %q", resp.ExecDecision, "approve")
		}
		if resp.Rule != "approve-sudo" {
			t.Errorf("rule: got %q, want %q", resp.Rule, "approve-sudo")
		}
	})
}

func TestESExecHandler_XPCIntegration_ShadowMode(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("integration tests require Unix sockets (linux or darwin)")
	}

	// Shadow mode: approve policy decision but effective is allow.
	p := &policy.Policy{
		Version: 1,
		Name:    "exec-shadow-test",
		CommandRules: []policy.CommandRule{
			{Name: "approve-sudo", Commands: []string{"sudo"}, Decision: "approve"},
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
	}
	// enforceApprovals=false (shadow mode)
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	checker := &integrationPolicyChecker{engine: engine}
	execHandler := NewESExecHandler(checker, "")

	sockPath := filepath.Join(t.TempDir(), "policy.sock")
	adapter := xpc.NewPolicyAdapter(engine, nil)
	srv := xpc.NewServer(sockPath, adapter)
	srv.SetExecHandler(execHandler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	waitForIntegrationServer(t, srv)

	// In shadow mode, approve should log the intent but allow through
	t.Run("approve_shadow_continues", func(t *testing.T) {
		resp := sendExecRequest(t, sockPath, xpc.PolicyRequest{
			Type:      xpc.RequestTypeExecCheck,
			Path:      "sudo",
			Args:      []string{"ls"},
			PID:       3333,
			ParentPID: 1,
			SessionID: "sess-1",
		})
		if !resp.Allow {
			t.Error("expected Allow=true in shadow mode")
		}
		if resp.Action != "continue" {
			t.Errorf("action: got %q, want %q (shadow mode lets it through)", resp.Action, "continue")
		}
		// ExecDecision should still reflect the policy intent (approve)
		if resp.ExecDecision != "approve" {
			t.Errorf("exec_decision: got %q, want %q", resp.ExecDecision, "approve")
		}
		if resp.Rule != "approve-sudo" {
			t.Errorf("rule: got %q, want %q", resp.Rule, "approve-sudo")
		}
	})
}

func TestESExecHandler_XPCIntegration_NilPolicyChecker(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("integration tests require Unix sockets (linux or darwin)")
	}

	// ESExecHandler with nil policy checker should allow everything.
	execHandler := NewESExecHandler(nil, "")

	p := &policy.Policy{Version: 1, Name: "test"}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	sockPath := filepath.Join(t.TempDir(), "policy.sock")
	adapter := xpc.NewPolicyAdapter(engine, nil)
	srv := xpc.NewServer(sockPath, adapter)
	srv.SetExecHandler(execHandler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	waitForIntegrationServer(t, srv)

	t.Run("nil_checker_allows_all", func(t *testing.T) {
		resp := sendExecRequest(t, sockPath, xpc.PolicyRequest{
			Type:      xpc.RequestTypeExecCheck,
			Path:      "/bin/rm",
			Args:      []string{"-rf", "/"},
			PID:       9999,
			ParentPID: 1,
		})
		if !resp.Allow {
			t.Error("expected Allow=true with nil policy checker")
		}
		if resp.Action != "continue" {
			t.Errorf("action: got %q, want %q", resp.Action, "continue")
		}
		if resp.ExecDecision != "allow" {
			t.Errorf("exec_decision: got %q, want %q", resp.ExecDecision, "allow")
		}
		if resp.Rule != "no_policy" {
			t.Errorf("rule: got %q, want %q", resp.Rule, "no_policy")
		}
	})
}

// sendExecRequest sends a PolicyRequest to the XPC server and returns the response.
func sendExecRequest(t *testing.T, sockPath string, req xpc.PolicyRequest) xpc.PolicyResponse {
	t.Helper()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var resp xpc.PolicyResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	return resp
}
