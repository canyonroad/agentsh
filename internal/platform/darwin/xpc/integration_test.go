//go:build integration

package xpc

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestIntegration_FullPolicyFlow(t *testing.T) {
	if os.Getenv("AGENTSH_INTEGRATION") != "1" {
		t.Skip("set AGENTSH_INTEGRATION=1 to run")
	}

	// Create real policy
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		FileRules: []policy.FileRule{
			{Name: "deny-etc", Paths: []string{"/etc/**"}, Operations: []string{"write"}, Decision: "deny"},
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
		CommandRules: []policy.CommandRule{
			{Name: "deny-rm", Commands: []string{"rm"}, Decision: "deny"},
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	// Start server
	sockPath := filepath.Join(t.TempDir(), "policy.sock")
	tracker := NewSessionTracker()
	tracker.RegisterProcess("session-test", 12345, 0)

	adapter := NewPolicyAdapter(engine, tracker)
	srv := NewServer(sockPath, adapter)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	<-srv.Ready()

	// Test file allow
	t.Run("file_allow", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypeFile,
			Path:      "/home/user/test.txt",
			Operation: "read",
			PID:       12345,
		})
		if !resp.Allow {
			t.Error("expected allow")
		}
	})

	// Test file deny
	t.Run("file_deny", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypeFile,
			Path:      "/etc/passwd",
			Operation: "write",
			PID:       12345,
		})
		if resp.Allow {
			t.Error("expected deny")
		}
		if resp.Rule != "deny-etc" {
			t.Errorf("rule: got %q, want %q", resp.Rule, "deny-etc")
		}
	})

	// Test command deny
	t.Run("command_deny", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type: RequestTypeCommand,
			Path: "/bin/rm",
			Args: []string{"-rf", "/"},
			PID:  12345,
		})
		if resp.Allow {
			t.Error("expected deny")
		}
	})

	// Test session lookup
	t.Run("session_lookup", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type: RequestTypeSession,
			PID:  12345,
		})
		if resp.SessionID != "session-test" {
			t.Errorf("session_id: got %q, want %q", resp.SessionID, "session-test")
		}
	})
}

func sendTestRequest(t *testing.T, sockPath string, req PolicyRequest) PolicyResponse {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var resp PolicyResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	return resp
}

// mockPNACLHandler is a test implementation of PNACLHandler.
type mockPNACLHandler struct {
	checkDecision    string
	checkRuleID      string
	pendingApprovals []ApprovalResponse
	submitResult     bool
	configureResult  bool
	events           []PNACLEventRequest
}

func (h *mockPNACLHandler) CheckNetwork(req PNACLCheckRequest) (decision, ruleID string) {
	return h.checkDecision, h.checkRuleID
}

func (h *mockPNACLHandler) ReportEvent(req PNACLEventRequest) {
	h.events = append(h.events, req)
}

func (h *mockPNACLHandler) GetPendingApprovals() []ApprovalResponse {
	return h.pendingApprovals
}

func (h *mockPNACLHandler) SubmitApproval(requestID, decision string, permanent bool) bool {
	return h.submitResult
}

func (h *mockPNACLHandler) Configure(blockingEnabled bool, decisionTimeout float64, failOpen bool) bool {
	return h.configureResult
}

func TestIntegration_PNACLFlow(t *testing.T) {
	if os.Getenv("AGENTSH_INTEGRATION") != "1" {
		t.Skip("set AGENTSH_INTEGRATION=1 to run")
	}

	// Create basic policy handler
	p := &policy.Policy{
		Version:   1,
		Name:      "test",
		FileRules: []policy.FileRule{},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	// Start server with PNACL handler
	sockPath := filepath.Join(t.TempDir(), "policy.sock")
	tracker := NewSessionTracker()
	adapter := NewPolicyAdapter(engine, tracker)
	srv := NewServer(sockPath, adapter)

	// Set up mock PNACL handler
	pnaclHandler := &mockPNACLHandler{
		checkDecision: "allow",
		checkRuleID:   "rule-123",
		pendingApprovals: []ApprovalResponse{
			{
				RequestID:      "req-1",
				ProcessName:    "test-app",
				BundleID:       "com.test.app",
				PID:            1234,
				TargetHost:     "api.example.com",
				TargetPort:     443,
				TargetProtocol: "tcp",
				Timestamp:      "2025-01-01T00:00:00Z",
				Timeout:        30.0,
			},
		},
		submitResult:    true,
		configureResult: true,
	}
	srv.SetPNACLHandler(pnaclHandler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	<-srv.Ready()

	// Test PNACL check
	t.Run("pnacl_check_allow", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:           RequestTypePNACLCheck,
			IP:             "104.18.0.1",
			Port:           443,
			Protocol:       "tcp",
			Domain:         "api.anthropic.com",
			PID:            1234,
			BundleID:       "com.example.app",
			ExecutablePath: "/Applications/Example.app/Contents/MacOS/Example",
			ProcessName:    "Example",
			ParentPID:      1,
		})
		if resp.Decision != "allow" {
			t.Errorf("decision: got %q, want %q", resp.Decision, "allow")
		}
		if resp.RuleID != "rule-123" {
			t.Errorf("rule_id: got %q, want %q", resp.RuleID, "rule-123")
		}
	})

	// Test PNACL check with deny
	t.Run("pnacl_check_deny", func(t *testing.T) {
		pnaclHandler.checkDecision = "deny"
		pnaclHandler.checkRuleID = "deny-rule"

		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:     RequestTypePNACLCheck,
			IP:       "10.0.0.1",
			Port:     80,
			Protocol: "tcp",
			PID:      1234,
		})
		if resp.Decision != "deny" {
			t.Errorf("decision: got %q, want %q", resp.Decision, "deny")
		}
		if resp.Allow {
			t.Error("expected Allow=false for deny decision")
		}
	})

	// Test PNACL event reporting
	t.Run("pnacl_event", func(t *testing.T) {
		initialEvents := len(pnaclHandler.events)

		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypePNACLEvent,
			EventType: "connection_allowed",
			IP:        "104.18.0.1",
			Port:      443,
			Protocol:  "tcp",
			Domain:    "api.anthropic.com",
			PID:       1234,
			BundleID:  "com.example.app",
			Decision:  "allow",
			RuleID:    "rule-123",
		})
		if !resp.Success {
			t.Error("expected success")
		}
		if len(pnaclHandler.events) != initialEvents+1 {
			t.Errorf("expected %d events, got %d", initialEvents+1, len(pnaclHandler.events))
		}
	})

	// Test get pending approvals
	t.Run("pnacl_get_approvals", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type: RequestTypePNACLGetApprovals,
		})
		if len(resp.Approvals) != 1 {
			t.Fatalf("expected 1 approval, got %d", len(resp.Approvals))
		}
		if resp.Approvals[0].RequestID != "req-1" {
			t.Errorf("request_id: got %q, want %q", resp.Approvals[0].RequestID, "req-1")
		}
		if resp.Approvals[0].ProcessName != "test-app" {
			t.Errorf("process_name: got %q, want %q", resp.Approvals[0].ProcessName, "test-app")
		}
	})

	// Test submit approval
	t.Run("pnacl_submit_approval", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypePNACLSubmit,
			RequestID: "req-1",
			Decision:  "allow_permanent",
			Permanent: true,
		})
		if !resp.Success {
			t.Error("expected success")
		}
	})

	// Test configure
	t.Run("pnacl_configure", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:            RequestTypePNACLConfigure,
			BlockingEnabled: true,
			DecisionTimeout: 0.5,
			FailOpen:        false,
		})
		if !resp.Success {
			t.Error("expected success")
		}
	})
}

func TestIntegration_ExecCheckWithHandler(t *testing.T) {
	if os.Getenv("AGENTSH_INTEGRATION") != "1" {
		t.Skip("set AGENTSH_INTEGRATION=1 to run")
	}

	// Create basic policy (needed for PolicyAdapter as PolicyHandler)
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	// Start server with a mock exec handler
	sockPath := filepath.Join(t.TempDir(), "policy.sock")
	tracker := NewSessionTracker()
	adapter := NewPolicyAdapter(engine, tracker)
	srv := NewServer(sockPath, adapter)

	execHandler := &mockExecHandler{
		result: ExecCheckResult{
			Decision: "allow",
			Action:   "continue",
			Rule:     "allow-ls",
			Message:  "",
		},
	}
	srv.SetExecHandler(execHandler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	<-srv.Ready()

	// Test exec_check with allow decision
	t.Run("exec_check_allow", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypeExecCheck,
			Path:      "/usr/bin/ls",
			Args:      []string{"-la"},
			PID:       1234,
			ParentPID: 1,
			SessionID: "session-1",
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
		if resp.Rule != "allow-ls" {
			t.Errorf("rule: got %q, want %q", resp.Rule, "allow-ls")
		}
	})

	// Test exec_check with deny decision
	t.Run("exec_check_deny", func(t *testing.T) {
		execHandler.result = ExecCheckResult{
			Decision: "deny",
			Action:   "deny",
			Rule:     "deny-rm",
			Message:  "command denied by policy",
		}

		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypeExecCheck,
			Path:      "/bin/rm",
			Args:      []string{"-rf", "/"},
			PID:       5678,
			ParentPID: 1,
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
		if resp.Message != "command denied by policy" {
			t.Errorf("message: got %q, want %q", resp.Message, "command denied by policy")
		}
	})

	// Test exec_check with redirect decision
	t.Run("exec_check_redirect", func(t *testing.T) {
		execHandler.result = ExecCheckResult{
			Decision: "redirect",
			Action:   "redirect",
			Rule:     "redirect-git",
			Message:  "redirecting to agentsh-stub",
		}

		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypeExecCheck,
			Path:      "/usr/bin/git",
			Args:      []string{"push"},
			PID:       9999,
			ParentPID: 1,
		})
		if resp.Allow {
			t.Error("expected Allow=false for redirect")
		}
		if resp.Action != "redirect" {
			t.Errorf("action: got %q, want %q", resp.Action, "redirect")
		}
		if resp.ExecDecision != "redirect" {
			t.Errorf("exec_decision: got %q, want %q", resp.ExecDecision, "redirect")
		}
	})
}

func TestIntegration_ExecCheckAllDecisions(t *testing.T) {
	if os.Getenv("AGENTSH_INTEGRATION") != "1" {
		t.Skip("set AGENTSH_INTEGRATION=1 to run")
	}

	// Create basic policy
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	sockPath := filepath.Join(t.TempDir(), "policy.sock")
	tracker := NewSessionTracker()
	adapter := NewPolicyAdapter(engine, tracker)
	srv := NewServer(sockPath, adapter)

	execHandler := &mockExecHandler{}
	srv.SetExecHandler(execHandler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	<-srv.Ready()

	tests := []struct {
		name         string
		decision     string
		action       string
		wantAllow    bool
		wantAction   string
		wantDecision string
	}{
		{"allow_continue", "allow", "continue", true, "continue", "allow"},
		{"deny_deny", "deny", "deny", false, "deny", "deny"},
		{"redirect_redirect", "redirect", "redirect", false, "redirect", "redirect"},
		{"audit_continue", "audit", "continue", true, "continue", "audit"},
		{"approve_redirect", "approve", "redirect", false, "redirect", "approve"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			execHandler.result = ExecCheckResult{
				Decision: tt.decision,
				Action:   tt.action,
				Rule:     "test-rule",
			}

			resp := sendTestRequest(t, sockPath, PolicyRequest{
				Type:      RequestTypeExecCheck,
				Path:      "/usr/bin/test",
				PID:       1234,
				ParentPID: 1,
			})
			if resp.Allow != tt.wantAllow {
				t.Errorf("Allow: got %v, want %v", resp.Allow, tt.wantAllow)
			}
			if resp.Action != tt.wantAction {
				t.Errorf("action: got %q, want %q", resp.Action, tt.wantAction)
			}
			if resp.ExecDecision != tt.wantDecision {
				t.Errorf("exec_decision: got %q, want %q", resp.ExecDecision, tt.wantDecision)
			}
		})
	}
}

func TestIntegration_ExecCheckFallbackToCommand(t *testing.T) {
	if os.Getenv("AGENTSH_INTEGRATION") != "1" {
		t.Skip("set AGENTSH_INTEGRATION=1 to run")
	}

	// Create policy with command rules
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "deny-rm", Commands: []string{"rm"}, Decision: "deny"},
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	sockPath := filepath.Join(t.TempDir(), "policy.sock")
	tracker := NewSessionTracker()
	adapter := NewPolicyAdapter(engine, tracker)
	srv := NewServer(sockPath, adapter)
	// Note: NOT setting exec handler — should fall back to basic command handler

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	<-srv.Ready()

	// Allowed command should fall back to command handler and allow
	t.Run("fallback_allow", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypeExecCheck,
			Path:      "/usr/bin/ls",
			Args:      []string{"-la"},
			PID:       1234,
			ParentPID: 1,
		})
		if !resp.Allow {
			t.Error("expected Allow=true via command handler fallback")
		}
		if resp.Action != "continue" {
			t.Errorf("action: got %q, want %q", resp.Action, "continue")
		}
		// ExecDecision should be populated in fallback path for consistent contract
		if resp.ExecDecision != "allow" {
			t.Errorf("exec_decision: got %q, want %q (fallback to command handler)", resp.ExecDecision, "allow")
		}
	})

	// Denied command should fall back to command handler and deny
	t.Run("fallback_deny", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypeExecCheck,
			Path:      "rm",
			Args:      []string{"-rf", "/"},
			PID:       5678,
			ParentPID: 1,
		})
		if resp.Allow {
			t.Error("expected Allow=false via command handler fallback")
		}
		if resp.Action != "deny" {
			t.Errorf("action: got %q, want %q", resp.Action, "deny")
		}
		if resp.Rule != "deny-rm" {
			t.Errorf("rule: got %q, want %q", resp.Rule, "deny-rm")
		}
	})
}

// mockExecHandler is a mock implementation of ExecHandler for integration tests.
type mockExecHandler struct {
	result ExecCheckResult
}

func (h *mockExecHandler) CheckExec(executable string, args []string, pid int32, parentPID int32, sessionID string) ExecCheckResult {
	return h.result
}

func TestIntegration_PNACLNoHandler(t *testing.T) {
	if os.Getenv("AGENTSH_INTEGRATION") != "1" {
		t.Skip("set AGENTSH_INTEGRATION=1 to run")
	}

	// Create server without PNACL handler
	p := &policy.Policy{Version: 1, Name: "test"}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	sockPath := filepath.Join(t.TempDir(), "policy.sock")
	tracker := NewSessionTracker()
	adapter := NewPolicyAdapter(engine, tracker)
	srv := NewServer(sockPath, adapter)
	// Note: NOT setting PNACL handler

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	<-srv.Ready()

	// PNACL check should default to allow when no handler
	t.Run("pnacl_check_no_handler", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:     RequestTypePNACLCheck,
			IP:       "1.2.3.4",
			Port:     443,
			Protocol: "tcp",
			PID:      1234,
		})
		if resp.Decision != "allow" {
			t.Errorf("decision: got %q, want %q", resp.Decision, "allow")
		}
		if !resp.Allow {
			t.Error("expected Allow=true when no handler")
		}
	})

	// Submit should fail when no handler
	t.Run("pnacl_submit_no_handler", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypePNACLSubmit,
			RequestID: "req-1",
			Decision:  "allow",
		})
		if resp.Success {
			t.Error("expected failure when no handler")
		}
	})
}
