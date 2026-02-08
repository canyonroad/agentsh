package windows

import "testing"

// mockExecPolicyChecker implements WinExecPolicyChecker for testing
type mockExecPolicyChecker struct {
	decision          string
	effectiveDecision string
	rule              string
	message           string
}

func (m *mockExecPolicyChecker) CheckCommand(cmd, cmdLine string) WinExecPolicyResult {
	return WinExecPolicyResult{
		Decision:          m.decision,
		EffectiveDecision: m.effectiveDecision,
		Rule:              m.rule,
		Message:           m.message,
	}
}

func TestWinExecHandler_AllowResumes(t *testing.T) {
	handler := NewWinExecHandler(&mockExecPolicyChecker{
		decision:          "allow",
		effectiveDecision: "allow",
	}, "")

	req := &SuspendedProcessRequest{
		ProcessId:   1234,
		ImagePath:   `C:\Windows\System32\cmd.exe`,
		CommandLine: `cmd.exe /c dir`,
	}

	decision := handler.HandleSuspended(req)
	if decision != ExecDecisionResume {
		t.Errorf("allow should map to ExecDecisionResume, got %d", decision)
	}
}

func TestWinExecHandler_AuditResumes(t *testing.T) {
	handler := NewWinExecHandler(&mockExecPolicyChecker{
		decision:          "audit",
		effectiveDecision: "audit",
	}, "")

	req := &SuspendedProcessRequest{
		ProcessId:   1234,
		ImagePath:   `C:\Windows\System32\cmd.exe`,
		CommandLine: `cmd.exe /c dir`,
	}

	decision := handler.HandleSuspended(req)
	if decision != ExecDecisionResume {
		t.Errorf("audit should map to ExecDecisionResume, got %d", decision)
	}
}

func TestWinExecHandler_DenyTerminates(t *testing.T) {
	handler := NewWinExecHandler(&mockExecPolicyChecker{
		decision:          "deny",
		effectiveDecision: "deny",
	}, "")

	req := &SuspendedProcessRequest{
		ProcessId:   1234,
		ImagePath:   `C:\malware.exe`,
		CommandLine: `malware.exe --bad`,
	}

	decision := handler.HandleSuspended(req)
	if decision != ExecDecisionTerminate {
		t.Errorf("deny should map to ExecDecisionTerminate, got %d", decision)
	}
}

func TestWinExecHandler_ApproveRedirects(t *testing.T) {
	handler := NewWinExecHandler(&mockExecPolicyChecker{
		decision:          "approve",
		effectiveDecision: "approve",
	}, "agentsh-stub.exe")

	req := &SuspendedProcessRequest{
		ProcessId:   1234,
		ImagePath:   `C:\tools\git.exe`,
		CommandLine: `git push origin main`,
	}

	decision := handler.HandleSuspended(req)
	if decision != ExecDecisionRedirect {
		t.Errorf("approve should map to ExecDecisionRedirect, got %d", decision)
	}
}

func TestWinExecHandler_RedirectWithoutStubTerminates(t *testing.T) {
	// If no stub binary is configured, redirect falls back to terminate
	handler := NewWinExecHandler(&mockExecPolicyChecker{
		decision:          "approve",
		effectiveDecision: "approve",
	}, "") // No stub binary

	req := &SuspendedProcessRequest{
		ProcessId: 1234,
	}

	decision := handler.HandleSuspended(req)
	if decision != ExecDecisionTerminate {
		t.Errorf("approve without stub binary should fall back to terminate, got %d", decision)
	}
}

func TestWinExecHandler_NilCheckerFailOpen(t *testing.T) {
	// Nil policy checker should fail-open (resume)
	handler := NewWinExecHandler(nil, "")

	req := &SuspendedProcessRequest{
		ProcessId: 1234,
	}

	decision := handler.HandleSuspended(req)
	if decision != ExecDecisionResume {
		t.Errorf("nil checker should fail-open to ExecDecisionResume, got %d", decision)
	}
}

func TestWinExecHandler_UnknownDecisionTerminates(t *testing.T) {
	// Unknown decision should fail-secure (terminate)
	handler := NewWinExecHandler(&mockExecPolicyChecker{
		decision:          "unknown-decision",
		effectiveDecision: "unknown-decision",
	}, "")

	req := &SuspendedProcessRequest{
		ProcessId: 1234,
	}

	decision := handler.HandleSuspended(req)
	if decision != ExecDecisionTerminate {
		t.Errorf("unknown decision should fail-secure to ExecDecisionTerminate, got %d", decision)
	}
}

func TestWinExecHandler_EffectiveDecisionOverrides(t *testing.T) {
	// The effective decision should be used over the raw decision
	handler := NewWinExecHandler(&mockExecPolicyChecker{
		decision:          "approve",
		effectiveDecision: "allow", // Effective overrides to allow
	}, "agentsh-stub.exe")

	req := &SuspendedProcessRequest{
		ProcessId: 1234,
	}

	decision := handler.HandleSuspended(req)
	if decision != ExecDecisionResume {
		t.Errorf("effective decision 'allow' should map to ExecDecisionResume, got %d", decision)
	}
}

func TestWinExecHandler_CommandInfoPassing(t *testing.T) {
	// Verify that command info is correctly passed to the policy checker
	var gotCmd, gotCmdLine string
	checker := &recordingChecker{
		result: WinExecPolicyResult{
			Decision:          "allow",
			EffectiveDecision: "allow",
		},
	}
	checker.recordCmd = func(cmd, cmdLine string) {
		gotCmd = cmd
		gotCmdLine = cmdLine
	}

	handler := NewWinExecHandler(checker, "")

	req := &SuspendedProcessRequest{
		ProcessId:   1234,
		ImagePath:   `C:\Windows\System32\cmd.exe`,
		CommandLine: `cmd.exe /c echo hello`,
	}

	handler.HandleSuspended(req)

	if gotCmd != `C:\Windows\System32\cmd.exe` {
		t.Errorf("expected cmd %q, got %q", `C:\Windows\System32\cmd.exe`, gotCmd)
	}
	if gotCmdLine != `cmd.exe /c echo hello` {
		t.Errorf("expected cmdLine %q, got %q", `cmd.exe /c echo hello`, gotCmdLine)
	}
}

// recordingChecker records calls for verification
type recordingChecker struct {
	result    WinExecPolicyResult
	recordCmd func(cmd, cmdLine string)
}

func (r *recordingChecker) CheckCommand(cmd, cmdLine string) WinExecPolicyResult {
	if r.recordCmd != nil {
		r.recordCmd(cmd, cmdLine)
	}
	return r.result
}
