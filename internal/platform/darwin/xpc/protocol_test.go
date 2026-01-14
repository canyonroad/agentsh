package xpc

import (
	"encoding/json"
	"testing"
)

func TestPolicyRequest_File_Marshal(t *testing.T) {
	req := PolicyRequest{
		Type:      RequestTypeFile,
		Path:      "/workspace/test.txt",
		Operation: "read",
		PID:       1234,
		SessionID: "session-abc",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PolicyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != RequestTypeFile {
		t.Errorf("type: got %q, want %q", decoded.Type, RequestTypeFile)
	}
	if decoded.Path != "/workspace/test.txt" {
		t.Errorf("path: got %q, want %q", decoded.Path, "/workspace/test.txt")
	}
}

func TestPolicyRequest_Network_Marshal(t *testing.T) {
	req := PolicyRequest{
		Type:      RequestTypeNetwork,
		PID:       5678,
		IP:        "192.168.1.100",
		Port:      443,
		Domain:    "example.com",
		SessionID: "session-net",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PolicyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != RequestTypeNetwork {
		t.Errorf("type: got %q, want %q", decoded.Type, RequestTypeNetwork)
	}
	if decoded.IP != "192.168.1.100" {
		t.Errorf("ip: got %q, want %q", decoded.IP, "192.168.1.100")
	}
	if decoded.Port != 443 {
		t.Errorf("port: got %d, want %d", decoded.Port, 443)
	}
	if decoded.Domain != "example.com" {
		t.Errorf("domain: got %q, want %q", decoded.Domain, "example.com")
	}
}

func TestPolicyRequest_Command_Marshal(t *testing.T) {
	req := PolicyRequest{
		Type:      RequestTypeCommand,
		Path:      "/usr/bin/git",
		Operation: "exec",
		PID:       9999,
		Args:      []string{"git", "status", "--porcelain"},
		SessionID: "session-cmd",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PolicyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != RequestTypeCommand {
		t.Errorf("type: got %q, want %q", decoded.Type, RequestTypeCommand)
	}
	if decoded.Path != "/usr/bin/git" {
		t.Errorf("path: got %q, want %q", decoded.Path, "/usr/bin/git")
	}
	if len(decoded.Args) != 3 {
		t.Fatalf("args length: got %d, want 3", len(decoded.Args))
	}
	if decoded.Args[0] != "git" || decoded.Args[1] != "status" || decoded.Args[2] != "--porcelain" {
		t.Errorf("args: got %v, want [git status --porcelain]", decoded.Args)
	}
}

func TestPolicyRequest_Session_Marshal(t *testing.T) {
	req := PolicyRequest{
		Type:      RequestTypeSession,
		PID:       1111,
		SessionID: "session-lookup",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PolicyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != RequestTypeSession {
		t.Errorf("type: got %q, want %q", decoded.Type, RequestTypeSession)
	}
	if decoded.SessionID != "session-lookup" {
		t.Errorf("session_id: got %q, want %q", decoded.SessionID, "session-lookup")
	}
}

func TestPolicyRequest_OmitEmpty(t *testing.T) {
	// Minimal request with only required fields
	req := PolicyRequest{
		Type: RequestTypeFile,
		PID:  1234,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	jsonStr := string(data)

	// These fields should NOT appear in JSON when empty/zero
	omittedFields := []string{
		`"path"`,
		`"operation"`,
		`"session_id"`,
		`"ip"`,
		`"domain"`,
		`"args"`,
		`"event_data"`,
	}

	for _, field := range omittedFields {
		if contains(jsonStr, field) {
			t.Errorf("expected %s to be omitted from JSON, got: %s", field, jsonStr)
		}
	}

	// Port with value 0 should also be omitted
	if contains(jsonStr, `"port"`) {
		t.Errorf("expected port to be omitted when zero, got: %s", jsonStr)
	}

	// These fields should appear
	if !contains(jsonStr, `"type"`) {
		t.Errorf("expected type to be present, got: %s", jsonStr)
	}
	if !contains(jsonStr, `"pid"`) {
		t.Errorf("expected pid to be present, got: %s", jsonStr)
	}
}

func TestPolicyResponse_Marshal(t *testing.T) {
	resp := PolicyResponse{
		Allow:   true,
		Rule:    "allow-workspace",
		Message: "",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PolicyResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !decoded.Allow {
		t.Error("expected allow=true")
	}
	if decoded.Rule != "allow-workspace" {
		t.Errorf("rule: got %q, want %q", decoded.Rule, "allow-workspace")
	}
}

func TestPolicyResponse_OmitEmpty(t *testing.T) {
	resp := PolicyResponse{
		Allow: false,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	jsonStr := string(data)

	// These fields should NOT appear when empty
	if contains(jsonStr, `"rule"`) {
		t.Errorf("expected rule to be omitted when empty, got: %s", jsonStr)
	}
	if contains(jsonStr, `"message"`) {
		t.Errorf("expected message to be omitted when empty, got: %s", jsonStr)
	}
	if contains(jsonStr, `"session_id"`) {
		t.Errorf("expected session_id to be omitted when empty, got: %s", jsonStr)
	}

	// allow should always be present (it's not omitempty)
	if !contains(jsonStr, `"allow"`) {
		t.Errorf("expected allow to be present, got: %s", jsonStr)
	}
}

// contains checks if substr is in s
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// PNACL Protocol Tests

func TestPolicyRequest_PNACLCheck_Marshal(t *testing.T) {
	req := PolicyRequest{
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
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PolicyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != RequestTypePNACLCheck {
		t.Errorf("type: got %q, want %q", decoded.Type, RequestTypePNACLCheck)
	}
	if decoded.IP != "104.18.0.1" {
		t.Errorf("ip: got %q, want %q", decoded.IP, "104.18.0.1")
	}
	if decoded.Port != 443 {
		t.Errorf("port: got %d, want %d", decoded.Port, 443)
	}
	if decoded.Protocol != "tcp" {
		t.Errorf("protocol: got %q, want %q", decoded.Protocol, "tcp")
	}
	if decoded.Domain != "api.anthropic.com" {
		t.Errorf("domain: got %q, want %q", decoded.Domain, "api.anthropic.com")
	}
	if decoded.BundleID != "com.example.app" {
		t.Errorf("bundle_id: got %q, want %q", decoded.BundleID, "com.example.app")
	}
	if decoded.ExecutablePath != "/Applications/Example.app/Contents/MacOS/Example" {
		t.Errorf("executable_path: got %q, want expected path", decoded.ExecutablePath)
	}
	if decoded.ProcessName != "Example" {
		t.Errorf("process_name: got %q, want %q", decoded.ProcessName, "Example")
	}
	if decoded.ParentPID != 1 {
		t.Errorf("parent_pid: got %d, want %d", decoded.ParentPID, 1)
	}
}

func TestPolicyRequest_PNACLEvent_Marshal(t *testing.T) {
	req := PolicyRequest{
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
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PolicyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != RequestTypePNACLEvent {
		t.Errorf("type: got %q, want %q", decoded.Type, RequestTypePNACLEvent)
	}
	if decoded.EventType != "connection_allowed" {
		t.Errorf("event_type: got %q, want %q", decoded.EventType, "connection_allowed")
	}
	if decoded.Decision != "allow" {
		t.Errorf("decision: got %q, want %q", decoded.Decision, "allow")
	}
	if decoded.RuleID != "rule-123" {
		t.Errorf("rule_id: got %q, want %q", decoded.RuleID, "rule-123")
	}
}

func TestPolicyRequest_PNACLSubmit_Marshal(t *testing.T) {
	req := PolicyRequest{
		Type:      RequestTypePNACLSubmit,
		RequestID: "req-abc-123",
		Decision:  "allow_permanent",
		Permanent: true,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PolicyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != RequestTypePNACLSubmit {
		t.Errorf("type: got %q, want %q", decoded.Type, RequestTypePNACLSubmit)
	}
	if decoded.RequestID != "req-abc-123" {
		t.Errorf("request_id: got %q, want %q", decoded.RequestID, "req-abc-123")
	}
	if decoded.Decision != "allow_permanent" {
		t.Errorf("decision: got %q, want %q", decoded.Decision, "allow_permanent")
	}
	if !decoded.Permanent {
		t.Error("expected permanent=true")
	}
}

func TestPolicyRequest_PNACLConfigure_Marshal(t *testing.T) {
	req := PolicyRequest{
		Type:            RequestTypePNACLConfigure,
		BlockingEnabled: true,
		DecisionTimeout: 0.5,
		FailOpen:        false,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PolicyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != RequestTypePNACLConfigure {
		t.Errorf("type: got %q, want %q", decoded.Type, RequestTypePNACLConfigure)
	}
	if !decoded.BlockingEnabled {
		t.Error("expected blocking_enabled=true")
	}
	if decoded.DecisionTimeout != 0.5 {
		t.Errorf("decision_timeout: got %f, want %f", decoded.DecisionTimeout, 0.5)
	}
	if decoded.FailOpen {
		t.Error("expected fail_open=false")
	}
}

func TestPolicyResponse_PNACL_Marshal(t *testing.T) {
	resp := PolicyResponse{
		Allow:    true,
		Decision: "allow",
		RuleID:   "rule-123",
		Success:  true,
		Approvals: []ApprovalResponse{
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
				ExecutablePath: "/path/to/app",
			},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PolicyResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !decoded.Allow {
		t.Error("expected allow=true")
	}
	if decoded.Decision != "allow" {
		t.Errorf("decision: got %q, want %q", decoded.Decision, "allow")
	}
	if decoded.RuleID != "rule-123" {
		t.Errorf("rule_id: got %q, want %q", decoded.RuleID, "rule-123")
	}
	if !decoded.Success {
		t.Error("expected success=true")
	}
	if len(decoded.Approvals) != 1 {
		t.Fatalf("expected 1 approval, got %d", len(decoded.Approvals))
	}
	if decoded.Approvals[0].RequestID != "req-1" {
		t.Errorf("approval request_id: got %q, want %q", decoded.Approvals[0].RequestID, "req-1")
	}
	if decoded.Approvals[0].TargetHost != "api.example.com" {
		t.Errorf("approval target_host: got %q, want %q", decoded.Approvals[0].TargetHost, "api.example.com")
	}
}

func TestApprovalResponse_Marshal(t *testing.T) {
	approval := ApprovalResponse{
		RequestID:      "req-abc-123",
		ProcessName:    "Safari",
		BundleID:       "com.apple.Safari",
		PID:            5678,
		TargetHost:     "www.example.com",
		TargetPort:     443,
		TargetProtocol: "tcp",
		Timestamp:      "2025-01-13T12:00:00Z",
		Timeout:        60.0,
		ExecutablePath: "/Applications/Safari.app/Contents/MacOS/Safari",
	}

	data, err := json.Marshal(approval)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ApprovalResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.RequestID != "req-abc-123" {
		t.Errorf("request_id: got %q, want %q", decoded.RequestID, "req-abc-123")
	}
	if decoded.ProcessName != "Safari" {
		t.Errorf("process_name: got %q, want %q", decoded.ProcessName, "Safari")
	}
	if decoded.BundleID != "com.apple.Safari" {
		t.Errorf("bundle_id: got %q, want %q", decoded.BundleID, "com.apple.Safari")
	}
	if decoded.PID != 5678 {
		t.Errorf("pid: got %d, want %d", decoded.PID, 5678)
	}
	if decoded.TargetHost != "www.example.com" {
		t.Errorf("target_host: got %q, want %q", decoded.TargetHost, "www.example.com")
	}
	if decoded.TargetPort != 443 {
		t.Errorf("target_port: got %d, want %d", decoded.TargetPort, 443)
	}
	if decoded.Timeout != 60.0 {
		t.Errorf("timeout: got %f, want %f", decoded.Timeout, 60.0)
	}
}
