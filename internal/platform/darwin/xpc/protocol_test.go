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
