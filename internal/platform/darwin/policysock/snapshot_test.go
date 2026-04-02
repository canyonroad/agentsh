package policysock

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicySnapshotResponse_JSON(t *testing.T) {
	snap := PolicySnapshotResponse{
		Version:   1,
		SessionID: "session-abc",
		RootPID:   1234,
		FileRules: []SnapshotFileRule{
			{Pattern: "/home/user/project/**", Operations: []string{"read", "write", "create"}, Action: "allow"},
			{Pattern: "/etc/shadow", Operations: []string{"read"}, Action: "deny"},
		},
		NetworkRules: []SnapshotNetworkRule{
			{Pattern: "*.evil.com", Ports: []int{}, Action: "deny"},
		},
		DNSRules: []SnapshotDNSRule{
			{Pattern: "*.evil.com", Action: "nxdomain"},
		},
		ExecRules: []SnapshotExecRule{
			{Pattern: "/usr/bin/git", Action: "redirect"},
			{Pattern: "/usr/bin/rm", Action: "deny"},
		},
		Defaults: &SnapshotDefaults{File: "allow", Network: "allow", DNS: "allow", Exec: "allow"},
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PolicySnapshotResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 1 {
		t.Fatalf("expected version 1, got %d", decoded.Version)
	}
	if len(decoded.FileRules) != 2 {
		t.Fatalf("expected 2 file rules, got %d", len(decoded.FileRules))
	}
	if decoded.FileRules[1].Action != "deny" {
		t.Fatalf("expected deny, got %s", decoded.FileRules[1].Action)
	}
	if len(decoded.ExecRules) != 2 {
		t.Fatalf("expected 2 exec rules, got %d", len(decoded.ExecRules))
	}
	if decoded.ExecRules[0].Action != "redirect" {
		t.Fatalf("expected redirect, got %s", decoded.ExecRules[0].Action)
	}
	if decoded.RootPID != 1234 {
		t.Fatalf("expected root_pid 1234, got %d", decoded.RootPID)
	}
	if decoded.Defaults == nil || decoded.Defaults.DNS != "allow" {
		t.Fatalf("expected allow, got %v", decoded.Defaults)
	}
	if decoded.Defaults == nil || decoded.Defaults.Exec != "allow" {
		t.Fatalf("expected exec default allow, got %v", decoded.Defaults)
	}
}

func TestPolicySnapshotResponse_ProxyFields(t *testing.T) {
	snap := PolicySnapshotResponse{
		SessionID: "test-session",
		ProxyAddr: "127.0.0.1:50382",
		DirectAllow: []DirectAllow{
			{Host: "127.0.0.1", Port: 0},
			{Host: "::1", Port: 0},
			{Host: "*", Port: 53},
		},
	}

	data, err := json.Marshal(snap)
	assert.NoError(t, err)
	assert.Contains(t, string(data), `"proxy_addr":"127.0.0.1:50382"`)

	var decoded PolicySnapshotResponse
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "127.0.0.1:50382", decoded.ProxyAddr)
	assert.Len(t, decoded.DirectAllow, 3)
	assert.Equal(t, "*", decoded.DirectAllow[2].Host)
	assert.Equal(t, 53, decoded.DirectAllow[2].Port)
}

func TestPolicySnapshotResponse_ProxyFieldsOmitEmpty(t *testing.T) {
	snap := PolicySnapshotResponse{
		SessionID: "test-session",
	}

	data, err := json.Marshal(snap)
	assert.NoError(t, err)
	assert.NotContains(t, string(data), "proxy_addr")
	assert.NotContains(t, string(data), "direct_allow")
}

func TestPolicySnapshotResponse_EmptyForMatchingVersion(t *testing.T) {
	snap := PolicySnapshotResponse{}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" {
		t.Fatal("expected valid JSON even for empty snapshot")
	}
	var decoded PolicySnapshotResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 0 {
		t.Fatalf("expected version 0, got %d", decoded.Version)
	}
}
