package xpc

import (
	"encoding/json"
	"testing"
)

func TestPolicySnapshotResponse_JSON(t *testing.T) {
	snap := PolicySnapshotResponse{
		Version:   1,
		SessionID: "session-abc",
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
		Defaults: &SnapshotDefaults{File: "allow", Network: "allow", DNS: "allow"},
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
	if decoded.Defaults == nil || decoded.Defaults.DNS != "allow" {
		t.Fatalf("expected allow, got %v", decoded.Defaults)
	}
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
