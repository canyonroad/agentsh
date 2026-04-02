package xpc

// PolicySnapshotResponse is the internal representation of a policy snapshot.
// BuildPolicySnapshot returns a PolicyResponse (the wire type) directly,
// embedding snapshot data in its optional fields. This type documents the
// snapshot schema and is used in tests for JSON round-trip validation.
type PolicySnapshotResponse struct {
	Version      uint64                `json:"version"`
	SessionID    string                `json:"session_id"`
	RootPID      int32                 `json:"root_pid"`
	FileRules    []SnapshotFileRule    `json:"file_rules"`
	NetworkRules []SnapshotNetworkRule `json:"network_rules"`
	DNSRules     []SnapshotDNSRule     `json:"dns_rules"`
	ExecRules    []SnapshotExecRule    `json:"exec_rules"`
	Defaults     *SnapshotDefaults     `json:"defaults"`
}

// SnapshotFileRule represents a single file-access rule in the snapshot.
type SnapshotFileRule struct {
	Pattern    string   `json:"pattern"`
	Operations []string `json:"operations"`
	Action     string   `json:"action"`
}

// SnapshotNetworkRule represents a single network-access rule in the snapshot.
type SnapshotNetworkRule struct {
	Pattern  string `json:"pattern"`
	Ports    []int  `json:"ports"`
	Protocol string `json:"protocol,omitempty"`
	Action   string `json:"action"`
}

// SnapshotDNSRule represents a single DNS-filtering rule in the snapshot.
type SnapshotDNSRule struct {
	Pattern string `json:"pattern"`
	Action  string `json:"action"`
}

// SnapshotExecRule represents a single exec rule in the snapshot.
type SnapshotExecRule struct {
	Pattern string `json:"pattern"`
	Action  string `json:"action"` // "allow", "deny", "redirect"
}

// SnapshotDefaults holds the default decision for each resource category.
type SnapshotDefaults struct {
	File    string `json:"file"`
	Network string `json:"network"`
	DNS     string `json:"dns"`
	Exec    string `json:"exec"`
}
