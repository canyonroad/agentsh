package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/netmonitor/pnacl"
)

func TestNetworkACLList_NoConfig(t *testing.T) {
	cmd := newNetworkACLListCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// Use a non-existent config path
	tmpDir := t.TempDir()
	cmd.SetArgs([]string{"--config", tmpDir + "/nonexistent-config.yml"})

	err := cmd.Execute()
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No network ACL configuration found") {
		t.Errorf("expected 'No network ACL configuration found', got: %s", output)
	}
}

func TestNetworkACLList_WithConfig(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "network-acl.yml")

	configContent := `
default: approve
processes:
  - name: test-process
    match:
      process_name: test-process
    default: deny
    rules:
      - target: "*.example.com"
        port: "443"
        decision: allow
      - ip: "10.0.0.1"
        decision: deny
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newNetworkACLListCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--config", configPath})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	output := buf.String()

	// Check that expected content is present
	if !strings.Contains(output, "test-process") {
		t.Errorf("expected 'test-process' in output, got: %s", output)
	}
	if !strings.Contains(output, "*.example.com") {
		t.Errorf("expected '*.example.com' in output, got: %s", output)
	}
	if !strings.Contains(output, "allow") {
		t.Errorf("expected 'allow' in output, got: %s", output)
	}
}

func TestNetworkACLList_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "network-acl.yml")

	configContent := `
default: deny
processes:
  - name: my-app
    match:
      process_name: my-app
    rules:
      - target: api.example.com
        decision: allow
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newNetworkACLListCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--config", configPath, "--json"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"default": "deny"`) {
		t.Errorf("expected JSON with default deny, got: %s", output)
	}
	// The struct uses exported fields so JSON has capital "Name"
	if !strings.Contains(output, `"Name": "my-app"`) {
		t.Errorf("expected JSON with my-app, got: %s", output)
	}
}

func TestNetworkACLList_ProcessFilter(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "network-acl.yml")

	configContent := `
processes:
  - name: app-one
    match:
      process_name: app-one
    rules:
      - target: one.example.com
        decision: allow
  - name: app-two
    match:
      process_name: app-two
    rules:
      - target: two.example.com
        decision: allow
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newNetworkACLListCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--config", configPath, "--process", "one"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "app-one") {
		t.Errorf("expected 'app-one' in output, got: %s", output)
	}
	if strings.Contains(output, "app-two") {
		t.Errorf("should not contain 'app-two' with filter, got: %s", output)
	}
}

func TestNetworkACLAdd(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "network-acl.yml")

	cmd := newNetworkACLAddCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"--config", configPath,
		"my-process",
		"api.example.com",
		"--port", "443",
		"--decision", "allow",
	})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Rule added") {
		t.Errorf("expected 'Rule added' in output, got: %s", output)
	}

	// Verify the config was created
	config, err := pnacl.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if len(config.Processes) != 1 {
		t.Errorf("expected 1 process, got %d", len(config.Processes))
	}
	if config.Processes[0].Name != "my-process" {
		t.Errorf("expected process name 'my-process', got %s", config.Processes[0].Name)
	}
	if len(config.Processes[0].Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(config.Processes[0].Rules))
	}
	rule := config.Processes[0].Rules[0]
	if rule.Host != "api.example.com" {
		t.Errorf("expected target 'api.example.com', got %s", rule.Host)
	}
	if rule.Port != "443" {
		t.Errorf("expected port '443', got %s", rule.Port)
	}
	if rule.Decision != pnacl.DecisionAllow {
		t.Errorf("expected decision 'allow', got %s", rule.Decision)
	}
}

func TestNetworkACLAdd_IPTarget(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "network-acl.yml")

	cmd := newNetworkACLAddCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"--config", configPath,
		"my-process",
		"192.168.1.1",
		"--decision", "deny",
	})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	config, err := pnacl.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	rule := config.Processes[0].Rules[0]
	if rule.IP != "192.168.1.1" {
		t.Errorf("expected IP '192.168.1.1', got %s", rule.IP)
	}
	if rule.Host != "" {
		t.Errorf("expected empty host, got %s", rule.Host)
	}
}

func TestNetworkACLAdd_CIDRTarget(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "network-acl.yml")

	cmd := newNetworkACLAddCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"--config", configPath,
		"my-process",
		"10.0.0.0/8",
		"--decision", "allow",
	})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	config, err := pnacl.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	rule := config.Processes[0].Rules[0]
	if rule.CIDR != "10.0.0.0/8" {
		t.Errorf("expected CIDR '10.0.0.0/8', got %s", rule.CIDR)
	}
}

func TestNetworkACLAdd_InvalidDecision(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "network-acl.yml")

	cmd := newNetworkACLAddCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"--config", configPath,
		"my-process",
		"example.com",
		"--decision", "invalid",
	})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for invalid decision")
	}
	if !strings.Contains(err.Error(), "invalid decision") {
		t.Errorf("expected 'invalid decision' error, got: %v", err)
	}
}

func TestNetworkACLRemove(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "network-acl.yml")

	// Create initial config
	configContent := `
default: approve
processes:
  - name: test-process
    match:
      process_name: test-process
    rules:
      - target: "first.example.com"
        decision: allow
      - target: "second.example.com"
        decision: deny
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newNetworkACLRemoveCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"--config", configPath,
		"--process", "test-process",
		"0",
	})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	// Verify the rule was removed
	config, err := pnacl.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if len(config.Processes[0].Rules) != 1 {
		t.Errorf("expected 1 rule after removal, got %d", len(config.Processes[0].Rules))
	}
	if config.Processes[0].Rules[0].Host != "second.example.com" {
		t.Errorf("expected remaining rule to be 'second.example.com', got %s", config.Processes[0].Rules[0].Host)
	}
}

func TestNetworkACLRemove_ProcessRequired(t *testing.T) {
	cmd := newNetworkACLRemoveCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"0"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when --process not provided")
	}
}

func TestNetworkACLRemove_InvalidIndex(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "network-acl.yml")

	configContent := `
processes:
  - name: test-process
    match:
      process_name: test-process
    rules:
      - target: example.com
        decision: allow
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newNetworkACLRemoveCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"--config", configPath,
		"--process", "test-process",
		"99",
	})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for out-of-range index")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("expected 'out of range' error, got: %v", err)
	}
}

func TestNetworkACLTest(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "network-acl.yml")

	configContent := `
default: deny
processes:
  - name: my-app
    match:
      process_name: my-app
    default: deny
    rules:
      - target: "*.allowed.com"
        port: "443"
        decision: allow
      - target: blocked.com
        decision: deny
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	tests := []struct {
		name           string
		process        string
		target         string
		port           string
		expectedOutput string
	}{
		{
			name:           "allowed by rule",
			process:        "my-app",
			target:         "api.allowed.com",
			port:           "443",
			expectedOutput: "allow",
		},
		{
			name:           "denied by rule",
			process:        "my-app",
			target:         "blocked.com",
			port:           "443",
			expectedOutput: "deny",
		},
		{
			name:           "default deny",
			process:        "my-app",
			target:         "unknown.com",
			port:           "80",
			expectedOutput: "deny",
		},
		{
			name:           "unmatched process global deny",
			process:        "other-app",
			target:         "example.com",
			port:           "443",
			expectedOutput: "deny",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newNetworkACLTestCmd()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs([]string{
				"--config", configPath,
				"--port", tc.port,
				tc.process,
				tc.target,
			})

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("execute: %v", err)
			}

			output := buf.String()
			if !strings.Contains(output, "Decision: "+tc.expectedOutput) {
				t.Errorf("expected 'Decision: %s' in output, got: %s", tc.expectedOutput, output)
			}
		})
	}
}

func TestNetworkACLTest_NoConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cmd := newNetworkACLTestCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"--config", tmpDir + "/nonexistent-config.yml",
		"my-app",
		"example.com",
	})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "approve") {
		t.Errorf("expected 'approve' default when no config, got: %s", output)
	}
}

func TestFormatTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   pnacl.NetworkTarget
		expected string
	}{
		{
			name:     "hostname only",
			target:   pnacl.NetworkTarget{Host: "example.com"},
			expected: "example.com",
		},
		{
			name:     "hostname with port",
			target:   pnacl.NetworkTarget{Host: "example.com", Port: "443"},
			expected: "example.com:443",
		},
		{
			name:     "IP with port and protocol",
			target:   pnacl.NetworkTarget{IP: "192.168.1.1", Port: "8080", Protocol: "tcp"},
			expected: "192.168.1.1:8080 (tcp)",
		},
		{
			name:     "CIDR",
			target:   pnacl.NetworkTarget{CIDR: "10.0.0.0/8"},
			expected: "10.0.0.0/8",
		},
		{
			name:     "wildcard port",
			target:   pnacl.NetworkTarget{Host: "example.com", Port: "*"},
			expected: "example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatTarget(tc.target)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestIsValidACLDecision(t *testing.T) {
	// Case-insensitive validation
	validDecisions := []string{"allow", "deny", "approve", "audit", "ALLOW", "Allow", "DENY", "Audit"}
	invalidDecisions := []string{"block", "permit", "invalid", ""}

	for _, d := range validDecisions {
		if !isValidACLDecision(d) {
			t.Errorf("expected %q to be valid", d)
		}
	}

	for _, d := range invalidDecisions {
		if isValidACLDecision(d) {
			t.Errorf("expected %q to be invalid", d)
		}
	}
}

func TestResolveNetworkACLConfigPath(t *testing.T) {
	// Test override
	override := "/custom/path/config.yml"
	result := resolveNetworkACLConfigPath(override)
	if result != override {
		t.Errorf("expected override path %q, got %q", override, result)
	}

	// Test env var
	os.Setenv("AGENTSH_NETWORK_ACL_CONFIG", "/env/path/config.yml")
	defer os.Unsetenv("AGENTSH_NETWORK_ACL_CONFIG")

	result = resolveNetworkACLConfigPath("")
	if result != "/env/path/config.yml" {
		t.Errorf("expected env path, got %q", result)
	}
}

func TestNetworkACLWatch(t *testing.T) {
	cmd := newNetworkACLWatchCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{})

	// This should return without error, showing usage instructions
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "daemon") {
		t.Errorf("expected daemon instructions in output, got: %s", output)
	}
}

func TestNetworkACLLearn_RequiresProcess(t *testing.T) {
	cmd := newNetworkACLLearnCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--duration", "1s"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when --process not provided")
	}
}
