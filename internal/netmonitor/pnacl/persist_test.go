package pnacl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileRulePersister_AddRule(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "pnacl.yaml")

	persister := NewFileRulePersister(configPath)

	target := NetworkTarget{
		Host:     "api.example.com",
		Port:     "443",
		Protocol: "tcp",
		Decision: DecisionAllow,
	}

	err := persister.AddRule("test-process", target, "Auto-added 2026-01-13 via PNACL prompt")
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}

	content := string(data)

	// Check that the file contains expected content
	if !strings.Contains(content, "test-process") {
		t.Error("config should contain process name")
	}
	if !strings.Contains(content, "api.example.com") {
		t.Error("config should contain target host")
	}
	if !strings.Contains(content, "443") {
		t.Error("config should contain port")
	}
	if !strings.Contains(content, "Auto-added") {
		t.Error("config should contain comment")
	}
}

func TestFileRulePersister_AddRule_ExistingConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "pnacl.yaml")

	// Create initial config
	initialConfig := `default: approve
processes:
  - name: existing-process
    match:
      process_name: existing-process
    default: approve
    rules:
      - target: "existing.example.com"
        port: "80"
        decision: allow
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	persister := NewFileRulePersister(configPath)

	// Add rule to existing process
	target := NetworkTarget{
		Host:     "new.example.com",
		Port:     "443",
		Protocol: "tcp",
		Decision: DecisionAllow,
	}

	err := persister.AddRule("existing-process", target, "New rule")
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "new.example.com") {
		t.Error("config should contain new target")
	}
	if !strings.Contains(content, "existing.example.com") {
		t.Error("config should still contain existing target")
	}
}

func TestFileRulePersister_AddRule_NewProcess(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "pnacl.yaml")

	// Create initial config with one process
	initialConfig := `default: approve
processes:
  - name: existing-process
    match:
      process_name: existing-process
    rules:
      - target: "existing.example.com"
        decision: allow
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	persister := NewFileRulePersister(configPath)

	// Add rule for new process
	target := NetworkTarget{
		Host:     "api.example.com",
		Port:     "443",
		Decision: DecisionAllow,
	}

	err := persister.AddRule("new-process", target, "First rule for new process")
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Reload and verify
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if len(config.NetworkACL.Processes) != 2 {
		t.Errorf("expected 2 processes, got %d", len(config.NetworkACL.Processes))
	}

	// Find new process
	var found bool
	for _, p := range config.NetworkACL.Processes {
		if p.Name == "new-process" {
			found = true
			if len(p.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(p.Rules))
			}
			break
		}
	}
	if !found {
		t.Error("new process not found")
	}
}

func TestFileRulePersister_AddRule_DuplicatePrevention(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "pnacl.yaml")

	persister := NewFileRulePersister(configPath)

	target := NetworkTarget{
		Host:     "api.example.com",
		Port:     "443",
		Protocol: "tcp",
		Decision: DecisionAllow,
	}

	// Add the same rule twice
	if err := persister.AddRule("test-process", target, "First add"); err != nil {
		t.Fatalf("first AddRule failed: %v", err)
	}
	if err := persister.AddRule("test-process", target, "Second add"); err != nil {
		t.Fatalf("second AddRule failed: %v", err)
	}

	// Verify only one rule exists
	rules, err := persister.GetRules("test-process")
	if err != nil {
		t.Fatalf("GetRules failed: %v", err)
	}

	if len(rules) != 1 {
		t.Errorf("expected 1 rule (no duplicate), got %d", len(rules))
	}
}

func TestFileRulePersister_RemoveRule(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "pnacl.yaml")

	persister := NewFileRulePersister(configPath)

	// Add two rules
	target1 := NetworkTarget{
		Host:     "api1.example.com",
		Port:     "443",
		Decision: DecisionAllow,
	}
	target2 := NetworkTarget{
		Host:     "api2.example.com",
		Port:     "443",
		Decision: DecisionAllow,
	}

	persister.AddRule("test-process", target1, "")
	persister.AddRule("test-process", target2, "")

	// Remove first rule
	err := persister.RemoveRule("test-process", target1)
	if err != nil {
		t.Fatalf("RemoveRule failed: %v", err)
	}

	// Verify
	rules, err := persister.GetRules("test-process")
	if err != nil {
		t.Fatalf("GetRules failed: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule remaining, got %d", len(rules))
	}
	if rules[0].Host != "api2.example.com" {
		t.Errorf("wrong rule remaining: %s", rules[0].Host)
	}
}

func TestFileRulePersister_GetRules_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "nonexistent.yaml")

	persister := NewFileRulePersister(configPath)

	rules, err := persister.GetRules("any-process")
	if err != nil {
		t.Fatalf("GetRules failed: %v", err)
	}

	if rules != nil && len(rules) > 0 {
		t.Errorf("expected nil or empty rules, got %v", rules)
	}
}

func TestFileRulePersister_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "subdir", "nested", "pnacl.yaml")

	persister := NewFileRulePersister(configPath)

	target := NetworkTarget{
		Host:     "api.example.com",
		Decision: DecisionAllow,
	}

	err := persister.AddRule("test-process", target, "")
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Verify directory and file were created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("config file was not created")
	}
}

func TestInMemoryRulePersister(t *testing.T) {
	persister := NewInMemoryRulePersister()

	target := NetworkTarget{
		Host:     "api.example.com",
		Port:     "443",
		Protocol: "tcp",
		Decision: DecisionAllow,
	}

	// Add rule
	err := persister.AddRule("test-process", target, "comment")
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Get rules
	rules := persister.GetRules("test-process")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Host != "api.example.com" {
		t.Errorf("expected host api.example.com, got %s", rules[0].Host)
	}

	// Add duplicate
	err = persister.AddRule("test-process", target, "duplicate")
	if err != nil {
		t.Fatalf("AddRule duplicate failed: %v", err)
	}

	rules = persister.GetRules("test-process")
	if len(rules) != 1 {
		t.Errorf("expected 1 rule (no duplicate), got %d", len(rules))
	}

	// Clear
	persister.Clear()
	rules = persister.GetRules("test-process")
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after clear, got %d", len(rules))
	}
}

func TestInMemoryRulePersister_RuleAtBeginning(t *testing.T) {
	persister := NewInMemoryRulePersister()

	target1 := NetworkTarget{Host: "first.example.com", Decision: DecisionAllow}
	target2 := NetworkTarget{Host: "second.example.com", Decision: DecisionAllow}

	persister.AddRule("test", target1, "")
	persister.AddRule("test", target2, "")

	rules := persister.GetRules("test")
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	// Second added should be first (prepended)
	if rules[0].Host != "second.example.com" {
		t.Errorf("expected second.example.com first, got %s", rules[0].Host)
	}
}
