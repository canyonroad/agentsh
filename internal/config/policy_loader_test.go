package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicyFiles_EnvPolicy(t *testing.T) {
	dir := t.TempDir()

	envPolicy := `
env_protection:
  enabled: true
  mode: allowlist
  allowlist:
    - PATH
    - HOME
    - USER
  blocklist:
    - "*_SECRET*"
    - "*_TOKEN*"
  sensitive_patterns:
    - "(?i)password"
  redact_instead_of_remove: true
  redact_placeholder: "[HIDDEN]"
  log_access: true
  alert_on_sensitive: true
`
	if err := os.WriteFile(filepath.Join(dir, "env.yaml"), []byte(envPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	policies, err := LoadPolicyFiles(dir)
	if err != nil {
		t.Fatalf("LoadPolicyFiles: %v", err)
	}

	if policies.Env == nil {
		t.Fatal("env policy should not be nil")
	}
	if !policies.Env.Enabled {
		t.Error("env_protection.enabled should be true")
	}
	if policies.Env.Mode != "allowlist" {
		t.Errorf("env_protection.mode = %q, want allowlist", policies.Env.Mode)
	}
	if len(policies.Env.Allowlist) != 3 {
		t.Errorf("env_protection.allowlist len = %d, want 3", len(policies.Env.Allowlist))
	}
	if len(policies.Env.Blocklist) != 2 {
		t.Errorf("env_protection.blocklist len = %d, want 2", len(policies.Env.Blocklist))
	}
	if !policies.Env.RedactInsteadOfRemove {
		t.Error("env_protection.redact_instead_of_remove should be true")
	}
	if policies.Env.RedactPlaceholder != "[HIDDEN]" {
		t.Errorf("env_protection.redact_placeholder = %q, want [HIDDEN]", policies.Env.RedactPlaceholder)
	}
}

func TestLoadPolicyFiles_FilePolicy(t *testing.T) {
	dir := t.TempDir()

	filePolicy := `
file_policy:
  default_action: deny
  rules:
    - name: workspace
      paths:
        - "${WORKSPACE}/**"
      operations:
        - read
        - write
        - create
      action: allow
    - name: sensitive
      paths:
        - "**/.ssh/**"
        - "**/.env"
      operations:
        - read
        - write
      action: deny
    - name: redirect-test
      paths:
        - "/etc/passwd"
      operations:
        - read
      action: redirect
      redirect:
        file_path: "/opt/honeypot/fake-passwd"
`
	if err := os.WriteFile(filepath.Join(dir, "files.yaml"), []byte(filePolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	policies, err := LoadPolicyFiles(dir)
	if err != nil {
		t.Fatalf("LoadPolicyFiles: %v", err)
	}

	if policies.File == nil {
		t.Fatal("file policy should not be nil")
	}
	if policies.File.DefaultAction != "deny" {
		t.Errorf("file_policy.default_action = %q, want deny", policies.File.DefaultAction)
	}
	if len(policies.File.Rules) != 3 {
		t.Errorf("file_policy.rules len = %d, want 3", len(policies.File.Rules))
	}

	// Check redirect rule
	redirectRule := policies.File.Rules[2]
	if redirectRule.Action != "redirect" {
		t.Errorf("redirect rule action = %q, want redirect", redirectRule.Action)
	}
	if redirectRule.Redirect == nil {
		t.Fatal("redirect rule should have redirect config")
	}
	if redirectRule.Redirect.FilePath != "/opt/honeypot/fake-passwd" {
		t.Errorf("redirect.file_path = %q", redirectRule.Redirect.FilePath)
	}
}

func TestLoadPolicyFiles_NetworkPolicy(t *testing.T) {
	dir := t.TempDir()

	networkPolicy := `
network_policy:
  default_action: deny
  rules:
    - name: package-registries
      domains:
        - npmjs.org
        - pypi.org
        - github.com
      action: allow
    - name: internal-block
      cidrs:
        - 10.0.0.0/8
        - 192.168.0.0/16
      action: deny
    - name: redirect-api
      domains:
        - api.openai.com
      action: redirect
      redirect:
        host: localhost
        port: 8080
`
	if err := os.WriteFile(filepath.Join(dir, "network.yaml"), []byte(networkPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	policies, err := LoadPolicyFiles(dir)
	if err != nil {
		t.Fatalf("LoadPolicyFiles: %v", err)
	}

	if policies.Network == nil {
		t.Fatal("network policy should not be nil")
	}
	if policies.Network.DefaultAction != "deny" {
		t.Errorf("network_policy.default_action = %q, want deny", policies.Network.DefaultAction)
	}
	if len(policies.Network.Rules) != 3 {
		t.Errorf("network_policy.rules len = %d, want 3", len(policies.Network.Rules))
	}

	// Check redirect rule
	redirectRule := policies.Network.Rules[2]
	if redirectRule.Redirect == nil {
		t.Fatal("redirect rule should have redirect config")
	}
	if redirectRule.Redirect.Host != "localhost" {
		t.Errorf("redirect.host = %q, want localhost", redirectRule.Redirect.Host)
	}
	if redirectRule.Redirect.Port != 8080 {
		t.Errorf("redirect.port = %d, want 8080", redirectRule.Redirect.Port)
	}
}

func TestLoadPolicyFiles_DNSPolicy(t *testing.T) {
	dir := t.TempDir()

	dnsPolicy := `
dns_policy:
  rules:
    - name: block-malware
      patterns:
        - "*.malware.com"
        - "*.evil.net"
      action: deny
    - name: redirect-dns
      patterns:
        - "*"
      action: redirect
      redirect:
        ip_address: "1.1.1.2"
`
	if err := os.WriteFile(filepath.Join(dir, "dns.yaml"), []byte(dnsPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	policies, err := LoadPolicyFiles(dir)
	if err != nil {
		t.Fatalf("LoadPolicyFiles: %v", err)
	}

	if policies.DNS == nil {
		t.Fatal("dns policy should not be nil")
	}
	if len(policies.DNS.Rules) != 2 {
		t.Errorf("dns_policy.rules len = %d, want 2", len(policies.DNS.Rules))
	}

	// Check redirect rule
	redirectRule := policies.DNS.Rules[1]
	if redirectRule.Redirect == nil {
		t.Fatal("redirect rule should have redirect config")
	}
	if redirectRule.Redirect.IPAddress != "1.1.1.2" {
		t.Errorf("redirect.ip_address = %q, want 1.1.1.2", redirectRule.Redirect.IPAddress)
	}
}

func TestLoadPolicyFiles_RegistryPolicy(t *testing.T) {
	dir := t.TempDir()

	registryPolicy := `
registry_policy:
  default_action: allow
  log_all: true
  rules:
    - name: block-autorun
      paths:
        - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*"
        - "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*"
      operations:
        - write
        - create
        - delete
      action: deny
    - name: approve-services
      paths:
        - "HKLM\\SYSTEM\\CurrentControlSet\\Services\\*"
      operations:
        - create
        - write
      action: approve
      timeout_seconds: 300
`
	if err := os.WriteFile(filepath.Join(dir, "registry.yaml"), []byte(registryPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	policies, err := LoadPolicyFiles(dir)
	if err != nil {
		t.Fatalf("LoadPolicyFiles: %v", err)
	}

	if policies.Registry == nil {
		t.Fatal("registry policy should not be nil")
	}
	if policies.Registry.DefaultAction != "allow" {
		t.Errorf("registry_policy.default_action = %q, want allow", policies.Registry.DefaultAction)
	}
	if !policies.Registry.LogAll {
		t.Error("registry_policy.log_all should be true")
	}
	if len(policies.Registry.Rules) != 2 {
		t.Errorf("registry_policy.rules len = %d, want 2", len(policies.Registry.Rules))
	}

	approveRule := policies.Registry.Rules[1]
	if approveRule.TimeoutSeconds != 300 {
		t.Errorf("approve rule timeout_seconds = %d, want 300", approveRule.TimeoutSeconds)
	}
}

func TestLoadPolicyFiles_NoFiles(t *testing.T) {
	dir := t.TempDir()

	policies, err := LoadPolicyFiles(dir)
	if err != nil {
		t.Fatalf("LoadPolicyFiles: %v", err)
	}

	// All policies should be nil when no files exist
	if policies.Env != nil {
		t.Error("env policy should be nil")
	}
	if policies.File != nil {
		t.Error("file policy should be nil")
	}
	if policies.Network != nil {
		t.Error("network policy should be nil")
	}
	if policies.DNS != nil {
		t.Error("dns policy should be nil")
	}
	if policies.Registry != nil {
		t.Error("registry policy should be nil")
	}
}

func TestLoadMinimalPolicy(t *testing.T) {
	dir := t.TempDir()

	minimalPolicy := `
env_protection:
  enabled: true
  mode: allowlist
  allowlist: [PATH, HOME, USER]
  blocklist: ["*_SECRET*"]

file_policy:
  default_action: deny
  rules:
    - name: workspace
      paths: ["${WORKSPACE}/**"]
      operations: [read, write, create]
      action: allow

network_policy:
  default_action: deny
  rules:
    - name: https
      ports: [443]
      action: allow
`
	path := filepath.Join(dir, "minimal.yaml")
	if err := os.WriteFile(path, []byte(minimalPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	policies, err := LoadMinimalPolicy(path)
	if err != nil {
		t.Fatalf("LoadMinimalPolicy: %v", err)
	}

	if policies.Env == nil {
		t.Fatal("env policy should not be nil")
	}
	if policies.File == nil {
		t.Fatal("file policy should not be nil")
	}
	if policies.Network == nil {
		t.Fatal("network policy should not be nil")
	}
}

func TestValidatePolicyFiles_InvalidEnvMode(t *testing.T) {
	policies := &PolicyFiles{
		Env: &EnvProtectionPolicy{
			Enabled: true,
			Mode:    "invalid_mode",
		},
	}

	err := ValidatePolicyFiles(policies)
	if err == nil {
		t.Error("expected error for invalid env mode")
	}
}

func TestValidatePolicyFiles_InvalidFileAction(t *testing.T) {
	policies := &PolicyFiles{
		File: &FilePolicyConfig{
			DefaultAction: "invalid_action",
		},
	}

	err := ValidatePolicyFiles(policies)
	if err == nil {
		t.Error("expected error for invalid file default_action")
	}
}

func TestValidatePolicyFiles_MissingRuleName(t *testing.T) {
	policies := &PolicyFiles{
		File: &FilePolicyConfig{
			DefaultAction: "allow",
			Rules: []FilePolicyRule{
				{
					// Name is missing
					Action: "allow",
				},
			},
		},
	}

	err := ValidatePolicyFiles(policies)
	if err == nil {
		t.Error("expected error for missing rule name")
	}
}

func TestValidatePolicyFiles_ValidPolicies(t *testing.T) {
	policies := &PolicyFiles{
		Env: &EnvProtectionPolicy{
			Enabled: true,
			Mode:    "allowlist",
		},
		File: &FilePolicyConfig{
			DefaultAction: "deny",
			Rules: []FilePolicyRule{
				{
					Name:   "test",
					Action: "allow",
				},
			},
		},
		Network: &NetworkPolicyConfig{
			DefaultAction: "deny",
			Rules: []NetworkPolicyRule{
				{
					Name:   "test",
					Action: "allow",
				},
			},
		},
		Registry: &RegistryPolicyConfig{
			DefaultAction: "allow",
			Rules: []RegistryPolicyRule{
				{
					Name:   "test",
					Action: "deny",
				},
			},
		},
	}

	err := ValidatePolicyFiles(policies)
	if err != nil {
		t.Errorf("ValidatePolicyFiles: %v", err)
	}
}

func TestLoadPolicyFiles_YmlExtension(t *testing.T) {
	dir := t.TempDir()

	// Use .yml extension instead of .yaml
	envPolicy := `
env_protection:
  enabled: true
  mode: blocklist
`
	if err := os.WriteFile(filepath.Join(dir, "env.yml"), []byte(envPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	policies, err := LoadPolicyFiles(dir)
	if err != nil {
		t.Fatalf("LoadPolicyFiles: %v", err)
	}

	if policies.Env == nil {
		t.Fatal("env policy should not be nil (loaded from .yml)")
	}
	if policies.Env.Mode != "blocklist" {
		t.Errorf("env_protection.mode = %q, want blocklist", policies.Env.Mode)
	}
}
