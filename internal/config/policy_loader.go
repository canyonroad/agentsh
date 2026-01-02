package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// PolicyFiles represents policy configuration loaded from separate files.
type PolicyFiles struct {
	Env      *EnvProtectionPolicy `yaml:"env_protection"`
	File     *FilePolicyConfig    `yaml:"file_policy"`
	Network  *NetworkPolicyConfig `yaml:"network_policy"`
	DNS      *DNSPolicyConfig     `yaml:"dns_policy"`
	Registry *RegistryPolicyConfig `yaml:"registry_policy"` // Windows only
}

// EnvProtectionPolicy configures environment variable protection.
type EnvProtectionPolicy struct {
	Enabled           bool     `yaml:"enabled"`
	Mode              string   `yaml:"mode"` // "allowlist" or "blocklist"
	Allowlist         []string `yaml:"allowlist"`
	Blocklist         []string `yaml:"blocklist"`
	SensitivePatterns []string `yaml:"sensitive_patterns"`
	RedactInsteadOfRemove bool   `yaml:"redact_instead_of_remove"`
	RedactPlaceholder     string `yaml:"redact_placeholder"`
	LogAccess             bool   `yaml:"log_access"`
	AlertOnSensitive      bool   `yaml:"alert_on_sensitive"`
}

// FilePolicyConfig configures file access policy.
type FilePolicyConfig struct {
	DefaultAction string           `yaml:"default_action"` // deny, allow, approve
	Rules         []FilePolicyRule `yaml:"rules"`
}

// FilePolicyRule defines a file access rule.
type FilePolicyRule struct {
	Name           string   `yaml:"name"`
	Paths          []string `yaml:"paths"`
	Operations     []string `yaml:"operations"` // read, write, create, delete, rename, stat
	Action         string   `yaml:"action"`     // allow, deny, approve, redirect
	TimeoutSeconds int      `yaml:"timeout_seconds,omitempty"`
	Redirect       *FileRedirectConfig `yaml:"redirect,omitempty"`
}

// FileRedirectConfig configures file redirect behavior.
type FileRedirectConfig struct {
	FilePath string `yaml:"file_path"`
}

// NetworkPolicyConfig configures network access policy.
type NetworkPolicyConfig struct {
	DefaultAction string              `yaml:"default_action"`
	Rules         []NetworkPolicyRule `yaml:"rules"`
}

// NetworkPolicyRule defines a network access rule.
type NetworkPolicyRule struct {
	Name           string   `yaml:"name"`
	Domains        []string `yaml:"domains,omitempty"`
	CIDRs          []string `yaml:"cidrs,omitempty"`
	Ports          []int    `yaml:"ports,omitempty"`
	Action         string   `yaml:"action"` // allow, deny, approve, redirect
	TimeoutSeconds int      `yaml:"timeout_seconds,omitempty"`
	Redirect       *NetworkRedirectConfig `yaml:"redirect,omitempty"`
}

// NetworkRedirectConfig configures network redirect behavior.
type NetworkRedirectConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// DNSPolicyConfig configures DNS query policy.
type DNSPolicyConfig struct {
	Rules []DNSPolicyRule `yaml:"rules"`
}

// DNSPolicyRule defines a DNS policy rule.
type DNSPolicyRule struct {
	Name     string   `yaml:"name"`
	Patterns []string `yaml:"patterns"` // glob patterns like "*.malware.com"
	Action   string   `yaml:"action"`   // allow, deny, redirect
	Redirect *DNSRedirectConfig `yaml:"redirect,omitempty"`
}

// DNSRedirectConfig configures DNS redirect behavior.
type DNSRedirectConfig struct {
	IPAddress string `yaml:"ip_address"`
}

// RegistryPolicyConfig configures Windows registry access policy.
type RegistryPolicyConfig struct {
	DefaultAction   string               `yaml:"default_action"`
	LogAll          bool                 `yaml:"log_all"`
	DefaultCacheTTL int                  `yaml:"default_cache_ttl"` // seconds
	NotifyOnDeny    bool                 `yaml:"notify_on_deny"`
	Rules           []RegistryPolicyRule `yaml:"rules"`
}

// RegistryPolicyRule defines a Windows registry access rule.
type RegistryPolicyRule struct {
	Name           string                  `yaml:"name"`
	Paths          []string                `yaml:"paths"` // e.g., "HKLM\\SOFTWARE\\..."
	Operations     []string                `yaml:"operations"` // read, write, create, delete
	Action         string                  `yaml:"action"` // allow, deny, approve, redirect
	Priority       int                     `yaml:"priority"`
	CacheTTL       int                     `yaml:"cache_ttl"` // seconds, 0 = use default
	TimeoutSeconds int                     `yaml:"timeout_seconds,omitempty"`
	Notify         bool                    `yaml:"notify"`
	Redirect       *RegistryRedirectConfig `yaml:"redirect,omitempty"`
}

// RegistryRedirectConfig configures registry redirect behavior.
type RegistryRedirectConfig struct {
	Value string `yaml:"value"`
}

// LoadPolicyFiles loads policy configuration from separate files in a directory.
func LoadPolicyFiles(dir string) (*PolicyFiles, error) {
	policies := &PolicyFiles{}

	// Load env policy
	if p, err := loadEnvPolicyFile(dir, "env.yaml", "env.yml"); err != nil {
		return nil, fmt.Errorf("load env policy: %w", err)
	} else if p != nil {
		policies.Env = p
	}

	// Load file policy
	if p, err := loadFilePolicyFile(dir, "files.yaml", "files.yml", "file.yaml", "file.yml"); err != nil {
		return nil, fmt.Errorf("load file policy: %w", err)
	} else if p != nil {
		policies.File = p
	}

	// Load network policy
	if p, err := loadNetworkPolicyFile(dir, "network.yaml", "network.yml"); err != nil {
		return nil, fmt.Errorf("load network policy: %w", err)
	} else if p != nil {
		policies.Network = p
	}

	// Load DNS policy (may be embedded in network.yaml or separate)
	if p, err := loadDNSPolicyFile(dir, "dns.yaml", "dns.yml"); err != nil {
		return nil, fmt.Errorf("load dns policy: %w", err)
	} else if p != nil {
		policies.DNS = p
	}

	// Load registry policy (Windows only)
	if p, err := loadRegistryPolicyFile(dir, "registry.yaml", "registry.yml"); err != nil {
		return nil, fmt.Errorf("load registry policy: %w", err)
	} else if p != nil {
		policies.Registry = p
	}

	return policies, nil
}

// Wrapper types for YAML files with top-level keys
type envPolicyWrapper struct {
	EnvProtection *EnvProtectionPolicy `yaml:"env_protection"`
}

type filePolicyWrapper struct {
	FilePolicy *FilePolicyConfig `yaml:"file_policy"`
}

type networkPolicyWrapper struct {
	NetworkPolicy *NetworkPolicyConfig `yaml:"network_policy"`
}

type dnsPolicyWrapper struct {
	DNSPolicy *DNSPolicyConfig `yaml:"dns_policy"`
}

type registryPolicyWrapper struct {
	RegistryPolicy *RegistryPolicyConfig `yaml:"registry_policy"`
}

func loadEnvPolicyFile(dir string, names ...string) (*EnvProtectionPolicy, error) {
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		var wrapper envPolicyWrapper
		if err := yaml.Unmarshal(data, &wrapper); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		return wrapper.EnvProtection, nil
	}
	return nil, nil
}

func loadFilePolicyFile(dir string, names ...string) (*FilePolicyConfig, error) {
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		var wrapper filePolicyWrapper
		if err := yaml.Unmarshal(data, &wrapper); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		return wrapper.FilePolicy, nil
	}
	return nil, nil
}

func loadNetworkPolicyFile(dir string, names ...string) (*NetworkPolicyConfig, error) {
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		var wrapper networkPolicyWrapper
		if err := yaml.Unmarshal(data, &wrapper); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		return wrapper.NetworkPolicy, nil
	}
	return nil, nil
}

func loadDNSPolicyFile(dir string, names ...string) (*DNSPolicyConfig, error) {
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		var wrapper dnsPolicyWrapper
		if err := yaml.Unmarshal(data, &wrapper); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		return wrapper.DNSPolicy, nil
	}
	return nil, nil
}

func loadRegistryPolicyFile(dir string, names ...string) (*RegistryPolicyConfig, error) {
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		var wrapper registryPolicyWrapper
		if err := yaml.Unmarshal(data, &wrapper); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		return wrapper.RegistryPolicy, nil
	}
	return nil, nil
}

// LoadMinimalPolicy loads a minimal starter policy from a single file.
func LoadMinimalPolicy(path string) (*PolicyFiles, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var policies PolicyFiles
	if err := yaml.Unmarshal(data, &policies); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return &policies, nil
}

// ValidatePolicyFiles validates the loaded policy files.
func ValidatePolicyFiles(policies *PolicyFiles) error {
	if policies.Env != nil {
		if err := validateEnvPolicy(policies.Env); err != nil {
			return fmt.Errorf("env policy: %w", err)
		}
	}
	if policies.File != nil {
		if err := validateFilePolicy(policies.File); err != nil {
			return fmt.Errorf("file policy: %w", err)
		}
	}
	if policies.Network != nil {
		if err := validateNetworkPolicy(policies.Network); err != nil {
			return fmt.Errorf("network policy: %w", err)
		}
	}
	if policies.Registry != nil {
		if err := validateRegistryPolicy(policies.Registry); err != nil {
			return fmt.Errorf("registry policy: %w", err)
		}
	}
	return nil
}

func validateEnvPolicy(p *EnvProtectionPolicy) error {
	switch strings.ToLower(p.Mode) {
	case "", "allowlist", "blocklist":
	default:
		return fmt.Errorf("invalid mode %q (must be 'allowlist' or 'blocklist')", p.Mode)
	}
	return nil
}

func validateFilePolicy(p *FilePolicyConfig) error {
	if err := validateAction(p.DefaultAction); err != nil {
		return fmt.Errorf("default_action: %w", err)
	}
	for i, rule := range p.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule[%d]: name is required", i)
		}
		if err := validateAction(rule.Action); err != nil {
			return fmt.Errorf("rule[%d] %q: action: %w", i, rule.Name, err)
		}
	}
	return nil
}

func validateNetworkPolicy(p *NetworkPolicyConfig) error {
	if err := validateAction(p.DefaultAction); err != nil {
		return fmt.Errorf("default_action: %w", err)
	}
	for i, rule := range p.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule[%d]: name is required", i)
		}
		if err := validateAction(rule.Action); err != nil {
			return fmt.Errorf("rule[%d] %q: action: %w", i, rule.Name, err)
		}
	}
	return nil
}

func validateRegistryPolicy(p *RegistryPolicyConfig) error {
	if err := validateAction(p.DefaultAction); err != nil {
		return fmt.Errorf("default_action: %w", err)
	}
	for i, rule := range p.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule[%d]: name is required", i)
		}
		if err := validateAction(rule.Action); err != nil {
			return fmt.Errorf("rule[%d] %q: action: %w", i, rule.Name, err)
		}
	}
	return nil
}

func validateAction(action string) error {
	switch strings.ToLower(action) {
	case "", "allow", "deny", "approve", "redirect":
		return nil
	default:
		return fmt.Errorf("invalid action %q (must be 'allow', 'deny', 'approve', or 'redirect')", action)
	}
}
