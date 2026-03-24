//go:build darwin && cgo

package darwin

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestCompileDarwinSandbox_EmptyPolicy(t *testing.T) {
	pol := &policy.Policy{}
	cfg, err := CompileDarwinSandbox(pol, "")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox() error = %v", err)
	}
	if !strings.Contains(cfg.Profile, "(version 1)") {
		t.Error("profile should contain (version 1)")
	}
	if !strings.Contains(cfg.Profile, "(deny default)") {
		t.Error("profile should contain (deny default)")
	}
	// System essentials should be present
	if !strings.Contains(cfg.Profile, "(allow process-fork)") {
		t.Error("profile should contain system essentials (process-fork)")
	}
	if !strings.Contains(cfg.Profile, `(subpath "/usr/lib")`) {
		t.Error("profile should contain system essentials (/usr/lib)")
	}
}

func TestCompileDarwinSandbox_FileRules(t *testing.T) {
	pol := &policy.Policy{
		FileRules: []policy.FileRule{
			{
				Paths:      []string{"/etc/config.json"},
				Operations: []string{"read"},
				Decision:   "allow",
			},
			{
				Paths:      []string{"/var/data/"},
				Operations: []string{"read", "write"},
				Decision:   "allow",
			},
		},
	}
	cfg, err := CompileDarwinSandbox(pol, "/workspace")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox() error = %v", err)
	}

	// Read-only rule should produce file-read*
	if !strings.Contains(cfg.Profile, "file-read*") {
		t.Error("profile should contain file-read* for read-only rule")
	}
	if !strings.Contains(cfg.Profile, "/etc/config.json") {
		t.Error("profile should contain the read-only path")
	}

	// Write rule should produce file-write*
	if !strings.Contains(cfg.Profile, "file-write*") {
		t.Error("profile should contain file-write* for write rule")
	}
	if !strings.Contains(cfg.Profile, "/var/data") {
		t.Error("profile should contain the write path")
	}

	// Should have tokens: at least workspace + file rules
	if len(cfg.TokenValues) < 2 {
		t.Errorf("expected at least 2 tokens (workspace + file rules), got %d", len(cfg.TokenValues))
	}
}

func TestCompileDarwinSandbox_CommandRules(t *testing.T) {
	pol := &policy.Policy{
		CommandRules: []policy.CommandRule{
			{
				Commands: []string{"/usr/bin/git"},
				Decision: "allow",
			},
			{
				Commands: []string{"/usr/bin/curl"},
				Decision: "deny",
			},
		},
	}
	cfg, err := CompileDarwinSandbox(pol, "")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox() error = %v", err)
	}

	// Allow rule should produce allow process-exec
	if !strings.Contains(cfg.Profile, `(allow process-exec (literal "/usr/bin/git"))`) {
		t.Errorf("profile should contain allow process-exec for git, got:\n%s", cfg.Profile)
	}

	// Deny rule should produce deny process-exec
	if !strings.Contains(cfg.Profile, `(deny process-exec (literal "/usr/bin/curl"))`) {
		t.Errorf("profile should contain deny process-exec for curl, got:\n%s", cfg.Profile)
	}
}

func TestCompileDarwinSandbox_NetworkAllowAll(t *testing.T) {
	pol := &policy.Policy{
		NetworkRules: []policy.NetworkRule{
			{
				Decision: "allow",
				// No ports, no domains, no CIDRs => allow all
			},
		},
	}
	cfg, err := CompileDarwinSandbox(pol, "")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox() error = %v", err)
	}
	if !strings.Contains(cfg.Profile, "(allow network*)") {
		t.Errorf("profile should contain (allow network*), got:\n%s", cfg.Profile)
	}
}

func TestCompileDarwinSandbox_WorkspaceFullAccess(t *testing.T) {
	pol := &policy.Policy{}
	cfg, err := CompileDarwinSandbox(pol, "/tmp/test-workspace")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox() error = %v", err)
	}

	// Workspace should have file-ioctl
	if !strings.Contains(cfg.Profile, "file-ioctl") {
		t.Error("profile should contain file-ioctl for workspace")
	}
	// Workspace path should be in profile
	if !strings.Contains(cfg.Profile, "/tmp/test-workspace") {
		// Might be resolved to /private/tmp/test-workspace on macOS
		if !strings.Contains(cfg.Profile, "/private/tmp/test-workspace") {
			t.Errorf("profile should contain workspace path, got:\n%s", cfg.Profile)
		}
	}
}

func TestCompileDarwinSandbox_DefaultExecBlocklist(t *testing.T) {
	pol := &policy.Policy{}
	cfg, err := CompileDarwinSandbox(pol, "")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox() error = %v", err)
	}

	blocklist := []string{
		"osascript",
		"security",
		"systemsetup",
		"tccutil",
		"csrutil",
	}
	for _, name := range blocklist {
		if !strings.Contains(cfg.Profile, name) {
			t.Errorf("profile should contain blocked command %q", name)
		}
	}
}

func TestCompileDarwinSandbox_DefaultExecAllowPaths(t *testing.T) {
	pol := &policy.Policy{}
	cfg, err := CompileDarwinSandbox(pol, "")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox() error = %v", err)
	}

	allowPaths := []string{
		"/usr/bin",
		"/bin",
		"/usr/sbin",
		"/sbin",
		"/usr/local/bin",
		"/opt/homebrew/bin",
	}
	for _, path := range allowPaths {
		expected := `(allow process-exec (subpath "` + path + `"))`
		if !strings.Contains(cfg.Profile, expected) {
			t.Errorf("profile should contain %q, got:\n%s", expected, cfg.Profile)
		}
	}
}

func TestCompileDarwinSandbox_MachEssentials(t *testing.T) {
	pol := &policy.Policy{}
	cfg, err := CompileDarwinSandbox(pol, "")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox() error = %v", err)
	}

	// Allowed mach services
	if !strings.Contains(cfg.Profile, "com.apple.system.logger") {
		t.Error("profile should contain allowed mach service com.apple.system.logger")
	}

	// Blocked mach services
	if !strings.Contains(cfg.Profile, "com.apple.security.authtrampoline") {
		t.Error("profile should contain blocked mach service com.apple.security.authtrampoline")
	}
}

func TestCompileDarwinSandbox_DenyFileRuleOmitted(t *testing.T) {
	pol := &policy.Policy{
		FileRules: []policy.FileRule{
			{
				Paths:      []string{"/secret/data"},
				Operations: []string{"read"},
				Decision:   "deny",
			},
		},
	}
	cfg, err := CompileDarwinSandbox(pol, "")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox() error = %v", err)
	}

	// Deny file rules should be omitted (deny = default, so just don't allow)
	if strings.Contains(cfg.Profile, "/secret/data") {
		t.Error("profile should NOT contain denied file path /secret/data")
	}
}
