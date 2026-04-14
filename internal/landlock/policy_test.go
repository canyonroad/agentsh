package landlock

import (
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestDeriveExecutePathsFromPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("landlock tests use Unix paths")
	}
	// Create a policy with command rules
	p := &policy.Policy{
		CommandRules: []policy.CommandRule{
			{
				Name:     "allow git",
				Commands: []string{"/usr/bin/git"},
				Decision: "allow",
			},
			{
				Name:     "allow node",
				Commands: []string{"/usr/local/bin/node"},
				Decision: "allow",
			},
			{
				Name:     "deny rm",
				Commands: []string{"/bin/rm"},
				Decision: "deny", // Should be ignored
			},
			{
				Name:     "allow by basename",
				Commands: []string{"curl"}, // No path - should be ignored
				Decision: "allow",
			},
		},
	}

	paths := DeriveExecutePathsFromPolicy(p)

	// Should extract directories, not full paths
	expected := map[string]bool{
		"/usr/bin":       true,
		"/usr/local/bin": true,
	}

	found := make(map[string]bool)
	for _, p := range paths {
		found[p] = true
	}

	for exp := range expected {
		if !found[exp] {
			t.Errorf("expected path %q not found in result", exp)
		}
	}

	// /bin should NOT be in the list (from denied rule)
	if found["/bin"] {
		t.Error("/bin should not be included (from denied rule)")
	}
}

func TestDeriveExecutePathsFromGlobs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("landlock tests use Unix paths")
	}
	p := &policy.Policy{
		CommandRules: []policy.CommandRule{
			{
				Name:     "allow usr bin",
				Commands: []string{"/usr/bin/*"},
				Decision: "allow",
			},
			{
				Name:     "allow opt",
				Commands: []string{"/opt/*/bin/*"},
				Decision: "allow",
			},
		},
	}

	paths := DeriveExecutePathsFromPolicy(p)

	// Should extract base directories from globs
	found := make(map[string]bool)
	for _, p := range paths {
		found[p] = true
	}

	if !found["/usr/bin"] {
		t.Error("expected /usr/bin from glob /usr/bin/*")
	}

	if !found["/opt"] {
		t.Error("expected /opt from glob /opt/*/bin/*")
	}
}

func TestDeriveReadPaths_WildcardOps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("landlock tests use Unix paths")
	}
	// The agent-default policy uses operations: ["*"] for rules like allow-tmp.
	// DeriveReadPathsFromPolicy must recognize "*" as including "read".
	p := &policy.Policy{
		FileRules: []policy.FileRule{
			{
				Name:       "allow-tmp",
				Paths:      []string{"/tmp/**"},
				Operations: []string{"*"},
				Decision:   "allow",
			},
			{
				Name:       "allow-package-caches",
				Paths:      []string{"/home/user/.cache/**"},
				Operations: []string{"*"},
				Decision:   "allow",
			},
		},
	}

	paths := DeriveReadPathsFromPolicy(p)

	found := make(map[string]bool)
	for _, p := range paths {
		found[p] = true
	}

	if !found["/tmp"] {
		t.Error("expected /tmp from allow-tmp rule with operations: [*]")
	}
	if !found["/home/user/.cache"] {
		t.Error("expected /home/user/.cache from rule with operations: [*]")
	}
}

func TestDeriveWritePaths_WildcardOps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("landlock tests use Unix paths")
	}
	// Same bug: DeriveWritePathsFromPolicy must recognize "*" as including "write".
	p := &policy.Policy{
		FileRules: []policy.FileRule{
			{
				Name:       "allow-tmp",
				Paths:      []string{"/tmp/**", "/var/tmp/**"},
				Operations: []string{"*"},
				Decision:   "allow",
			},
		},
	}

	paths := DeriveWritePathsFromPolicy(p)

	found := make(map[string]bool)
	for _, p := range paths {
		found[p] = true
	}

	if !found["/tmp"] {
		t.Error("expected /tmp from allow-tmp rule with operations: [*]")
	}
	if !found["/var/tmp"] {
		t.Error("expected /var/tmp from allow-tmp rule with operations: [*]")
	}
}

func TestCouldContainBinaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("landlock tests use Unix paths")
	}
	tests := []struct {
		dir  string
		want bool
	}{
		{"/bin", true},
		{"/sbin", true},
		{"/usr", true},          // parent of /usr/bin
		{"/usr/bin", true},
		{"/usr/sbin", true},
		{"/usr/local", true},    // parent of /usr/local/bin
		{"/usr/local/bin", true},
		{"/usr/local/sbin", true},
		{"/lib", false},
		{"/lib64", false},
		{"/dev", false},
		{"/etc", false},
		{"/opt", false},
		{"/tmp", false},
		{"/home/user", false},
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			if got := couldContainBinaries(tt.dir); got != tt.want {
				t.Errorf("couldContainBinaries(%q) = %v, want %v", tt.dir, got, tt.want)
			}
		})
	}
}

func TestDeriveExecutePathsFromFileRules(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("landlock tests use Unix paths")
	}
	p := &policy.Policy{
		FileRules: []policy.FileRule{
			{
				Name:       "allow-system-read",
				Paths:      []string{"/usr/**", "/lib/**", "/lib64/**", "/bin/**", "/sbin/**", "/opt/**", "/dev/**"},
				Operations: []string{"read", "open", "stat", "list", "readlink"},
				Decision:   "allow",
			},
			{
				Name:       "allow-tmp",
				Paths:      []string{"/tmp/**", "/var/tmp/**"},
				Operations: []string{"*"},
				Decision:   "allow",
			},
			{
				Name:       "deny-sensitive",
				Paths:      []string{"/usr/bin/secret"},
				Operations: []string{"read"},
				Decision:   "deny",
			},
		},
	}

	paths := DeriveExecutePathsFromFileRules(p)
	found := make(map[string]bool)
	for _, p := range paths {
		found[p] = true
	}

	for _, want := range []string{"/usr", "/bin", "/sbin"} {
		if !found[want] {
			t.Errorf("expected %q in result, got %v", want, paths)
		}
	}

	for _, reject := range []string{"/lib", "/lib64", "/opt", "/dev", "/tmp", "/var/tmp"} {
		if found[reject] {
			t.Errorf("unexpected %q in result", reject)
		}
	}
}

func TestDeriveExecutePathsFromFileRules_NilPolicy(t *testing.T) {
	paths := DeriveExecutePathsFromFileRules(nil)
	if paths != nil {
		t.Errorf("expected nil for nil policy, got %v", paths)
	}
}

func TestDeriveExecutePathsFromFileRules_NoReadOps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("landlock tests use Unix paths")
	}
	p := &policy.Policy{
		FileRules: []policy.FileRule{
			{
				Name:       "write-only",
				Paths:      []string{"/usr/bin/**"},
				Operations: []string{"write"},
				Decision:   "allow",
			},
		},
	}

	paths := DeriveExecutePathsFromFileRules(p)
	if len(paths) != 0 {
		t.Errorf("expected empty for write-only rule, got %v", paths)
	}
}

func TestDeriveReadPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("landlock tests use Unix paths")
	}
	// Test with file rules
	p := &policy.Policy{
		FileRules: []policy.FileRule{
			{
				Name:       "allow ssl certs",
				Paths:      []string{"/etc/ssl/certs/**"},
				Operations: []string{"read"},
				Decision:   "allow",
			},
			{
				Name:       "deny secrets",
				Paths:      []string{"/etc/passwd"},
				Operations: []string{"read"},
				Decision:   "deny", // Should be ignored
			},
		},
	}

	paths := DeriveReadPathsFromPolicy(p)

	found := make(map[string]bool)
	for _, p := range paths {
		found[p] = true
	}

	if !found["/etc/ssl/certs"] {
		t.Error("expected /etc/ssl/certs from file rule")
	}

	// /etc should NOT be included (from denied rule)
	if found["/etc"] {
		t.Error("/etc should not be included (from denied rule that matches /etc/passwd)")
	}
}
