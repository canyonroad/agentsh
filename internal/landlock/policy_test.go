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
		{"/", false},           // root — filtered out by caller, but function itself returns false
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

func TestDeriveExecutePathsFromFileRules_EmptyFileRules(t *testing.T) {
	// Non-nil policy with empty FileRules slice should return empty.
	p := &policy.Policy{
		FileRules: []policy.FileRule{},
	}
	paths := DeriveExecutePathsFromFileRules(p)
	if len(paths) != 0 {
		t.Errorf("expected empty for empty FileRules, got %v", paths)
	}
}

func TestDeriveExecutePathsFromFileRules_EmptyOperations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("landlock tests use Unix paths")
	}
	// A rule with empty Operations is treated as "all operations" (consistent
	// with DeriveReadPathsFromPolicy behavior). This test documents that.
	p := &policy.Policy{
		FileRules: []policy.FileRule{
			{
				Name:       "no-ops-specified",
				Paths:      []string{"/usr/bin/**"},
				Operations: []string{},
				Decision:   "allow",
			},
		},
	}

	paths := DeriveExecutePathsFromFileRules(p)
	found := make(map[string]bool)
	for _, p := range paths {
		found[p] = true
	}
	if !found["/usr/bin"] {
		t.Errorf("expected /usr/bin from rule with empty operations, got %v", paths)
	}
}

func TestDeriveExecutePathsFromFileRules_Deduplication(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("landlock tests use Unix paths")
	}
	// Multiple rules pointing to the same base directory should be deduplicated.
	p := &policy.Policy{
		FileRules: []policy.FileRule{
			{
				Name:       "rule-a",
				Paths:      []string{"/usr/bin/**"},
				Operations: []string{"read"},
				Decision:   "allow",
			},
			{
				Name:       "rule-b",
				Paths:      []string{"/usr/bin/**", "/usr/sbin/**"},
				Operations: []string{"open"},
				Decision:   "allow",
			},
		},
	}

	paths := DeriveExecutePathsFromFileRules(p)
	counts := make(map[string]int)
	for _, p := range paths {
		counts[p]++
	}
	for dir, count := range counts {
		if count > 1 {
			t.Errorf("directory %q appears %d times, expected 1", dir, count)
		}
	}
	if counts["/usr/bin"] != 1 {
		t.Errorf("expected /usr/bin exactly once, got %d", counts["/usr/bin"])
	}
}

// TestDeriveExecutePaths_BareCommandGap verifies that the original issue is
// fixed: policies using bare command names (git, bash) produce no results from
// DeriveExecutePathsFromPolicy, but DeriveExecutePathsFromFileRules fills the
// gap when file rules grant read access to FHS binary directories.
func TestDeriveExecutePaths_BareCommandGap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("landlock tests use Unix paths")
	}
	// This mimics a real-world policy: bare command names + glob file rules.
	p := &policy.Policy{
		CommandRules: []policy.CommandRule{
			{Name: "allow git", Commands: []string{"git"}, Decision: "allow"},
			{Name: "allow bash", Commands: []string{"bash"}, Decision: "allow"},
			{Name: "allow node", Commands: []string{"node"}, Decision: "allow"},
		},
		FileRules: []policy.FileRule{
			{
				Name:       "allow-system-read",
				Paths:      []string{"/usr/**", "/bin/**", "/sbin/**", "/lib/**"},
				Operations: []string{"read", "open"},
				Decision:   "allow",
			},
		},
	}

	// DeriveExecutePathsFromPolicy should return empty — bare names have no "/".
	fromCommands := DeriveExecutePathsFromPolicy(p)
	if len(fromCommands) != 0 {
		t.Errorf("DeriveExecutePathsFromPolicy should return empty for bare names, got %v", fromCommands)
	}

	// DeriveExecutePathsFromFileRules should bridge the gap.
	fromFileRules := DeriveExecutePathsFromFileRules(p)
	found := make(map[string]bool)
	for _, p := range fromFileRules {
		found[p] = true
	}

	// Must include FHS binary directory ancestors.
	for _, want := range []string{"/usr", "/bin", "/sbin"} {
		if !found[want] {
			t.Errorf("DeriveExecutePathsFromFileRules missing %q — original issue NOT fixed", want)
		}
	}
	// Must exclude non-binary dirs.
	if found["/lib"] {
		t.Errorf("/lib should not be included as execute path")
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
