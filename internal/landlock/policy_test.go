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
