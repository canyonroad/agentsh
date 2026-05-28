package policy

import (
	"path/filepath"
	"testing"
)

// loaderEssentialReads are paths the dynamic linker opens on essentially every
// program startup. Under file_monitor enforcement (FUSE off) these must resolve
// to "allow", or no dynamically-linked program can start. See issue #369.
var loaderEssentialReads = []string{
	"/etc/ld.so.cache",
	"/etc/ld.so.preload",
	"/lib",
	"/lib64",
	"/usr",
	"/bin",
	"/sbin",
	"/lib/x86_64-linux-gnu/libc.so.6",
}

// shippedPoliciesWithSystemRead are the policy files that ship the
// allow-system-read rule (relative to internal/policy/).
var shippedPoliciesWithSystemRead = []string{
	"../../default-policy.yml",
	"../../configs/default-policy.yaml",
	"../../configs/policies/agent-default.yaml",
	"../../configs/policies/agent-sandbox.yaml",
	"../../configs/policies/default.yaml",
	"../../configs/policies/dev-safe.yaml",
	"../../configs/policies/ci-strict.yaml",
	"../../configs/policies/bench-realistic.yaml",
}

// TestIssue369_ShippedPoliciesAllowLoaderReads asserts every shipped policy
// that ships allow-system-read permits the dynamic loader's essential reads
// for op=open. Currently RED for the bare dirs + ld.so.cache (they hit the
// default-deny-files catch-all); turns GREEN once allow-system-read /
// allow-etc-read-safe are broadened.
func TestIssue369_ShippedPoliciesAllowLoaderReads(t *testing.T) {
	for _, rel := range shippedPoliciesWithSystemRead {
		rel := rel
		t.Run(filepath.Base(rel), func(t *testing.T) {
			p, err := LoadFromFile(rel)
			if err != nil {
				t.Fatalf("load %s: %v", rel, err)
			}
			e, err := NewEngine(p, false, true)
			if err != nil {
				// Some shipped files (root default-policy.yml,
				// configs/default-policy.yaml) carry a command-rule arg pattern
				// that NewEngine rejects as a regexp — an unrelated pre-existing
				// issue. Skip rather than conflate it with the loader-reads check.
				t.Skipf("engine %s: %v", rel, err)
			}
			for _, path := range loaderEssentialReads {
				dec := e.CheckFile(path, "open")
				if dec.EffectiveDecision != "allow" {
					t.Errorf("CheckFile(%q, open) = %s (rule=%s); loader read must be allowed",
						path, dec.EffectiveDecision, dec.Rule)
				}
			}
		})
	}
}
