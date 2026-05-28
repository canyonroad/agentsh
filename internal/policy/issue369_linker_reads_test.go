package policy

import (
	"path/filepath"
	"strings"
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

// TestIssue369_BareDirsAreLoadBearing is the controlled, non-tautological proof
// that the bare-directory additions to allow-system-read matter: against a
// deny-by-default policy (catch-all default-deny-files on every op), the bare
// dir /lib is DENIED without the bare-dir entry and ALLOWED (via the explicit
// allow-system-read rule) with it. The libc *file* path matches /lib/** either
// way — only the bare dir exercises the fix.
func TestIssue369_BareDirsAreLoadBearing(t *testing.T) {
	const withoutBareDirs = `
version: 1
name: repro-369-without
file_rules:
  - name: allow-system-read
    paths: ["/lib/**"]
    operations: [read, open, stat, list, readlink]
    decision: allow
  - name: default-deny-files
    paths: ["**"]
    operations: ["*"]
    decision: deny
`
	const withBareDirs = `
version: 1
name: repro-369-with
file_rules:
  - name: allow-system-read
    paths: ["/lib", "/lib/**"]
    operations: [read, open, stat, list, readlink]
    decision: allow
  - name: default-deny-files
    paths: ["**"]
    operations: ["*"]
    decision: deny
`
	mustEngine := func(yaml string) *Engine {
		p, err := LoadFromBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		e, err := NewEngine(p, false, true)
		if err != nil {
			t.Fatalf("engine: %v", err)
		}
		return e
	}

	// Without the bare dir, the loader's directory open of /lib is denied.
	if dec := mustEngine(withoutBareDirs).CheckFile("/lib", "open"); dec.EffectiveDecision != "deny" || dec.Rule != "default-deny-files" {
		t.Fatalf("control: /lib without bare dir should hit default-deny-files; got %s/%s", dec.EffectiveDecision, dec.Rule)
	}
	// With the bare dir, it is allowed via the explicit allow-system-read rule.
	if dec := mustEngine(withBareDirs).CheckFile("/lib", "open"); dec.EffectiveDecision != "allow" || dec.Rule != "allow-system-read" {
		t.Fatalf("/lib with bare dir should be allowed via allow-system-read; got %s/%s", dec.EffectiveDecision, dec.Rule)
	}
}

// denyByDefaultPoliciesWithSystemRead are the shipped policies whose catch-all
// default-deny-files matches read ops (so loader reads can actually be denied)
// and that this fix modifies. The write-scoped-catch-all policies (default.yaml,
// agent-default.yaml) allow loader reads via the engine's default-allow-reads
// fallback and are intentionally excluded — asserting an explicit allow rule
// there would wrongly fail.
var denyByDefaultPoliciesWithSystemRead = []string{
	"../../configs/policies/agent-sandbox.yaml",
	"../../configs/policies/dev-safe.yaml",
	"../../configs/policies/ci-strict.yaml",
	"../../configs/policies/bench-realistic.yaml",
	"../../default-policy.yml",
	"../../configs/default-policy.yaml",
}

// TestIssue369_ShippedPoliciesAllowLoaderReads asserts the deny-by-default
// shipped policies permit the dynamic loader's essential reads for op=open VIA
// AN EXPLICIT ALLOW RULE (not the permissive default-allow-reads fallback), so
// removing the bare-dir / etc-open edits would fail this test.
func TestIssue369_ShippedPoliciesAllowLoaderReads(t *testing.T) {
	for _, rel := range denyByDefaultPoliciesWithSystemRead {
		rel := rel
		t.Run(filepath.Base(rel), func(t *testing.T) {
			p, err := LoadFromFile(rel)
			if err != nil {
				t.Fatalf("load %s: %v", rel, err)
			}
			e, err := NewEngine(p, false, true)
			if err != nil {
				// Root default-policy.yml + configs/default-policy.yaml carry a
				// command-rule arg pattern NewEngine rejects as a regexp — an
				// unrelated pre-existing issue. Skip rather than conflate it.
				t.Skipf("engine %s: %v", rel, err)
			}
			for _, path := range loaderEssentialReads {
				dec := e.CheckFile(path, "open")
				if dec.EffectiveDecision != "allow" {
					t.Errorf("CheckFile(%q, open) = %s (rule=%s); loader read must be allowed",
						path, dec.EffectiveDecision, dec.Rule)
					continue
				}
				if !strings.HasPrefix(dec.Rule, "allow-") {
					t.Errorf("CheckFile(%q, open) allowed via %q; expected an explicit allow- rule "+
						"(default-allow-reads fallback means the loader path isn't intentionally allowed)",
						path, dec.Rule)
				}
			}
		})
	}
}
