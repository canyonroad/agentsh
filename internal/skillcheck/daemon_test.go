package skillcheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// memCache is a simple in-memory VerdictCache used by daemon tests to avoid
// an import cycle with the skillcheck/cache sub-package.
type memCache struct {
	mu      sync.RWMutex
	entries map[string]*Verdict
}

func newMemCache() *memCache { return &memCache{entries: map[string]*Verdict{}} }

func (c *memCache) Get(sha string) (*Verdict, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.entries[sha]
	return v, ok
}

func (c *memCache) Put(sha string, v *Verdict) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[sha] = v
}

func (c *memCache) Flush() error { return nil }

func TestDaemon_QuarantinesMaliciousSkill(t *testing.T) {
	root := t.TempDir()
	trashDir := filepath.Join(root, ".trash")

	d, err := NewDaemon(DaemonConfig{
		Roots:    []string{root},
		TrashDir: trashDir,
		Providers: map[string]ProviderEntry{
			"local": {Provider: stubProvider{
				name:     "local",
				findings: []Finding{{Type: FindingPromptInjection, Severity: SeverityCritical}},
			}},
		},
		Approval: &fakeApproval{},
		Audit:    &fakeAudit{},
		Cache:    newMemCache(),
	})
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	defer d.Close()
	time.Sleep(100 * time.Millisecond)

	skillDir := filepath.Join(root, "evil")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: evil\n---\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(skillDir); os.IsNotExist(err) {
			return // success — quarantined
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("skill was not quarantined within 3s")
}

func TestDaemon_ProviderErrorWithDenyEscalatesToBlock(t *testing.T) {
	root := t.TempDir()
	trashDir := filepath.Join(root, ".trash")

	d, err := NewDaemon(DaemonConfig{
		Roots:    []string{root},
		TrashDir: trashDir,
		Cache:    newMemCache(),
		Providers: map[string]ProviderEntry{
			"broken": {Provider: stubProvider{name: "broken", err: errors.New("boom")}, OnFailure: "deny"},
		},
		Approval: &fakeApproval{approved: false},
		Audit:    &fakeAudit{},
	})
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	defer d.Close()
	time.Sleep(100 * time.Millisecond)

	skillDir := filepath.Join(root, "skill")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: x\n---\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(skillDir); os.IsNotExist(err) {
			return // quarantined as expected
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("provider error with on_failure=deny should have escalated to quarantine")
}

func TestDaemon_DenyFloorBeatsPositiveProvenance(t *testing.T) {
	// Provider error with OnFailure=deny, plus a positive provenance finding.
	// Without the floor, evaluator would downgrade critical → high → approve.
	// With the floor, the deny survives.
	root := t.TempDir()
	trashDir := filepath.Join(root, ".trash")

	d, err := NewDaemon(DaemonConfig{
		Roots:    []string{root},
		TrashDir: trashDir,
		Cache:    newMemCache(),
		Providers: map[string]ProviderEntry{
			"broken": {Provider: stubProvider{name: "broken", err: errors.New("boom")}, OnFailure: "deny"},
			"skillssh": {Provider: stubProvider{name: "skillssh", findings: []Finding{
				{Type: FindingProvenance, Severity: SeverityInfo, Reasons: []Reason{{Code: "skills_sh_registered"}}},
			}}},
		},
		Approval: &fakeApproval{approved: false},
		Audit:    &fakeAudit{},
	})
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	defer d.Close()
	time.Sleep(100 * time.Millisecond)

	skillDir := filepath.Join(root, "victim")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: victim\n---\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(skillDir); os.IsNotExist(err) {
			return // quarantined as expected
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("provider deny + positive provenance should still block (floor enforced); skill remained installed")
}

func TestDaemon_WarnFloorAllowsLowerActionsToWin(t *testing.T) {
	// Provider error with OnFailure=warn, plus a critical real finding.
	// Floor=warn should NOT downgrade the critical → block evaluator outcome.
	root := t.TempDir()
	trashDir := filepath.Join(root, ".trash")

	d, err := NewDaemon(DaemonConfig{
		Roots:    []string{root},
		TrashDir: trashDir,
		Cache:    newMemCache(),
		Providers: map[string]ProviderEntry{
			"broken": {Provider: stubProvider{name: "broken", err: errors.New("boom")}, OnFailure: "warn"},
			"real": {Provider: stubProvider{name: "real", findings: []Finding{
				{Type: FindingPromptInjection, Severity: SeverityCritical},
			}}},
		},
		Approval: &fakeApproval{approved: false},
		Audit:    &fakeAudit{},
	})
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	defer d.Close()
	time.Sleep(100 * time.Millisecond)

	skillDir := filepath.Join(root, "victim2")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: victim2\n---\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(skillDir); os.IsNotExist(err) {
			return // critical → block; warn floor doesn't lower it
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("critical finding should block regardless of warn floor; skill remained installed")
}
