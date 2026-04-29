package skillcheck

import (
	"context"
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
	os.MkdirAll(skillDir, 0o755)
	os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: evil\n---\n"), 0o644)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(skillDir); os.IsNotExist(err) {
			return // success — quarantined
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("skill was not quarantined within 3s")
}
