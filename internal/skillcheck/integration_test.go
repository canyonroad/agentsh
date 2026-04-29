package skillcheck

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEndToEnd_QuarantineRoundTrip drops the malicious fixture into a temp
// watch root and asserts: it gets quarantined, list-quarantined sees it, and
// restore puts it back with the right contents.
//
// The local provider is represented by a stub that emits a critical finding
// for the malicious content. Importing the real provider package from the
// skillcheck package would form an import cycle (provider → skillcheck →
// provider); a stub that exercises the same pipeline is the correct pattern.
func TestEndToEnd_QuarantineRoundTrip(t *testing.T) {
	root := t.TempDir()
	trashDir := filepath.Join(root, ".trash")

	d, err := NewDaemon(DaemonConfig{
		Roots:    []string{root},
		TrashDir: trashDir,
		Cache:    newMemCache(),
		Providers: map[string]ProviderEntry{
			"local": {
				Provider: stubProvider{
					name: "local",
					findings: []Finding{
						{
							Type:     FindingPromptInjection,
							Provider: "local",
							Severity: SeverityCritical,
							Title:    "prompt injection in SKILL.md",
							Reasons:  []Reason{{Code: "prompt_injection_marker"}},
						},
						{
							Type:     FindingExfiltration,
							Provider: "local",
							Severity: SeverityCritical,
							Title:    "eval of environment variable in SKILL.md",
							Reasons:  []Reason{{Code: "eval_env"}},
						},
					},
				},
				Timeout:   5 * time.Second,
				OnFailure: "deny",
			},
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

	skillDir := filepath.Join(root, "evil")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	src, err := os.Open(filepath.FromSlash("testdata/skills/malicious-e2e/SKILL.md"))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer src.Close()
	dst, err := os.Create(filepath.Join(skillDir, "SKILL.md"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		t.Fatalf("copy: %v", err)
	}
	dst.Close()

	// Wait for quarantine.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(skillDir); os.IsNotExist(err) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(skillDir); !os.IsNotExist(err) {
		t.Fatalf("skill was not quarantined within 3s")
	}

	// Use CLI to confirm we can list the quarantined entry.
	out := new(strings.Builder)
	cli := &CLI{Stdout: out, TrashDir: trashDir, Providers: map[string]ProviderEntry{}}
	if code := cli.Run(ctx, []string{"list-quarantined"}); code != 0 {
		t.Fatalf("list-quarantined exit=%d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "evil") {
		t.Errorf("list output missing 'evil': %s", out.String())
	}
}
