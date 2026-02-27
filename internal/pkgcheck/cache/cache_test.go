package cache

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

func TestKeyString(t *testing.T) {
	k := Key{
		Provider:  "osv",
		Ecosystem: "npm",
		Package:   "lodash",
		Version:   "4.17.21",
	}
	want := "osv:npm:lodash:4.17.21"
	if got := k.String(); got != want {
		t.Errorf("Key.String() = %q, want %q", got, want)
	}
}

func TestPutThenGet(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{
		Dir:        dir,
		DefaultTTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	key := Key{Provider: "osv", Ecosystem: "npm", Package: "lodash", Version: "4.17.21"}
	findings := []pkgcheck.Finding{
		{
			Type:     pkgcheck.FindingVulnerability,
			Provider: "osv",
			Package:  pkgcheck.PackageRef{Name: "lodash", Version: "4.17.21"},
			Severity: pkgcheck.SeverityHigh,
			Title:    "Prototype Pollution",
		},
	}

	c.Put(key, findings)

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("Get returned false, want true")
	}
	if len(got) != len(findings) {
		t.Fatalf("got %d findings, want %d", len(got), len(findings))
	}
	if got[0].Title != findings[0].Title {
		t.Errorf("got title %q, want %q", got[0].Title, findings[0].Title)
	}
	if got[0].Severity != findings[0].Severity {
		t.Errorf("got severity %q, want %q", got[0].Severity, findings[0].Severity)
	}
}

func TestCacheMiss(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{
		Dir:        dir,
		DefaultTTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	key := Key{Provider: "osv", Ecosystem: "npm", Package: "nonexistent", Version: "0.0.0"}
	got, ok := c.Get(key)
	if ok {
		t.Error("Get returned true for non-existent key")
	}
	if got != nil {
		t.Errorf("Get returned non-nil findings for non-existent key: %v", got)
	}
}

func TestExpiry(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{
		Dir:        dir,
		DefaultTTL: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	key := Key{Provider: "osv", Ecosystem: "npm", Package: "lodash", Version: "4.17.21"}
	findings := []pkgcheck.Finding{
		{
			Type:     pkgcheck.FindingVulnerability,
			Provider: "osv",
			Package:  pkgcheck.PackageRef{Name: "lodash", Version: "4.17.21"},
			Severity: pkgcheck.SeverityHigh,
			Title:    "Prototype Pollution",
		},
	}

	c.Put(key, findings)
	time.Sleep(5 * time.Millisecond)

	got, ok := c.Get(key)
	if ok {
		t.Error("Get returned true for expired entry")
	}
	if got != nil {
		t.Errorf("Get returned non-nil findings for expired entry: %v", got)
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()

	key := Key{Provider: "osv", Ecosystem: "npm", Package: "lodash", Version: "4.17.21"}
	findings := []pkgcheck.Finding{
		{
			Type:     pkgcheck.FindingVulnerability,
			Provider: "osv",
			Package:  pkgcheck.PackageRef{Name: "lodash", Version: "4.17.21"},
			Severity: pkgcheck.SeverityHigh,
			Title:    "Prototype Pollution",
		},
	}

	// Write entries and close.
	c1, err := New(Config{
		Dir:        dir,
		DefaultTTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New (first): %v", err)
	}
	c1.Put(key, findings)
	if err := c1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Open a new cache from the same directory.
	c2, err := New(Config{
		Dir:        dir,
		DefaultTTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New (second): %v", err)
	}
	defer c2.Close()

	got, ok := c2.Get(key)
	if !ok {
		t.Fatal("Get returned false after reload, want true")
	}
	if len(got) != len(findings) {
		t.Fatalf("got %d findings after reload, want %d", len(got), len(findings))
	}
	if got[0].Title != findings[0].Title {
		t.Errorf("got title %q after reload, want %q", got[0].Title, findings[0].Title)
	}
}

func TestThreadSafety(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{
		Dir:        dir,
		DefaultTTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	const goroutines = 50

	for i := range goroutines {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := Key{
				Provider:  "osv",
				Ecosystem: "npm",
				Package:   "pkg",
				Version:   time.Now().String(),
			}
			findings := []pkgcheck.Finding{
				{
					Type:     pkgcheck.FindingVulnerability,
					Provider: "osv",
					Severity: pkgcheck.SeverityLow,
					Title:    "test",
				},
			}
			c.Put(key, findings)
			c.Get(key)
		}(i)
	}

	wg.Wait()
}

func TestLoadCorruptFile(t *testing.T) {
	dir := t.TempDir()

	// Write invalid JSON to the cache file.
	path := filepath.Join(dir, "pkgcache.json")
	if err := writeFile(path, []byte("not json")); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	c, err := New(Config{
		Dir:        dir,
		DefaultTTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New should not fail on corrupt file: %v", err)
	}
	defer c.Close()

	// Should start with empty cache.
	key := Key{Provider: "osv", Ecosystem: "npm", Package: "lodash", Version: "4.17.21"}
	_, ok := c.Get(key)
	if ok {
		t.Error("Get returned true on cache loaded from corrupt file")
	}
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}
