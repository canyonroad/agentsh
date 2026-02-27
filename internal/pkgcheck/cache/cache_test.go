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

func TestTTLByType(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{
		Dir:        dir,
		DefaultTTL: 1 * time.Hour,
		TTLByType: map[string]time.Duration{
			"malware": 24 * time.Hour,
			"vulnerability": 2 * time.Hour,
		},
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
		{
			Type:     pkgcheck.FindingMalware,
			Provider: "osv",
			Package:  pkgcheck.PackageRef{Name: "lodash", Version: "4.17.21"},
			Severity: pkgcheck.SeverityCritical,
			Title:    "Malware Detected",
		},
	}

	c.Put(key, findings)

	// The TTL should be the max of matching types: max(vulnerability=2h, malware=24h) = 24h
	c.mu.RLock()
	e := c.entries[key.String()]
	c.mu.RUnlock()

	// ExpiresAt should be approximately now + 24h (the max TTL)
	expectedExpiry := time.Now().Add(24 * time.Hour)
	diff := e.ExpiresAt.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expected expiry near %v, got %v (diff %v)", expectedExpiry, e.ExpiresAt, diff)
	}
}

func TestTTLByType_FallbackToDefault(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{
		Dir:        dir,
		DefaultTTL: 1 * time.Hour,
		TTLByType: map[string]time.Duration{
			"malware": 24 * time.Hour,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	key := Key{Provider: "osv", Ecosystem: "npm", Package: "lodash", Version: "4.17.21"}
	findings := []pkgcheck.Finding{
		{
			Type:     pkgcheck.FindingLicense,
			Provider: "osv",
			Package:  pkgcheck.PackageRef{Name: "lodash", Version: "4.17.21"},
			Severity: pkgcheck.SeverityLow,
			Title:    "License Issue",
		},
	}

	c.Put(key, findings)

	// No matching TTLByType for "license", should use DefaultTTL (1h)
	c.mu.RLock()
	e := c.entries[key.String()]
	c.mu.RUnlock()

	expectedExpiry := time.Now().Add(1 * time.Hour)
	diff := e.ExpiresAt.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expected expiry near %v, got %v (diff %v)", expectedExpiry, e.ExpiresAt, diff)
	}
}

func TestDeepCopyFindings(t *testing.T) {
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
			Reasons:  []pkgcheck.Reason{{Code: "CVE-2021-12345", Message: "test"}},
			Links:    []string{"https://example.com"},
			Metadata: map[string]string{"key": "value"},
		},
	}

	c.Put(key, findings)

	// Mutate the original findings
	findings[0].Reasons[0].Code = "MUTATED"
	findings[0].Links[0] = "MUTATED"
	findings[0].Metadata["key"] = "MUTATED"

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("Get returned false, want true")
	}

	// Verify that the cached data was not affected by mutation of the original
	if got[0].Reasons[0].Code != "CVE-2021-12345" {
		t.Errorf("cached Reasons was mutated: got %q", got[0].Reasons[0].Code)
	}
	if got[0].Links[0] != "https://example.com" {
		t.Errorf("cached Links was mutated: got %q", got[0].Links[0])
	}
	if got[0].Metadata["key"] != "value" {
		t.Errorf("cached Metadata was mutated: got %q", got[0].Metadata["key"])
	}

	// Mutate the returned findings and verify cache is still unaffected
	got[0].Reasons[0].Code = "MUTATED_AGAIN"
	got[0].Links[0] = "MUTATED_AGAIN"
	got[0].Metadata["key"] = "MUTATED_AGAIN"

	got2, ok := c.Get(key)
	if !ok {
		t.Fatal("Get returned false on second read")
	}
	if got2[0].Reasons[0].Code != "CVE-2021-12345" {
		t.Errorf("cached Reasons was mutated via Get result: got %q", got2[0].Reasons[0].Code)
	}
	if got2[0].Links[0] != "https://example.com" {
		t.Errorf("cached Links was mutated via Get result: got %q", got2[0].Links[0])
	}
	if got2[0].Metadata["key"] != "value" {
		t.Errorf("cached Metadata was mutated via Get result: got %q", got2[0].Metadata["key"])
	}
}

func TestFlushToDisk_FiltersExpired(t *testing.T) {
	dir := t.TempDir()

	key1 := Key{Provider: "osv", Ecosystem: "npm", Package: "active", Version: "1.0.0"}
	key2 := Key{Provider: "osv", Ecosystem: "npm", Package: "expired", Version: "1.0.0"}

	findings := []pkgcheck.Finding{
		{
			Type:     pkgcheck.FindingVulnerability,
			Provider: "osv",
			Severity: pkgcheck.SeverityLow,
			Title:    "test",
		},
	}

	// Create cache and add entries with different TTLs
	c1, err := New(Config{
		Dir:        dir,
		DefaultTTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	c1.Put(key1, findings)
	c1.Put(key2, findings)

	// Manually expire key2
	c1.mu.Lock()
	e := c1.entries[key2.String()]
	e.ExpiresAt = time.Now().Add(-1 * time.Second)
	c1.entries[key2.String()] = e
	c1.mu.Unlock()

	if err := c1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reload cache and verify expired entry was not persisted
	c2, err := New(Config{
		Dir:        dir,
		DefaultTTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	defer c2.Close()

	_, ok1 := c2.Get(key1)
	if !ok1 {
		t.Error("active entry should still be present after reload")
	}

	_, ok2 := c2.Get(key2)
	if ok2 {
		t.Error("expired entry should not be present after reload")
	}

	// Also verify the expired key doesn't exist in the map at all
	c2.mu.RLock()
	_, exists := c2.entries[key2.String()]
	c2.mu.RUnlock()
	if exists {
		t.Error("expired entry should not exist in the reloaded cache map")
	}
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}
