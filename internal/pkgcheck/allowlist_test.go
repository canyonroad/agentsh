package pkgcheck

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAllowlistAddAndCheck(t *testing.T) {
	al := NewAllowlist(5 * time.Second)
	al.Add("https://registry.npmjs.org", "express", "5.1.0")

	if !al.IsAllowed("https://registry.npmjs.org", "express", "5.1.0") {
		t.Error("expected allowed")
	}
	if al.IsAllowed("https://registry.npmjs.org", "lodash", "4.17.21") {
		t.Error("expected not allowed")
	}
}

func TestAllowlistExpiry(t *testing.T) {
	al := NewAllowlist(10 * time.Millisecond)
	al.Add("https://registry.npmjs.org", "express", "5.1.0")
	time.Sleep(20 * time.Millisecond)
	if al.IsAllowed("https://registry.npmjs.org", "express", "5.1.0") {
		t.Error("expected expired")
	}
}

func TestAllowlistReadOnlyAPIs(t *testing.T) {
	al := NewAllowlist(5 * time.Second)
	if !al.IsReadOnlyRegistryCall("/express") {
		t.Error("npm view should be read-only")
	}
	if al.IsReadOnlyRegistryCall("/express/-/express-5.1.0.tgz") {
		t.Error("tarball download should not be read-only")
	}
	if al.IsReadOnlyRegistryCall("/packages/source/r/requests/requests-2.31.0.tar.gz") {
		t.Error("PyPI package download should not be read-only")
	}
	if !al.IsReadOnlyRegistryCall("/simple/requests/") {
		t.Error("PyPI simple index should be read-only")
	}
}

func TestAllowlistThreadSafety(t *testing.T) {
	al := NewAllowlist(5 * time.Second)

	const goroutines = 50
	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half the goroutines write, half read
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				al.Add("https://registry.npmjs.org", fmt.Sprintf("pkg-%d", id), fmt.Sprintf("%d.0.0", j))
			}
		}(i)

		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				al.IsAllowed("https://registry.npmjs.org", fmt.Sprintf("pkg-%d", id), fmt.Sprintf("%d.0.0", j))
			}
		}(i)
	}

	wg.Wait()

	// After all goroutines complete, verify entries were recorded correctly
	for i := 0; i < goroutines; i++ {
		lastVersion := fmt.Sprintf("%d.0.0", iterations-1)
		if !al.IsAllowed("https://registry.npmjs.org", fmt.Sprintf("pkg-%d", i), lastVersion) {
			t.Errorf("expected pkg-%d@%s to be allowed after concurrent writes", i, lastVersion)
		}
	}
}

func TestAllowlistMultipleEntries(t *testing.T) {
	al := NewAllowlist(5 * time.Second)

	entries := []struct {
		registry string
		pkg      string
		version  string
	}{
		{"https://registry.npmjs.org", "express", "5.1.0"},
		{"https://registry.npmjs.org", "lodash", "4.17.21"},
		{"https://registry.npmjs.org", "react", "18.2.0"},
		{"https://pypi.org", "requests", "2.31.0"},
		{"https://pypi.org", "flask", "3.0.0"},
	}

	// Add all entries
	for _, e := range entries {
		al.Add(e.registry, e.pkg, e.version)
	}

	// Verify each entry is independently tracked and allowed
	for _, e := range entries {
		if !al.IsAllowed(e.registry, e.pkg, e.version) {
			t.Errorf("expected %s/%s@%s to be allowed", e.registry, e.pkg, e.version)
		}
	}

	// Verify non-existent entries are not allowed
	if al.IsAllowed("https://registry.npmjs.org", "express", "4.0.0") {
		t.Error("wrong version should not be allowed")
	}
	if al.IsAllowed("https://pypi.org", "express", "5.1.0") {
		t.Error("wrong registry should not be allowed")
	}
	if al.IsAllowed("https://registry.npmjs.org", "nonexistent", "1.0.0") {
		t.Error("nonexistent package should not be allowed")
	}
}
