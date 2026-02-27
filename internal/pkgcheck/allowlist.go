package pkgcheck

import (
	"strings"
	"sync"
	"time"
)

type allowEntry struct {
	expiresAt time.Time
}

// Allowlist is a short-lived in-memory store of approved (registry, package, version)
// tuples. Entries expire after a configurable TTL.
type Allowlist struct {
	mu      sync.RWMutex
	entries map[string]allowEntry
	ttl     time.Duration
}

// NewAllowlist creates a new Allowlist with the given TTL for entries.
func NewAllowlist(ttl time.Duration) *Allowlist {
	return &Allowlist{
		entries: make(map[string]allowEntry),
		ttl:     ttl,
	}
}

// Add records an approved (registry, package, version) tuple.
func (a *Allowlist) Add(registry, pkg, version string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := registry + ":" + pkg + ":" + version
	a.entries[key] = allowEntry{expiresAt: time.Now().Add(a.ttl)}
}

// IsAllowed reports whether the given (registry, package, version) tuple
// has been approved and has not yet expired.
func (a *Allowlist) IsAllowed(registry, pkg, version string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	key := registry + ":" + pkg + ":" + version
	entry, ok := a.entries[key]
	if !ok {
		return false
	}
	return time.Now().Before(entry.expiresAt)
}

// IsReadOnlyRegistryCall returns true for registry metadata requests
// that don't download tarballs (e.g., "npm view", "pip index versions").
func (a *Allowlist) IsReadOnlyRegistryCall(urlPath string) bool {
	// Tarball downloads contain /-/ in the path
	if strings.Contains(urlPath, "/-/") {
		return false
	}
	// PyPI download URLs contain /packages/ in the path
	if strings.Contains(urlPath, "/packages/") {
		return false
	}
	return true
}
