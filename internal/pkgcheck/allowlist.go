package pkgcheck

import (
	"strings"
	"sync"
	"time"
)

// allowKey is a collision-safe composite key for allowlist entries.
type allowKey struct {
	registry string
	pkg      string
	version  string
}

type allowEntry struct {
	expiresAt time.Time
}

// Allowlist is a short-lived in-memory store of approved (registry, package, version)
// tuples. Entries expire after a configurable TTL.
type Allowlist struct {
	mu      sync.RWMutex
	entries map[allowKey]allowEntry
	ttl     time.Duration
}

// NewAllowlist creates a new Allowlist with the given TTL for entries.
func NewAllowlist(ttl time.Duration) *Allowlist {
	return &Allowlist{
		entries: make(map[allowKey]allowEntry),
		ttl:     ttl,
	}
}

// Add records an approved (registry, package, version) tuple.
func (a *Allowlist) Add(registry, pkg, version string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := allowKey{registry: registry, pkg: pkg, version: version}
	a.entries[key] = allowEntry{expiresAt: time.Now().Add(a.ttl)}
}

// IsAllowed reports whether the given (registry, package, version) tuple
// has been approved and has not yet expired.
func (a *Allowlist) IsAllowed(registry, pkg, version string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	key := allowKey{registry: registry, pkg: pkg, version: version}
	entry, ok := a.entries[key]
	if !ok {
		return false
	}
	return time.Now().Before(entry.expiresAt)
}

// IsReadOnlyRegistryCall returns true for registry metadata requests
// that don't download tarballs (e.g., "npm view", "pip index versions").
//
// Default: not read-only (fail closed).
// Known safe patterns: npm metadata, PyPI simple index.
//
//   - npm: metadata requests don't contain /-/ (tarballs do)
//   - PyPI: simple index doesn't contain /packages/ (downloads do)
//   - Go module: zip/mod downloads end in .zip or .mod
//   - Generic: .tgz, .tar.gz, .whl are download artifacts
//
// For unknown patterns, treat as read-only (metadata) only if none of the
// known download markers are present.
func (a *Allowlist) IsReadOnlyRegistryCall(urlPath string) bool {
	// If path is empty, it's not read-only (fail closed).
	if urlPath == "" {
		return false
	}

	// npm tarball downloads
	if strings.Contains(urlPath, "/-/") {
		return false
	}
	// PyPI package downloads
	if strings.Contains(urlPath, "/packages/") {
		return false
	}
	// Go module zip downloads
	if strings.HasSuffix(urlPath, ".zip") || strings.HasSuffix(urlPath, ".mod") {
		return false
	}
	// Generic: .tgz, .tar.gz, .whl downloads
	if strings.HasSuffix(urlPath, ".tgz") || strings.HasSuffix(urlPath, ".tar.gz") || strings.HasSuffix(urlPath, ".whl") {
		return false
	}

	return true
}
