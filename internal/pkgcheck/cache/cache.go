package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

// Key identifies a cached entry by provider, ecosystem, package, and version.
type Key struct {
	Provider  string
	Ecosystem string
	Package   string
	Version   string
}

// String returns the key formatted as "provider:ecosystem:package:version".
func (k Key) String() string {
	return fmt.Sprintf("%s:%s:%s:%s", k.Provider, k.Ecosystem, k.Package, k.Version)
}

// Config controls how the cache behaves.
type Config struct {
	// Dir is the directory where the cache file is stored.
	Dir string
	// MaxSizeMB is the maximum size of the cache file in megabytes (reserved for future use).
	MaxSizeMB int
	// DefaultTTL is the default time-to-live for cache entries.
	DefaultTTL time.Duration
	// TTLByType allows overriding the TTL for specific FindingType values.
	TTLByType map[string]time.Duration
}

// entry is a single cached result with an expiry timestamp.
type entry struct {
	Findings  []pkgcheck.Finding `json:"findings"`
	ExpiresAt time.Time          `json:"expires_at"`
}

// diskFormat is the JSON structure written to and read from disk.
type diskFormat struct {
	Entries map[string]entry `json:"entries"`
}

// Cache provides a thread-safe, TTL-based disk-backed cache for provider findings.
type Cache struct {
	mu      sync.RWMutex
	cfg     Config
	entries map[string]entry
	path    string
}

// New creates a new Cache. If a cache file already exists in cfg.Dir, its entries
// are loaded. The directory is created if it does not exist.
func New(cfg Config) (*Cache, error) {
	if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	c := &Cache{
		cfg:     cfg,
		entries: make(map[string]entry),
		path:    filepath.Join(cfg.Dir, "pkgcache.json"),
	}

	if err := c.loadFromDisk(); err != nil {
		// Non-fatal: start with an empty cache if the file is missing or corrupt.
		c.entries = make(map[string]entry)
	}

	return c, nil
}

// Get retrieves findings for the given key. It returns (nil, false) if the entry
// is missing or has expired.
func (c *Cache) Get(key Key) ([]pkgcheck.Finding, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	e, ok := c.entries[key.String()]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.ExpiresAt) {
		return nil, false
	}
	// Return a deep copy so callers cannot mutate cached data.
	return deepCopyFindings(e.Findings), true
}

// Put stores findings under the given key with a TTL derived from the findings.
// The TTL is the maximum TTLByType value among all finding types in the batch,
// falling back to DefaultTTL when no finding type matches.
func (c *Cache) Put(key Key, findings []pkgcheck.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stored := deepCopyFindings(findings)

	ttl := c.computeTTL(findings)

	c.entries[key.String()] = entry{
		Findings:  stored,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// computeTTL returns the maximum TTLByType value among all finding types,
// falling back to DefaultTTL when no match is found.
func (c *Cache) computeTTL(findings []pkgcheck.Finding) time.Duration {
	if len(c.cfg.TTLByType) == 0 {
		return c.cfg.DefaultTTL
	}

	maxTTL := time.Duration(0)
	found := false
	for _, f := range findings {
		if ttl, ok := c.cfg.TTLByType[string(f.Type)]; ok {
			if !found || ttl > maxTTL {
				maxTTL = ttl
				found = true
			}
		}
	}

	if !found {
		return c.cfg.DefaultTTL
	}
	return maxTTL
}

// Close flushes all entries to disk.
func (c *Cache) Close() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.flushToDisk()
}

// loadFromDisk reads the cache file and populates the in-memory map.
// It is called during New and does not require the mutex since the cache
// is not yet shared.
func (c *Cache) loadFromDisk() error {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}

	var df diskFormat
	if err := json.Unmarshal(data, &df); err != nil {
		return fmt.Errorf("unmarshal cache: %w", err)
	}

	if df.Entries != nil {
		c.entries = df.Entries
	}
	return nil
}

// flushToDisk writes the current non-expired entries to the cache file.
// Expired entries are filtered out and not persisted.
// The caller must hold at least an RLock.
func (c *Cache) flushToDisk() error {
	now := time.Now()
	filtered := make(map[string]entry, len(c.entries))
	for k, e := range c.entries {
		if now.Before(e.ExpiresAt) {
			filtered[k] = e
		}
	}

	df := diskFormat{Entries: filtered}
	data, err := json.Marshal(df)
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}
	if err := os.WriteFile(c.path, data, 0600); err != nil {
		return fmt.Errorf("write cache file: %w", err)
	}
	return nil
}

// deepCopyFindings returns a deep copy of a slice of findings,
// properly copying nested Reasons, Links, and Metadata fields.
func deepCopyFindings(src []pkgcheck.Finding) []pkgcheck.Finding {
	if src == nil {
		return nil
	}
	dst := make([]pkgcheck.Finding, len(src))
	for i, f := range src {
		dst[i] = f // shallow copy of value fields

		// Deep copy Reasons
		if f.Reasons != nil {
			dst[i].Reasons = make([]pkgcheck.Reason, len(f.Reasons))
			copy(dst[i].Reasons, f.Reasons)
		}

		// Deep copy Links
		if f.Links != nil {
			dst[i].Links = make([]string, len(f.Links))
			copy(dst[i].Links, f.Links)
		}

		// Deep copy Metadata
		if f.Metadata != nil {
			dst[i].Metadata = make(map[string]string, len(f.Metadata))
			for k, v := range f.Metadata {
				dst[i].Metadata[k] = v
			}
		}
	}
	return dst
}
