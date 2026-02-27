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
	// Return a copy so callers cannot mutate cached data.
	out := make([]pkgcheck.Finding, len(e.Findings))
	copy(out, e.Findings)
	return out, true
}

// Put stores findings under the given key with the configured TTL.
func (c *Cache) Put(key Key, findings []pkgcheck.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stored := make([]pkgcheck.Finding, len(findings))
	copy(stored, findings)

	c.entries[key.String()] = entry{
		Findings:  stored,
		ExpiresAt: time.Now().Add(c.cfg.DefaultTTL),
	}
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

// flushToDisk writes the current entries to the cache file.
// The caller must hold at least an RLock.
func (c *Cache) flushToDisk() error {
	df := diskFormat{Entries: c.entries}
	data, err := json.Marshal(df)
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}
	if err := os.WriteFile(c.path, data, 0600); err != nil {
		return fmt.Errorf("write cache file: %w", err)
	}
	return nil
}
