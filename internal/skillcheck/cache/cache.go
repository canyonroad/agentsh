package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/skillcheck"
)

// Config controls cache behavior.
type Config struct {
	Dir        string
	DefaultTTL time.Duration
}

type entry struct {
	Verdict   *skillcheck.Verdict `json:"verdict"`
	ExpiresAt time.Time           `json:"expires_at"`
}

// Cache is a thread-safe SHA-keyed verdict cache, persisted as JSON.
type Cache struct {
	mu      sync.RWMutex
	cfg     Config
	entries map[string]entry
	path    string
}

// New creates a new Cache. If a cache file already exists in cfg.Dir, its
// entries are loaded. The directory is created if it does not exist.
func New(cfg Config) (*Cache, error) {
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	c := &Cache{cfg: cfg, entries: map[string]entry{}, path: filepath.Join(cfg.Dir, "skillcache.json")}
	_ = c.load()
	return c, nil
}

// Get retrieves the verdict for the given SHA256 key. It returns (nil, false)
// if the entry is missing or has expired.
func (c *Cache) Get(sha string) (*skillcheck.Verdict, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[sha]
	if !ok || time.Now().After(e.ExpiresAt) {
		return nil, false
	}
	return e.Verdict, true
}

// Put stores a verdict under the given SHA256 key with the configured DefaultTTL.
func (c *Cache) Put(sha string, v *skillcheck.Verdict) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[sha] = entry{Verdict: v, ExpiresAt: time.Now().Add(c.cfg.DefaultTTL)}
}

// Flush writes non-expired entries to disk atomically via tmp+rename.
func (c *Cache) Flush() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	tmp := c.path + ".tmp"
	data, err := json.Marshal(c.entries)
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write cache tmp: %w", err)
	}
	if err := os.Rename(tmp, c.path); err != nil {
		return fmt.Errorf("rename cache: %w", err)
	}
	return nil
}

// load reads the cache file and populates the in-memory map.
// Called during New before the cache is shared; no mutex needed.
func (c *Cache) load() error {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &c.entries)
}
