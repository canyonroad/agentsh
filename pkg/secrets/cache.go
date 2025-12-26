package secrets

import (
	"sync"
	"time"
)

// secretCache provides caching for secrets.
type secretCache struct {
	ttl     time.Duration
	entries map[string]*cacheEntry
	mu      sync.RWMutex
}

type cacheEntry struct {
	secret    *Secret
	expiresAt time.Time
}

// newSecretCache creates a new secret cache.
func newSecretCache(ttl time.Duration) *secretCache {
	c := &secretCache{
		ttl:     ttl,
		entries: make(map[string]*cacheEntry),
	}

	// Start cleanup goroutine
	go c.cleanupLoop()

	return c
}

// get retrieves a secret from the cache.
func (c *secretCache) get(provider, path string) *Secret {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.key(provider, path)
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry.secret
}

// set stores a secret in the cache.
func (c *secretCache) set(provider, path string, secret *Secret) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.key(provider, path)
	c.entries[key] = &cacheEntry{
		secret:    secret,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// delete removes a secret from the cache.
func (c *secretCache) delete(provider, path string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.key(provider, path)
	delete(c.entries, key)
}

// clear removes all entries from the cache.
func (c *secretCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheEntry)
}

// size returns the number of entries in the cache.
func (c *secretCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// key generates a cache key for a provider and path.
func (c *secretCache) key(provider, path string) string {
	return provider + ":" + path
}

// cleanupLoop periodically removes expired entries.
func (c *secretCache) cleanupLoop() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

// cleanup removes expired entries.
func (c *secretCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}
