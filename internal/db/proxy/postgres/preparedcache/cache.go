//go:build linux

// Package preparedcache is a per-connection LRU prepared-statement cache used
// by the PostgreSQL proxy. Plan 05a uses it for the wire-protocol Extended
// Query cache; Plan 05b adds a second instance per connection for SQL-level
// PREPARE/EXECUTE.
//
// The default capacity is 4096 entries per spec §7.4.
package preparedcache

import (
	"container/list"
	"sync"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

const DefaultCapacity = 4096

// Entry is the cached value: the classified statement plus the redaction
// tier captured at Parse time so a later Execute renders consistently even
// if policy is hot-swapped between Parse and Execute.
type Entry struct {
	Classification           effects.ClassifiedStatement
	RedactionTier            policy.RedactionTier
	CatalogRefreshSearchPath bool
	CatalogRefreshSnapshot   bool
}

// Cache is a fixed-capacity LRU keyed by prepared-statement name. Empty name
// is a legal key per §7.4 (unnamed prepared statement).
type Cache struct {
	mu    sync.Mutex
	cap   int
	order *list.List // front=MRU, back=LRU
	byKey map[string]*list.Element
}

type cacheItem struct {
	key   string
	value Entry
}

// New returns a Cache with the given capacity. capacity <= 0 falls back to
// DefaultCapacity.
func New(capacity int) *Cache {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Cache{
		cap:   capacity,
		order: list.New(),
		byKey: make(map[string]*list.Element, capacity),
	}
}

// Put inserts or updates name -> e. Existing entries are promoted to MRU.
// At capacity, the LRU entry is evicted.
func (c *Cache) Put(name string, e Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byKey[name]; ok {
		el.Value.(*cacheItem).value = e
		c.order.MoveToFront(el)
		return
	}
	el := c.order.PushFront(&cacheItem{key: name, value: e})
	c.byKey[name] = el
	if c.order.Len() > c.cap {
		oldest := c.order.Back()
		if oldest != nil {
			ci := oldest.Value.(*cacheItem)
			c.order.Remove(oldest)
			delete(c.byKey, ci.key)
		}
	}
}

// Get returns the cached entry and promotes it to MRU. Second return is
// false on miss.
func (c *Cache) Get(name string) (Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byKey[name]
	if !ok {
		return Entry{}, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*cacheItem).value, true
}

// Delete removes name if present. No-op on miss.
func (c *Cache) Delete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byKey[name]
	if !ok {
		return
	}
	c.order.Remove(el)
	delete(c.byKey, name)
}

// Clear empties the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.order.Init()
	c.byKey = make(map[string]*list.Element, c.cap)
}

// Len returns the current entry count.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
