package windows

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// NATEntry tracks a redirected connection's original destination.
type NATEntry struct {
	OriginalDstIP   net.IP
	OriginalDstPort uint16
	Protocol        string // "tcp" or "udp"
	ProcessID       uint32
	CreatedAt       time.Time

	// Redirect fields for connect-level redirect support
	RedirectTo  string // "host:port" if redirect matched, empty otherwise
	RedirectTLS string // "passthrough" or "rewrite_sni"
	RedirectSNI string // SNI to use if rewrite_sni mode
}

// IsRedirected returns true if this entry has a redirect destination.
func (e *NATEntry) IsRedirected() bool {
	return e.RedirectTo != ""
}

// GetConnectTarget returns the destination to connect to (redirect or original).
func (e *NATEntry) GetConnectTarget() string {
	if e.RedirectTo != "" {
		return e.RedirectTo
	}
	return net.JoinHostPort(e.OriginalDstIP.String(), fmt.Sprintf("%d", e.OriginalDstPort))
}

// NATTable maps local proxy connections to original destinations.
// Key format: "srcIP:srcPort" (the redirected connection's local source)
type NATTable struct {
	mu      sync.RWMutex
	entries map[string]*NATEntry
	ttl     time.Duration
}

// NewNATTable creates a new NAT table with the given TTL for entries.
func NewNATTable(ttl time.Duration) *NATTable {
	return &NATTable{
		entries: make(map[string]*NATEntry),
		ttl:     ttl,
	}
}

// Insert adds or updates a NAT entry.
func (t *NATTable) Insert(key string, entry *NATEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}
	t.entries[key] = entry
}

// Lookup retrieves a NAT entry by key.
// Returns nil if not found or expired.
func (t *NATTable) Lookup(key string) *NATEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	entry, ok := t.entries[key]
	if !ok {
		return nil
	}

	// Check if expired
	if time.Since(entry.CreatedAt) > t.ttl {
		return nil
	}

	return entry
}

// Remove deletes a NAT entry.
func (t *NATTable) Remove(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// RemoveByPID removes all entries for a given process ID.
// Returns the number of entries removed.
func (t *NATTable) RemoveByPID(pid uint32) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	removed := 0
	for key, entry := range t.entries {
		if entry.ProcessID == pid {
			delete(t.entries, key)
			removed++
		}
	}
	return removed
}

// Cleanup removes all expired entries.
func (t *NATTable) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for key, entry := range t.entries {
		if now.Sub(entry.CreatedAt) > t.ttl {
			delete(t.entries, key)
		}
	}
}

// Len returns the number of entries in the table.
func (t *NATTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}
