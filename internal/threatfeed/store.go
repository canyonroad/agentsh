package threatfeed

import (
	"encoding/gob"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// FeedEntry records which feed flagged a domain and when.
type FeedEntry struct {
	FeedName      string
	AddedAt       time.Time
	MatchedDomain string // set by Check() — the actual domain that matched
}

// Store is a thread-safe in-memory set of blocked domains with disk persistence.
type Store struct {
	mu        sync.RWMutex
	domains   map[string]FeedEntry
	allowlist map[string]struct{}
	cacheDir  string
}

// NewStore creates a new threat feed store.
func NewStore(cacheDir string, allowlist []string) *Store {
	al := make(map[string]struct{}, len(allowlist))
	for _, d := range allowlist {
		d = strings.ToLower(strings.TrimRight(strings.TrimSpace(d), "."))
		if d != "" {
			al[d] = struct{}{}
		}
	}
	return &Store{
		domains:   make(map[string]FeedEntry),
		allowlist: al,
		cacheDir:  cacheDir,
	}
}

// Check returns the matching FeedEntry if the domain (or a parent domain) is in
// the threat feed store and not in the allowlist.
func (s *Store) Check(domain string) (FeedEntry, bool) {
	domain = strings.ToLower(strings.TrimRight(strings.TrimSpace(domain), "."))
	if domain == "" {
		return FeedEntry{}, false
	}

	if _, ok := s.allowlist[domain]; ok {
		return FeedEntry{}, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if entry, ok := s.domains[domain]; ok {
		entry.MatchedDomain = domain
		return entry, true
	}

	d := domain
	for {
		idx := strings.Index(d, ".")
		if idx < 0 {
			break
		}
		d = d[idx+1:]
		if d == "" {
			break
		}
		if !strings.Contains(d, ".") {
			break
		}
		if _, ok := s.allowlist[d]; ok {
			return FeedEntry{}, false
		}
		if entry, ok := s.domains[d]; ok {
			entry.MatchedDomain = d
			return entry, true
		}
	}

	return FeedEntry{}, false
}

// Update atomically replaces the entire domain set.
func (s *Store) Update(domains map[string]FeedEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domains = domains
}

// Size returns the number of domains in the store.
func (s *Store) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.domains)
}

// Snapshot returns a copy of the current domain map grouped by feed name.
func (s *Store) Snapshot() map[string][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grouped := make(map[string][]string)
	for domain, entry := range s.domains {
		grouped[entry.FeedName] = append(grouped[entry.FeedName], domain)
	}
	return grouped
}

type diskCache struct {
	Domains map[string]FeedEntry
}

const cacheFileName = "feeds.cache"

// SaveToDisk persists the current domain set to a gob-encoded file.
func (s *Store) SaveToDisk() error {
	if s.cacheDir == "" {
		return nil
	}
	if err := os.MkdirAll(s.cacheDir, 0o755); err != nil {
		return err
	}

	s.mu.RLock()
	cache := diskCache{Domains: s.domains}
	s.mu.RUnlock()

	path := filepath.Join(s.cacheDir, cacheFileName)
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := gob.NewEncoder(f).Encode(&cache); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// On Windows, os.Rename fails if the destination exists. Remove it first.
	if runtime.GOOS == "windows" {
		os.Remove(path)
	}
	return os.Rename(tmp, path)
}

// LoadFromDisk loads a previously persisted domain set from disk.
func (s *Store) LoadFromDisk() error {
	if s.cacheDir == "" {
		return nil
	}
	path := filepath.Join(s.cacheDir, cacheFileName)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	var cache diskCache
	if err := gob.NewDecoder(f).Decode(&cache); err != nil {
		return err
	}
	s.mu.Lock()
	s.domains = cache.Domains
	s.mu.Unlock()
	return nil
}
