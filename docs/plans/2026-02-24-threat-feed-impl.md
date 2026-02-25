# Threat Intelligence Feed Integration — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a threat intelligence feed system that blocks agent connections to known-malicious domains by integrating with the existing policy engine.

**Architecture:** New `internal/threatfeed/` package with three components: `Store` (in-memory hash set + gob disk cache), `Syncer` (background goroutine fetching feeds), and `Parser` (hostfile + domain-list formats). The store is created in `server.New()`, passed to `policy.Engine` via a setter method, and checked as a pre-step in `CheckNetworkCtx()` before existing `network_rules`. The syncer goroutine starts in `server.Run()` alongside existing goroutines.

**Tech Stack:** Go stdlib (`sync`, `net/http`, `encoding/gob`, `time`), `github.com/stretchr/testify`, `net/http/httptest`

---

## Context

The policy engine (`internal/policy/engine.go`) evaluates network rules in `CheckNetworkCtx()` (line 695) using first-match-wins semantics against compiled domain globs and CIDRs. The proxy (`internal/netmonitor/proxy.go`) calls `checkNetwork()` (line 330) which delegates to the engine. Events are emitted as `net_connect` with `Fields map[string]any` and `Policy *PolicyInfo`.

The server (`internal/server/server.go`) creates the policy engine in `New()` (line 99) and starts goroutines in `Run()` (line 599) using an `errCh` channel pattern. Config is defined in `internal/config/config.go` with the top-level `Config` struct (line 13).

This plan adds threat feed checking as a transparent pre-step inside the engine — no changes to the proxy, events, or report packages.

---

### Task 1: Add config structs for threat feeds

Add `ThreatFeedsConfig` and related types to the config package, and wire the new field into the top-level `Config` struct.

**Files:**
- Create: `internal/config/threatfeeds.go`
- Modify: `internal/config/config.go:13-33` (add field to Config struct)
- Modify: `internal/config/config.go:799` (wire defaults in `applyDefaultsWithSource`)

**Step 1: Create the config types**

Create `internal/config/threatfeeds.go`:

```go
package config

import "time"

// ThreatFeedsConfig configures external threat intelligence feed integration.
type ThreatFeedsConfig struct {
	Enabled      bool              `yaml:"enabled"`
	Action       string            `yaml:"action"`
	Feeds        []ThreatFeedEntry `yaml:"feeds"`
	LocalLists   []string          `yaml:"local_lists"`
	Allowlist    []string          `yaml:"allowlist"`
	SyncInterval time.Duration     `yaml:"sync_interval"`
	CacheDir     string            `yaml:"cache_dir"`
	Realtime     RealtimeConfig    `yaml:"realtime"`
}

// ThreatFeedEntry defines a single remote threat feed.
type ThreatFeedEntry struct {
	Name   string `yaml:"name"`
	URL    string `yaml:"url"`
	Format string `yaml:"format"` // "hostfile" or "domain-list"
}

// RealtimeConfig defines the paid real-time API tier (reserved, not implemented in v1).
type RealtimeConfig struct {
	Provider  string        `yaml:"provider"`
	APIKey    string        `yaml:"api_key"`
	Timeout   time.Duration `yaml:"timeout"`
	CacheTTL  time.Duration `yaml:"cache_ttl"`
	OnTimeout string        `yaml:"on_timeout"`
}
```

**Step 2: Add field to Config struct**

In `internal/config/config.go`, add `ThreatFeeds` to the `Config` struct (after line 32, before the closing brace):

```go
ThreatFeeds       ThreatFeedsConfig       `yaml:"threat_feeds"`
```

**Step 3: Wire defaults in `applyDefaultsWithSource`**

In `internal/config/config.go`, add after existing defaults in `applyDefaultsWithSource()`:

```go
if cfg.ThreatFeeds.Action == "" {
	cfg.ThreatFeeds.Action = "deny"
}
if cfg.ThreatFeeds.SyncInterval == 0 {
	cfg.ThreatFeeds.SyncInterval = 6 * time.Hour
}
if cfg.ThreatFeeds.Realtime.Timeout == 0 {
	cfg.ThreatFeeds.Realtime.Timeout = 500 * time.Millisecond
}
if cfg.ThreatFeeds.Realtime.CacheTTL == 0 {
	cfg.ThreatFeeds.Realtime.CacheTTL = 1 * time.Hour
}
if cfg.ThreatFeeds.Realtime.OnTimeout == "" {
	cfg.ThreatFeeds.Realtime.OnTimeout = "local-only"
}
```

**Step 4: Verify build**

Run: `go build ./...`
Expected: clean build

**Step 5: Commit**

```
feat(config): add ThreatFeedsConfig for threat intelligence feeds
```

---

### Task 2: Implement parsers with tests

Create the `Parser` interface and two implementations: `HostfileParser` and `DomainListParser`.

**Files:**
- Create: `internal/threatfeed/parser.go`
- Create: `internal/threatfeed/parser_test.go`

**Step 1: Write the failing tests**

Create `internal/threatfeed/parser_test.go`:

```go
package threatfeed

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostfileParser_Standard(t *testing.T) {
	input := `# comment line
127.0.0.1 localhost
0.0.0.0 malware.example.com
127.0.0.1 phishing.bad.org  # trailing comment
`
	p := &HostfileParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"malware.example.com", "phishing.bad.org"}, domains)
}

func TestHostfileParser_SkipsLocalhost(t *testing.T) {
	input := "127.0.0.1 localhost\n0.0.0.0 localhost\n0.0.0.0 evil.com\n"
	p := &HostfileParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, []string{"evil.com"}, domains)
}

func TestHostfileParser_Deduplicates(t *testing.T) {
	input := "0.0.0.0 evil.com\n127.0.0.1 evil.com\n0.0.0.0 EVIL.COM\n"
	p := &HostfileParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, []string{"evil.com"}, domains)
}

func TestHostfileParser_EmptyInput(t *testing.T) {
	p := &HostfileParser{}
	domains, err := p.Parse(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, domains)
}

func TestHostfileParser_CommentsOnly(t *testing.T) {
	input := "# This is a comment\n# Another comment\n"
	p := &HostfileParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Empty(t, domains)
}

func TestDomainListParser_Standard(t *testing.T) {
	input := `# Phishing domains
evil.com
bad.org

UPPER.NET
`
	p := &DomainListParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, []string{"evil.com", "bad.org", "upper.net"}, domains)
}

func TestDomainListParser_Deduplicates(t *testing.T) {
	input := "evil.com\nevil.com\nEVIL.COM\n"
	p := &DomainListParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, []string{"evil.com"}, domains)
}

func TestDomainListParser_EmptyInput(t *testing.T) {
	p := &DomainListParser{}
	domains, err := p.Parse(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, domains)
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/threatfeed/ -v`
Expected: compilation failure — package doesn't exist yet

**Step 3: Implement the parsers**

Create `internal/threatfeed/parser.go`:

```go
package threatfeed

import (
	"bufio"
	"io"
	"sort"
	"strings"
)

// Parser extracts domain names from a threat feed format.
type Parser interface {
	Parse(r io.Reader) ([]string, error)
}

// HostfileParser parses hosts-file format: "127.0.0.1 domain" or "0.0.0.0 domain".
type HostfileParser struct{}

func (p *HostfileParser) Parse(r io.Reader) ([]string, error) {
	seen := make(map[string]struct{})
	var domains []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip trailing comments.
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		domain := strings.ToLower(fields[1])
		if domain == "localhost" || domain == "localhost.localdomain" ||
			domain == "broadcasthost" || domain == "local" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	return domains, scanner.Err()
}

// DomainListParser parses one-domain-per-line format.
type DomainListParser struct{}

func (p *DomainListParser) Parse(r io.Reader) ([]string, error) {
	seen := make(map[string]struct{})
	var domains []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain := strings.ToLower(line)
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	return domains, scanner.Err()
}

// ParserForFormat returns the appropriate parser for a feed format string.
func ParserForFormat(format string) Parser {
	switch strings.ToLower(format) {
	case "hostfile":
		return &HostfileParser{}
	case "domain-list":
		return &DomainListParser{}
	default:
		return &DomainListParser{}
	}
}

// dedupSorted returns a sorted, deduplicated copy of the input.
func dedupSorted(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}
	sort.Strings(domains)
	result := domains[:1]
	for _, d := range domains[1:] {
		if d != result[len(result)-1] {
			result = append(result, d)
		}
	}
	return result
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/threatfeed/ -v`
Expected: all PASS

**Step 5: Commit**

```
feat(threatfeed): add hostfile and domain-list parsers
```

---

### Task 3: Implement the store with tests

Create the thread-safe in-memory domain store with disk cache persistence.

**Files:**
- Create: `internal/threatfeed/store.go`
- Create: `internal/threatfeed/store_test.go`

**Step 1: Write the failing tests**

Create `internal/threatfeed/store_test.go`:

```go
package threatfeed

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_ExactMatch(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	entry, matched := s.Check("evil.com")
	assert.True(t, matched)
	assert.Equal(t, "urlhaus", entry.FeedName)
}

func TestStore_NoMatch(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	_, matched := s.Check("safe.com")
	assert.False(t, matched)
}

func TestStore_ParentDomainMatch(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	entry, matched := s.Check("sub.evil.com")
	assert.True(t, matched)
	assert.Equal(t, "evil.com", entry.MatchedDomain)
}

func TestStore_DeepSubdomainMatch(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	entry, matched := s.Check("a.b.c.evil.com")
	assert.True(t, matched)
	assert.Equal(t, "evil.com", entry.MatchedDomain)
}

func TestStore_AllowlistOverride(t *testing.T) {
	s := NewStore("", []string{"legit.evil.com"})
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	_, matched := s.Check("legit.evil.com")
	assert.False(t, matched, "allowlisted domain should not match")

	// Non-allowlisted subdomain still matches via parent.
	_, matched = s.Check("other.evil.com")
	assert.True(t, matched)
}

func TestStore_CaseInsensitive(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	_, matched := s.Check("EVIL.COM")
	assert.True(t, matched)
}

func TestStore_EmptyStore(t *testing.T) {
	s := NewStore("", nil)
	_, matched := s.Check("anything.com")
	assert.False(t, matched)
}

func TestStore_AtomicUpdate(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"old.com": {FeedName: "feed1", AddedAt: time.Now()},
	})
	s.Update(map[string]FeedEntry{
		"new.com": {FeedName: "feed2", AddedAt: time.Now()},
	})
	_, matched := s.Check("old.com")
	assert.False(t, matched, "old entries should be gone after update")
	_, matched = s.Check("new.com")
	assert.True(t, matched)
}

func TestStore_ConcurrentAccess(t *testing.T) {
	s := NewStore("", nil)
	s.Update(map[string]FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			s.Check("evil.com")
		}()
		go func() {
			defer wg.Done()
			s.Update(map[string]FeedEntry{
				"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
			})
		}()
	}
	wg.Wait()
}

func TestStore_DiskRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s1 := NewStore(dir, []string{"safe.com"})
	s1.Update(map[string]FeedEntry{
		"evil.com":    {FeedName: "urlhaus", AddedAt: time.Now()},
		"phishing.io": {FeedName: "phishdb", AddedAt: time.Now()},
	})
	err := s1.SaveToDisk()
	require.NoError(t, err)

	// Verify cache file exists.
	_, err = os.Stat(filepath.Join(dir, "feeds.cache"))
	require.NoError(t, err)

	// Load into fresh store.
	s2 := NewStore(dir, []string{"safe.com"})
	err = s2.LoadFromDisk()
	require.NoError(t, err)

	entry, matched := s2.Check("evil.com")
	assert.True(t, matched)
	assert.Equal(t, "urlhaus", entry.FeedName)

	entry, matched = s2.Check("phishing.io")
	assert.True(t, matched)
	assert.Equal(t, "phishdb", entry.FeedName)
}

func TestStore_LoadFromDisk_NoFile(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, nil)
	err := s.LoadFromDisk()
	assert.NoError(t, err, "missing cache file should not be an error")
}

func TestStore_Size(t *testing.T) {
	s := NewStore("", nil)
	assert.Equal(t, 0, s.Size())
	s.Update(map[string]FeedEntry{
		"a.com": {FeedName: "f1", AddedAt: time.Now()},
		"b.com": {FeedName: "f2", AddedAt: time.Now()},
	})
	assert.Equal(t, 2, s.Size())
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/threatfeed/ -v -run TestStore`
Expected: compilation failure — `Store`, `FeedEntry`, `NewStore` not defined

**Step 3: Implement the store**

Create `internal/threatfeed/store.go`:

```go
package threatfeed

import (
	"encoding/gob"
	"os"
	"path/filepath"
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
// cacheDir is the directory for disk persistence (empty string disables persistence).
// allowlist is a list of domains that should never be blocked.
func NewStore(cacheDir string, allowlist []string) *Store {
	al := make(map[string]struct{}, len(allowlist))
	for _, d := range allowlist {
		al[strings.ToLower(d)] = struct{}{}
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
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return FeedEntry{}, false
	}

	// Check allowlist first (exact match).
	if _, ok := s.allowlist[domain]; ok {
		return FeedEntry{}, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Exact match.
	if entry, ok := s.domains[domain]; ok {
		entry.MatchedDomain = domain
		return entry, true
	}

	// Walk parent domains: sub.evil.com → evil.com → com
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
		// Don't match bare TLDs.
		if !strings.Contains(d, ".") {
			break
		}
		if _, ok := s.allowlist[domain]; ok {
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

// diskCache is the serializable form persisted to disk.
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
	return os.Rename(tmp, path)
}

// LoadFromDisk loads a previously persisted domain set from disk.
// Returns nil if the cache file does not exist.
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
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/threatfeed/ -v -run TestStore -race`
Expected: all PASS (the `-race` flag validates concurrent access safety)

**Step 5: Commit**

```
feat(threatfeed): add thread-safe domain store with disk cache
```

---

### Task 4: Implement the syncer with tests

Create the background syncer that periodically downloads feeds and updates the store.

**Files:**
- Create: `internal/threatfeed/syncer.go`
- Create: `internal/threatfeed/syncer_test.go`

**Step 1: Write the failing tests**

Create `internal/threatfeed/syncer_test.go`:

```go
package threatfeed

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentsh/agentsh/internal/config"
)

func TestSyncer_FetchesAndPopulatesStore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "0.0.0.0 evil.com")
		fmt.Fprintln(w, "0.0.0.0 bad.org")
	}))
	defer srv.Close()

	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "test-feed", URL: srv.URL, Format: "hostfile"},
		},
		SyncInterval: time.Hour, // won't tick in this test
	}
	syncer := NewSyncer(store, cfg, nil)
	syncer.syncAll()

	assert.Equal(t, 2, store.Size())
	_, matched := store.Check("evil.com")
	assert.True(t, matched)
	_, matched = store.Check("bad.org")
	assert.True(t, matched)
}

func TestSyncer_DomainListFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "# comment")
		fmt.Fprintln(w, "phish.net")
	}))
	defer srv.Close()

	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "phish", URL: srv.URL, Format: "domain-list"},
		},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)
	syncer.syncAll()

	_, matched := store.Check("phish.net")
	assert.True(t, matched)
}

func TestSyncer_MergesMultipleFeeds(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "0.0.0.0 evil.com")
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "phish.net")
	}))
	defer srv2.Close()

	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "feed1", URL: srv1.URL, Format: "hostfile"},
			{Name: "feed2", URL: srv2.URL, Format: "domain-list"},
		},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)
	syncer.syncAll()

	assert.Equal(t, 2, store.Size())
}

func TestSyncer_FetchFailureKeepsPreviousData(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			fmt.Fprintln(w, "0.0.0.0 evil.com")
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "flaky", URL: srv.URL, Format: "hostfile"},
		},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)

	syncer.syncAll()
	assert.Equal(t, 1, store.Size())

	// Second sync fails — store should keep previous data.
	syncer.syncAll()
	assert.Equal(t, 1, store.Size())
	_, matched := store.Check("evil.com")
	assert.True(t, matched)
}

func TestSyncer_LocalListFile(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "custom.txt")
	err := os.WriteFile(listPath, []byte("custom-bad.com\n"), 0o644)
	require.NoError(t, err)

	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		LocalLists:   []string{listPath},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)
	syncer.syncAll()

	_, matched := store.Check("custom-bad.com")
	assert.True(t, matched)
}

func TestSyncer_RunRespectsContextCancellation(t *testing.T) {
	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		syncer.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("syncer did not stop after context cancellation")
	}
}

func TestSyncer_SavesToDiskOnShutdown(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "0.0.0.0 evil.com")
	}))
	defer srv.Close()

	store := NewStore(dir, nil)
	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "test", URL: srv.URL, Format: "hostfile"},
		},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		syncer.Run(ctx)
		close(done)
	}()

	// Wait for initial sync, then cancel.
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	// Verify disk cache was written.
	_, err := os.Stat(filepath.Join(dir, "feeds.cache"))
	assert.NoError(t, err)
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/threatfeed/ -v -run TestSyncer`
Expected: compilation failure — `Syncer`, `NewSyncer` not defined

**Step 3: Implement the syncer**

Create `internal/threatfeed/syncer.go`:

```go
package threatfeed

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/agentsh/agentsh/internal/config"
)

// Syncer periodically downloads threat feeds and updates the store.
type Syncer struct {
	store    *Store
	feeds    []config.ThreatFeedEntry
	locals   []string
	interval time.Duration
	client   *http.Client
	logger   *slog.Logger
	etags    map[string]string // feed URL → last ETag
}

// NewSyncer creates a new feed syncer. Pass nil for logger to disable logging.
func NewSyncer(store *Store, cfg config.ThreatFeedsConfig, logger *slog.Logger) *Syncer {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Syncer{
		store:    store,
		feeds:    cfg.Feeds,
		locals:   cfg.LocalLists,
		interval: cfg.SyncInterval,
		client:   &http.Client{Timeout: 30 * time.Second},
		logger:   logger,
		etags:    make(map[string]string),
	}
}

// Run starts the periodic sync loop. It blocks until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	s.syncAll()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.store.SaveToDisk()
			return
		case <-ticker.C:
			s.syncAll()
		}
	}
}

// syncAll fetches all feeds and local lists, merges results, and updates the store.
func (s *Syncer) syncAll() {
	merged := make(map[string]FeedEntry)
	allFailed := true

	for _, feed := range s.feeds {
		domains, err := s.fetchFeed(feed)
		if err != nil {
			s.logger.Warn("threat feed fetch failed",
				"feed", feed.Name, "url", feed.URL, "error", err)
			continue
		}
		allFailed = false
		now := time.Now()
		for _, d := range domains {
			if _, exists := merged[d]; !exists {
				merged[d] = FeedEntry{FeedName: feed.Name, AddedAt: now}
			}
		}
		s.logger.Info("threat feed synced",
			"feed", feed.Name, "domains", len(domains))
	}

	for _, path := range s.locals {
		domains, err := s.parseLocalFile(path)
		if err != nil {
			s.logger.Warn("local threat list failed",
				"path", path, "error", err)
			continue
		}
		allFailed = false
		now := time.Now()
		for _, d := range domains {
			if _, exists := merged[d]; !exists {
				merged[d] = FeedEntry{FeedName: "local:" + path, AddedAt: now}
			}
		}
	}

	// Only update if at least one source succeeded, to avoid wiping the store
	// when all sources are temporarily down.
	if !allFailed || (len(s.feeds) == 0 && len(s.locals) == 0) {
		s.store.Update(merged)
		s.store.SaveToDisk()
	}
}

func (s *Syncer) fetchFeed(feed config.ThreatFeedEntry) ([]string, error) {
	req, err := http.NewRequest("GET", feed.URL, nil)
	if err != nil {
		return nil, err
	}
	if etag, ok := s.etags[feed.URL]; ok {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, nil // no changes
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if etag := resp.Header.Get("ETag"); etag != "" {
		s.etags[feed.URL] = etag
	}

	parser := ParserForFormat(feed.Format)
	return parser.Parse(resp.Body)
}

func (s *Syncer) parseLocalFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	p := &DomainListParser{}
	return p.Parse(f)
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/threatfeed/ -v -run TestSyncer -race`
Expected: all PASS

**Step 5: Commit**

```
feat(threatfeed): add background syncer with periodic feed refresh
```

---

### Task 5: Integrate threat store into the policy engine

Add the threat feed pre-check to `CheckNetworkCtx()` using a setter method on Engine.

**Files:**
- Modify: `internal/policy/engine.go:17-37` (add fields to Engine struct)
- Modify: `internal/policy/engine.go:695-769` (add pre-check in CheckNetworkCtx)
- Create: `internal/policy/engine_threat_test.go`

**Step 1: Write the failing tests**

Create `internal/policy/engine_threat_test.go`:

```go
package policy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentsh/agentsh/internal/threatfeed"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestCheckNetworkCtx_ThreatFeedDeny(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "allow-all", Domains: []string{"*"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	store := threatfeed.NewStore("", nil)
	store.Update(map[string]threatfeed.FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	e.SetThreatStore(store, "deny")

	dec := e.CheckNetworkCtx(context.Background(), "evil.com", 443)
	assert.Equal(t, types.DecisionDeny, dec.EffectiveDecision)
	assert.Equal(t, "threat-feed:urlhaus", dec.Rule)
}

func TestCheckNetworkCtx_ThreatFeedAudit(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "allow-all", Domains: []string{"*"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	store := threatfeed.NewStore("", nil)
	store.Update(map[string]threatfeed.FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	e.SetThreatStore(store, "audit")

	dec := e.CheckNetworkCtx(context.Background(), "evil.com", 443)
	assert.Equal(t, types.DecisionAudit, dec.PolicyDecision)
	// Audit = allow effective (log but don't block).
	assert.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	assert.Equal(t, "threat-feed:urlhaus", dec.Rule)
}

func TestCheckNetworkCtx_ThreatFeedNoMatchFallsThrough(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "deny-bad", Domains: []string{"bad.org"}, Decision: "deny"},
		{Name: "allow-all", Domains: []string{"*"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	store := threatfeed.NewStore("", nil)
	store.Update(map[string]threatfeed.FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	e.SetThreatStore(store, "deny")

	// safe.com not in threat feed → falls through to network_rules → allow-all.
	dec := e.CheckNetworkCtx(context.Background(), "safe.com", 443)
	assert.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	assert.Equal(t, "allow-all", dec.Rule)
}

func TestCheckNetworkCtx_NilThreatStoreSkipsCheck(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "allow-all", Domains: []string{"*"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)
	// No SetThreatStore call — threatStore is nil.

	dec := e.CheckNetworkCtx(context.Background(), "evil.com", 443)
	assert.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	assert.Equal(t, "allow-all", dec.Rule)
}

func TestCheckNetworkCtx_ThreatFeedParentDomainMatch(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "allow-all", Domains: []string{"*"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	store := threatfeed.NewStore("", nil)
	store.Update(map[string]threatfeed.FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	e.SetThreatStore(store, "deny")

	dec := e.CheckNetworkCtx(context.Background(), "sub.evil.com", 443)
	assert.Equal(t, types.DecisionDeny, dec.EffectiveDecision)
	assert.Equal(t, "threat-feed:urlhaus", dec.Rule)
	assert.Contains(t, dec.Message, "evil.com")
}

func TestCheckNetworkCtx_ThreatFeedFields(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "allow-all", Domains: []string{"*"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	store := threatfeed.NewStore("", nil)
	store.Update(map[string]threatfeed.FeedEntry{
		"evil.com": {FeedName: "urlhaus", AddedAt: time.Now()},
	})
	e.SetThreatStore(store, "deny")

	dec := e.CheckNetworkCtx(context.Background(), "sub.evil.com", 443)
	assert.Equal(t, "urlhaus", dec.ThreatFeed)
	assert.Equal(t, "evil.com", dec.ThreatMatch)
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/ -v -run TestCheckNetworkCtx_Threat`
Expected: compilation failure — `SetThreatStore`, `ThreatFeed`, `ThreatMatch` not defined

**Step 3: Add threat fields to Decision and Engine structs**

In `internal/policy/engine.go`, add fields to the `Engine` struct (after line 36):

```go
// Threat intelligence feed store (optional).
threatStore  *threatfeed.Store
threatAction string // "deny" or "audit"
```

Add import for `"github.com/agentsh/agentsh/internal/threatfeed"` at the top.

Add the `SetThreatStore` method after `NewEngine`:

```go
// SetThreatStore configures an optional threat feed store for domain checking.
// action should be "deny" or "audit".
func (e *Engine) SetThreatStore(store *threatfeed.Store, action string) {
	e.threatStore = store
	e.threatAction = action
}
```

Add fields to the `Decision` struct (after line 104):

```go
ThreatFeed  string // feed name that matched (empty if not a threat feed decision)
ThreatMatch string // the actual domain that matched in the feed
```

**Step 4: Add the pre-check in CheckNetworkCtx**

In `internal/policy/engine.go`, insert the threat feed check at line 697, after the domain normalization and before the lazy DNS resolver:

```go
// Threat feed pre-check: block known-malicious domains before evaluating rules.
if e.threatStore != nil {
	if entry, matched := e.threatStore.Check(domain); matched {
		dec := e.wrapDecision(e.threatAction, "threat-feed:"+entry.FeedName,
			"domain matched threat feed: "+entry.FeedName+" (matched: "+entry.MatchedDomain+")", nil)
		dec.ThreatFeed = entry.FeedName
		dec.ThreatMatch = entry.MatchedDomain
		return dec
	}
}
```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/policy/ -v -run TestCheckNetworkCtx_Threat -race`
Expected: all PASS

Also verify existing tests still pass:
Run: `go test ./internal/policy/ -race`
Expected: all PASS

**Step 6: Commit**

```
feat(policy): integrate threat feed store into CheckNetworkCtx
```

---

### Task 6: Wire threat feed into the server lifecycle

Create the store in `server.New()`, pass it to the engine, and start the syncer in `server.Run()`.

**Files:**
- Modify: `internal/server/server.go:44-65` (add fields to Server struct)
- Modify: `internal/server/server.go:87-102` (create store and configure engine in New)
- Modify: `internal/server/server.go:599-641` (start syncer goroutine in Run)
- Modify: `internal/server/server.go:643-672` (save to disk on shutdown)

**Step 1: Add fields to Server struct**

In `internal/server/server.go`, add after the existing fields (around line 63):

```go
threatSyncer *threatfeed.Syncer
threatStore  *threatfeed.Store
```

Add import for `"github.com/agentsh/agentsh/internal/threatfeed"`.

**Step 2: Create store and syncer in New()**

In `internal/server/server.go`, insert after the engine is created (after line 102, before `limits := engine.Limits()`):

```go
// Threat feed store (optional).
var threatStore *threatfeed.Store
var threatSyncer *threatfeed.Syncer
if cfg.ThreatFeeds.Enabled {
	cacheDir := cfg.ThreatFeeds.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(config.GetDataDir(), "threat-feeds")
	}
	threatStore = threatfeed.NewStore(cacheDir, cfg.ThreatFeeds.Allowlist)
	if err := threatStore.LoadFromDisk(); err != nil {
		slog.Warn("threat feed cache load failed", "error", err)
	} else if threatStore.Size() > 0 {
		slog.Info("threat feed loaded from cache", "domains", threatStore.Size())
	}
	engine.SetThreatStore(threatStore, cfg.ThreatFeeds.Action)
	threatSyncer = threatfeed.NewSyncer(threatStore, cfg.ThreatFeeds, slog.Default())
}
```

**Step 3: Store references on Server struct**

In the `srv := &Server{...}` block (around line 358), add:

```go
threatSyncer: threatSyncer,
threatStore:  threatStore,
```

**Step 4: Start syncer goroutine in Run()**

In `server.Run()`, insert after the session reaper goroutine (after line 619) and before `errCh`:

```go
// Start threat feed syncer.
if s.threatSyncer != nil {
	go s.threatSyncer.Run(ctx)
}
```

The syncer's `Run()` already respects `ctx.Done()` and calls `SaveToDisk()` on exit, so no additional shutdown logic is needed — context cancellation at line 644 propagates to the syncer.

**Step 5: Verify build**

Run: `go build ./...`
Expected: clean build

Run: `go test ./... -short`
Expected: all existing tests pass

**Step 6: Commit**

```
feat(server): wire threat feed store and syncer into server lifecycle
```

---

### Task 7: Define the Provider interface for future real-time tier

Define the interface and types for the paid real-time API tier. No implementation — just the contract.

**Files:**
- Create: `internal/threatfeed/provider.go`

**Step 1: Create the provider interface**

Create `internal/threatfeed/provider.go`:

```go
package threatfeed

import "context"

// Provider defines the interface for real-time domain threat checking.
// This is reserved for the paid tier (Web Risk API, VirusTotal, etc.)
// and is not implemented in v1.
type Provider interface {
	// Check queries the provider for a domain's threat status.
	Check(ctx context.Context, domain string) (ThreatResult, error)

	// Name returns the provider's identifier (e.g., "webrisk", "virustotal").
	Name() string
}

// ThreatResult holds the result of a real-time threat check.
type ThreatResult struct {
	Matched    bool
	FeedName   string
	ThreatType string // "malware", "phishing", "unwanted", etc.
}
```

**Step 2: Verify build**

Run: `go build ./...`
Expected: clean build

**Step 3: Commit**

```
feat(threatfeed): define Provider interface for future real-time tier
```

---

## Key Files Reference

| File | Role | Lines |
|------|------|-------|
| `internal/config/config.go` | Top-level Config struct | 13-33 (add field) |
| `internal/config/config.go` | Default wiring | ~799 (add defaults) |
| `internal/config/threatfeeds.go` | New: config types | — |
| `internal/threatfeed/parser.go` | New: feed parsers | — |
| `internal/threatfeed/store.go` | New: in-memory store + disk cache | — |
| `internal/threatfeed/syncer.go` | New: background sync goroutine | — |
| `internal/threatfeed/provider.go` | New: future real-time interface | — |
| `internal/policy/engine.go` | Engine struct | 17-37 (add fields) |
| `internal/policy/engine.go` | CheckNetworkCtx pre-check | 695-697 (insert) |
| `internal/policy/engine.go` | Decision struct | 96-105 (add fields) |
| `internal/server/server.go` | Server struct | 44-65 (add fields) |
| `internal/server/server.go` | New() — create store | 99-102 (insert after) |
| `internal/server/server.go` | Run() — start syncer | 619 (insert after) |

## Task Summary

| # | Task | Files | Depends On |
|---|------|-------|------------|
| 1 | Config structs | config/threatfeeds.go, config/config.go | — |
| 2 | Parsers | threatfeed/parser.go, parser_test.go | — |
| 3 | Store | threatfeed/store.go, store_test.go | — |
| 4 | Syncer | threatfeed/syncer.go, syncer_test.go | 1, 2, 3 |
| 5 | Policy engine integration | policy/engine.go, engine_threat_test.go | 3 |
| 6 | Server wiring | server/server.go | 1, 3, 4, 5 |
| 7 | Provider interface | threatfeed/provider.go | — |
