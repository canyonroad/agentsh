# Threat Intelligence Feed Integration — Design

**Date:** 2026-02-24
**Status:** Draft

## Overview

Add a threat intelligence feed system to agentsh that blocks connections to known-malicious domains. External feeds (URLhaus, phishing lists, custom blocklists) are synced periodically into an in-memory store and checked on every network connection via the existing policy engine.

**Use cases:**
- Block agent connections to known malware distribution, phishing, and C2 domains
- Audit-mode monitoring to discover if agents are reaching suspicious destinations
- Custom enterprise blocklists alongside public feeds
- Future paid tier: real-time API-based lookups (Google Web Risk, VirusTotal)

## Architecture

```
server.New()
├── threatfeed.NewStore(cacheDir, allowlist)
│   └── LoadFromDisk()              ← immediate protection from cache
├── policy.NewEngine(..., WithThreatStore(store))
└── server.Run()
    └── go syncer.Run(ctx)          ← background goroutine
        ├── syncAll()               ← immediate first fetch
        └── ticker loop             ← periodic refresh
            ├── fetch remote feeds
            ├── parse local lists
            ├── store.Update()      ← atomic swap
            └── store.SaveToDisk()

Network connection arrives:
    netmonitor.Proxy → policy.Engine.CheckNetworkCtx()
        1. threatStore.Check(domain)    ← NEW pre-check
        2. network_rules evaluation     ← existing, unchanged
        3. default deny                 ← existing, unchanged
```

**New package:** `internal/threatfeed/`
**Modified packages:** `internal/config/`, `internal/policy/`, `internal/server/`
**No changes to:** `internal/netmonitor/`, `internal/llmproxy/`, `internal/session/`

## Configuration

New `threat_feeds` section in server config (`internal/config/config.go`):

```yaml
threat_feeds:
  enabled: true
  action: deny                    # deny | audit
  feeds:
    - name: urlhaus
      url: https://urlhaus.abuse.ch/downloads/hostfile/
      format: hostfile            # hostfile | domain-list
    - name: phishing-database
      url: https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/active-domains.txt
      format: domain-list
  local_lists:
    - /etc/agentsh/custom-blocklist.txt
  allowlist:
    - legit-domain.example.com
  sync_interval: 6h
  cache_dir: ""                   # defaults to GetDataDir()/threat-feeds/
  realtime:                       # paid tier — not implemented in v1
    provider: ""                  # webrisk | virustotal
    api_key: ""
    timeout: 500ms
    cache_ttl: 1h
    on_timeout: local-only        # local-only | allow | deny
```

**Key decisions:**

- `action: deny` blocks connections; `action: audit` logs without blocking — lets users trial before enforcing
- `allowlist` overrides feed matches (false positive handling), evaluated before the feed check
- `sync_interval` defaults to 6h; the syncer fetches immediately on startup after loading disk cache
- `realtime` section is defined in the config struct but gated — returns an error if `provider` is set without a license, reserving the config shape for later
- `local_lists` are parsed on the same schedule as remote feeds using the same parser interface

## Components

### Store (`internal/threatfeed/store.go`)

Thread-safe in-memory hash set with disk persistence:

```go
type Store struct {
    mu        sync.RWMutex
    domains   map[string]FeedEntry  // domain → which feed flagged it
    allowlist map[string]struct{}
    cacheDir  string
}

type FeedEntry struct {
    FeedName string
    AddedAt  time.Time
}
```

**Methods:**

- `Check(domain string) (FeedEntry, bool)` — checks allowlist first, then the domain map. Also checks parent domains (e.g., `sub.evil.com` queries also check `evil.com`). Read-locked, zero allocation on the hot path.
- `Update(domains map[string]FeedEntry)` — atomic swap under write lock. Old map is dropped for GC.
- `LoadFromDisk() error` — loads gob-encoded cache from `cacheDir/feeds.cache`. Called synchronously during `server.New()` so protection is active before any sessions start.
- `SaveToDisk() error` — persists current state. Called after each sync and on graceful shutdown.

### Syncer (`internal/threatfeed/syncer.go`)

Background goroutine that downloads and parses feeds:

```go
type Syncer struct {
    store    *Store
    feeds    []FeedConfig
    locals   []string
    interval time.Duration
    client   *http.Client
    logger   *slog.Logger
}
```

**Lifecycle:**

```go
func (s *Syncer) Run(ctx context.Context) {
    s.syncAll()                    // immediate first fetch
    ticker := time.NewTicker(s.interval)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            s.store.SaveToDisk()   // persist before exit
            return
        case <-ticker.C:
            s.syncAll()
        }
    }
}
```

- `syncAll()` — iterates all remote feeds and local lists, merges results, calls `store.Update()` then `store.SaveToDisk()`
- `fetchFeed(feed FeedConfig) ([]string, error)` — downloads a single feed URL, passes body to the appropriate parser. Uses `If-Modified-Since` / `ETag` headers to skip re-downloading unchanged feeds.
- On any fetch error: logs a warning, keeps using previous data. Never clears the store because a single feed is temporarily unavailable.

### Parsers (`internal/threatfeed/parser.go`)

```go
type Parser interface {
    Parse(r io.Reader) ([]string, error)
}
```

Two implementations for v1:

- **`HostfileParser`** — skips comments (`#`), splits on whitespace, takes the second field (the domain), lowercases, deduplicates. Handles both `127.0.0.1` and `0.0.0.0` prefixes.
- **`DomainListParser`** — one domain per line, skips comments and blanks, lowercases, deduplicates.

### Provider Interface (`internal/threatfeed/provider.go`)

Defined for the future real-time paid tier:

```go
type Provider interface {
    Check(ctx context.Context, domain string) (ThreatResult, error)
    Name() string
}

type ThreatResult struct {
    Matched    bool
    FeedName   string
    ThreatType string   // malware, phishing, unwanted, etc.
}
```

Not implemented in v1 — serves as the extension point for Web Risk / VirusTotal integration.

## Policy Engine Integration

### Check Flow

The `Engine` struct gets a new optional field:

```go
type Engine struct {
    // ... existing fields
    threatStore  *threatfeed.Store
    threatAction string  // "deny" or "audit"
}
```

Set via `WithThreatStore(*threatfeed.Store)` and `WithThreatAction(string)` options at construction time. If `threatStore` is nil, the check is skipped entirely — all existing behavior is unchanged.

In `CheckNetworkCtx()`, the threat feed check inserts before the existing rule loop:

```go
func (e *Engine) CheckNetworkCtx(ctx context.Context, domain string, port int) Decision {
    // 1. Threat feed check (new)
    if e.threatStore != nil {
        if entry, matched := e.threatStore.Check(domain); matched {
            return Decision{
                PolicyDecision: e.threatAction,
                Rule:           "threat-feed:" + entry.FeedName,
                Message:        "domain matched threat feed: " + entry.FeedName,
                Fields: map[string]string{
                    "threat_feed":  entry.FeedName,
                    "threat_match": domain,
                },
            }
        }
    }

    // 2. Existing network_rules evaluation (unchanged)
    for _, rule := range e.networkRules {
        // ...
    }

    // 3. Default deny
}
```

### Event Data

No new event types needed. Blocked connections produce standard `net_connect` events with structured threat metadata in the `Fields` map:

```json
{
    "type": "net_connect",
    "domain": "sub.evil.example.com",
    "fields": {
        "threat_feed": "urlhaus",
        "threat_match": "evil.example.com"
    },
    "policy": {
        "decision": "deny",
        "rule": "threat-feed:urlhaus",
        "message": "domain matched threat feed: urlhaus"
    }
}
```

- `threat_feed` — which feed matched (e.g., `urlhaus`, `phishing-database`, or a custom list name)
- `threat_match` — the actual domain that matched, which may differ from the requested domain if a parent domain was matched

This means reports, `policygen`, event tailing, and webhooks all work with no changes — they already process `net_connect` events. The `threat-feed:` prefix in the rule name distinguishes these from user-defined network rules.

## Server Wiring

### Initialization (`server.New()`)

Created alongside the policy engine:

```go
var threatStore *threatfeed.Store
if cfg.ThreatFeeds.Enabled {
    cacheDir := cfg.ThreatFeeds.CacheDir
    if cacheDir == "" {
        cacheDir = filepath.Join(config.GetDataDir(), "threat-feeds")
    }
    threatStore = threatfeed.NewStore(cacheDir, cfg.ThreatFeeds.Allowlist)
    threatStore.LoadFromDisk()
}

engine, err := policy.NewEngine(p, enforceApprovals,
    policy.WithThreatStore(threatStore),
    policy.WithThreatAction(cfg.ThreatFeeds.Action),
)
```

### Goroutine Startup (`server.Run()`)

Starts alongside existing goroutines (session reaper, HTTP server):

```go
if cfg.ThreatFeeds.Enabled && threatStore != nil {
    syncer := threatfeed.NewSyncer(threatStore, cfg.ThreatFeeds, s.logger)
    s.wg.Add(1)
    go func() {
        defer s.wg.Done()
        syncer.Run(ctx)
    }()
}
```

### Shutdown

Context cancellation triggers `syncer.Run()` to exit the ticker loop and call `store.SaveToDisk()` before returning. The server's `sync.WaitGroup` ensures the save completes before process exit.

## Future: Real-Time API Tier

When implementing the paid `realtime` section, the check flow extends to:

```
1. Check local feed store          (always, ~microseconds)
2. Check API result cache          (always, ~microseconds)
3. Cache miss? → API lookup        (paid tier only, ~50-200ms)
4. Evaluate network_rules
5. Default deny
```

The `Provider` interface slots in here. Key design decisions for that phase:
- Configurable timeout with `on_timeout` fallback policy (`local-only`, `allow`, `deny`)
- Local LRU cache with configurable TTL to minimize API calls
- Agents hit the same domains repeatedly, so cache hit rate will be very high after startup

## Feed Licensing Notes

| Feed | License | Commercial OK |
|------|---------|---------------|
| URLhaus (abuse.ch) | CC0 (public domain) | Yes |
| Phishing.Database (mitchellkrogza) | MIT | Yes |
| StevenBlack/hosts | MIT | Yes |
| OpenPhish community | Free community feed | Yes |
| Google Safe Browsing | Restrictive ToS | No (use Web Risk API for commercial) |
| Google Web Risk API | Commercial GCP service | Yes (paid) |
| VirusTotal | Commercial API tiers | Yes (paid) |
| Spamhaus | Free for non-commercial | Requires license for commercial |

Default bundled feed configuration should use CC0/MIT-licensed feeds only.

## Testing Strategy

### Unit Tests (`internal/threatfeed/`)

**`store_test.go`:**
- Exact domain match
- Parent domain match (`sub.evil.com` matches `evil.com` in store)
- Allowlist override (domain in feed + allowlist → no match)
- Concurrent read/write safety (goroutines calling `Check` while `Update` swaps)
- `SaveToDisk` / `LoadFromDisk` round-trip
- Empty store returns no matches

**`parser_test.go`:**
- Hostfile: standard lines, comments, blank lines, `0.0.0.0` vs `127.0.0.1`, trailing comments, duplicates
- Domain list: one per line, comments, whitespace, mixed case → lowercase
- Malformed input: binary garbage, extremely long lines, empty input → no panic, returns empty

**`syncer_test.go`:**
- `httptest.Server` serving fake feeds → store populated after `syncAll()`
- `If-Modified-Since` header sent on second fetch
- Fetch failure keeps previous data (serve feed, then 500, verify store unchanged)
- Context cancellation stops loop and triggers `SaveToDisk`
- Local file lists parsed alongside remote feeds

### Integration Test (`internal/policy/`)

**`engine_threat_test.go`:**
- `CheckNetworkCtx` with populated threat store → deny with correct rule, fields
- Action set to `audit` → audit decision, connection proceeds
- Threat store is nil → skipped, falls through to `network_rules`
- Domain in threat store checked before `network_rules`

### Existing Tests

No changes needed. The threat store is optional (nil = skipped), so all existing policy engine tests pass without modification.
