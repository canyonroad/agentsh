package tor

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestParseOnionoo(t *testing.T) {
	body := `{"relays":[
		{"or_addresses":["128.66.0.1:9001","[2001:db8::2]:443"]},
		{"or_addresses":["128.66.0.2:443"]},
		{"or_addresses":["garbage"]}
	]}`
	ips, err := parseOnionoo(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseOnionoo: %v", err)
	}
	if len(ips) != 3 {
		t.Fatalf("want 3 parseable IPs, got %d (%v)", len(ips), ips)
	}
	set := buildSet(ips)
	if !set.Contains(net.ParseIP("128.66.0.1")) {
		t.Fatal("expected 128.66.0.1 in set")
	}
	if !set.Contains(net.ParseIP("2001:db8::2")) {
		t.Fatal("expected IPv6 relay in set")
	}
}

func TestParseOnionoo_Malformed(t *testing.T) {
	if _, err := parseOnionoo(strings.NewReader("{not json")); err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestSyncer_CacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	syncer := &Syncer{cacheDir: dir}

	ips := []string{"10.0.0.1", "10.0.0.2", "2001:db8::3"}
	if err := syncer.saveCache(ips); err != nil {
		t.Fatalf("saveCache: %v", err)
	}
	cpath := filepath.Join(dir, "tor-relays.txt")
	if _, err := os.Stat(cpath); err != nil {
		t.Fatalf("cache file not created: %v", err)
	}
	loaded := syncer.loadCache()
	if len(loaded) != len(ips) {
		t.Fatalf("want %d ips, got %d: %v", len(ips), len(loaded), loaded)
	}
	set := buildSet(loaded)
	if !set.Contains(net.ParseIP("10.0.0.1")) {
		t.Fatal("expected 10.0.0.1 in loaded set")
	}
	if !set.Contains(net.ParseIP("2001:db8::3")) {
		t.Fatal("expected IPv6 in loaded set")
	}
}

func TestSyncer_FetchAndSync(t *testing.T) {
	body := `{"relays":[
		{"or_addresses":["192.0.2.1:9001"]},
		{"or_addresses":["[2001:db8::ff]:443"]}
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	cfg := config.ResolveTorConfig(config.TorConfig{})
	cfg.RelayFeed.Enabled = true
	cfg.RelayFeed.Sources = []string{srv.URL}
	pol, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	syncer := NewSyncer(pol, nil)
	ips, err := syncer.fetch(t.Context(), srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("want 2 ips, got %d: %v", len(ips), ips)
	}
	pol.SetRelays(buildSet(ips))

	v, ok := pol.EvalConnect(net.ParseIP("192.0.2.1"), 9001)
	if !ok {
		t.Fatal("expected match for fetched relay IP")
	}
	if v.Vector != VectorRelayIP {
		t.Fatalf("want vector %q, got %q", VectorRelayIP, v.Vector)
	}
}

func TestSyncer_PartialFailureRetainsLastGood(t *testing.T) {
	// Source A and B both serve valid relays initially; then A starts failing.
	// A's relay IP must remain enforced (substituted from per-source last-good)
	// rather than being silently dropped because A failed this run.
	aFail := false
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if aFail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"relays":[{"or_addresses":["198.51.100.1:9001"]}]}`))
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"relays":[{"or_addresses":["203.0.113.1:443"]}]}`))
	}))
	defer srvB.Close()

	cfg := config.ResolveTorConfig(config.TorConfig{})
	cfg.RelayFeed.Enabled = true
	cfg.RelayFeed.Sources = []string{srvA.URL, srvB.URL}
	pol, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := NewSyncer(pol, nil)

	s.sync(t.Context()) // first sync: both succeed
	if _, ok := pol.EvalConnect(net.ParseIP("198.51.100.1"), 9001); !ok {
		t.Fatal("A relay should match after first sync")
	}
	if _, ok := pol.EvalConnect(net.ParseIP("203.0.113.1"), 443); !ok {
		t.Fatal("B relay should match after first sync")
	}

	aFail = true
	s.sync(t.Context()) // second sync: A fails, B succeeds
	if _, ok := pol.EvalConnect(net.ParseIP("198.51.100.1"), 9001); !ok {
		t.Fatal("A relay must STILL match after A fails (per-source last-good substitution)")
	}
	if _, ok := pol.EvalConnect(net.ParseIP("203.0.113.1"), 443); !ok {
		t.Fatal("B relay should still match after second sync")
	}
}

func TestSyncer_EmptyResultRetainsPrior(t *testing.T) {
	// A single source first serves a relay, then returns 200 with zero relays.
	// The empty merged result must NOT wipe the enforced set.
	empty := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if empty {
			_, _ = w.Write([]byte(`{"relays":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"relays":[{"or_addresses":["192.0.2.50:9001"]}]}`))
	}))
	defer srv.Close()

	cfg := config.ResolveTorConfig(config.TorConfig{})
	cfg.RelayFeed.Enabled = true
	cfg.RelayFeed.Sources = []string{srv.URL}
	pol, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := NewSyncer(pol, nil)

	s.sync(t.Context())
	if _, ok := pol.EvalConnect(net.ParseIP("192.0.2.50"), 9001); !ok {
		t.Fatal("relay should match after first sync")
	}
	empty = true
	s.sync(t.Context())
	if _, ok := pol.EvalConnect(net.ParseIP("192.0.2.50"), 9001); !ok {
		t.Fatal("empty 200 response must retain prior set, not wipe it")
	}
}

func TestSyncer_RestartPartialFailureRetainsCachedRelays(t *testing.T) {
	// Simulate a restart: cacheSeed is populated (as Run would from disk),
	// per-source lastGood is empty, and one of two sources fails on the
	// first sync. The cached relay IP of the failed source must remain
	// enforced (folded from the cache seed), not be wiped.
	bFail := false
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"relays":[{"or_addresses":["198.51.100.1:9001"]}]}`))
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bFail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"relays":[{"or_addresses":["203.0.113.1:443"]}]}`))
	}))
	defer srvB.Close()

	cfg := config.ResolveTorConfig(config.TorConfig{})
	cfg.RelayFeed.Enabled = true
	cfg.RelayFeed.Sources = []string{srvA.URL, srvB.URL}
	pol, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := NewSyncer(pol, nil)
	// Emulate Run() having loaded a disk cache that contains B's relay IP.
	s.cacheSeed = []string{"203.0.113.1"}
	pol.SetRelays(buildSet(s.cacheSeed))

	bFail = true
	s.sync(t.Context()) // first post-restart sync: A ok, B fails
	if _, ok := pol.EvalConnect(net.ParseIP("203.0.113.1"), 443); !ok {
		t.Fatal("cached relay IP of the failed source must remain enforced after restart+partial failure")
	}
	if _, ok := pol.EvalConnect(net.ParseIP("198.51.100.1"), 9001); !ok {
		t.Fatal("healthy source relay must be enforced")
	}

	// Once B recovers and all sources are proven, the stale cache seed is no
	// longer folded; fresh per-source data takes over.
	bFail = false
	s.sync(t.Context())
	if _, ok := pol.EvalConnect(net.ParseIP("203.0.113.1"), 443); !ok {
		t.Fatal("B relay should still be enforced from its own fresh data")
	}
}

func TestSyncer_CacheSeedDroppedAfterAllProven(t *testing.T) {
	// A stale cache-seed IP that no live source serves must disappear once
	// every source has reported fresh at least once (no unbounded staleness).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"relays":[{"or_addresses":["192.0.2.10:9001"]}]}`))
	}))
	defer srv.Close()
	cfg := config.ResolveTorConfig(config.TorConfig{})
	cfg.RelayFeed.Enabled = true
	cfg.RelayFeed.Sources = []string{srv.URL}
	pol, _ := New(cfg)
	s := NewSyncer(pol, nil)
	s.cacheSeed = []string{"198.51.100.222"} // stale, not served by any source
	pol.SetRelays(buildSet(s.cacheSeed))

	s.sync(t.Context()) // single source succeeds → all proven → seed dropped
	if _, ok := pol.EvalConnect(net.ParseIP("192.0.2.10"), 9001); !ok {
		t.Fatal("fresh relay must be enforced")
	}
	if _, ok := pol.EvalConnect(net.ParseIP("198.51.100.222"), 9001); ok {
		t.Fatal("stale cache-seed IP must be dropped once all sources are proven")
	}
}

func TestSyncer_DedupesMergedSet(t *testing.T) {
	body := `{"relays":[{"or_addresses":["192.0.2.1:9001"]},{"or_addresses":["192.0.2.1:443"]}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	cfg := config.ResolveTorConfig(config.TorConfig{})
	cfg.RelayFeed.Enabled = true
	cfg.RelayFeed.Sources = []string{srv.URL}
	dir := t.TempDir()
	cfg.RelayFeed.CacheDir = dir
	pol, _ := New(cfg)
	s := NewSyncer(pol, nil)
	s.sync(t.Context())
	// 192.0.2.1 appears twice in the source; the persisted cache must contain it once.
	loaded := s.loadCache()
	count := 0
	for _, ip := range loaded {
		if ip == "192.0.2.1" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 192.0.2.1 once in deduped cache, got %d (%v)", count, loaded)
	}
}
