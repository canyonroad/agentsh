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
		SyncInterval: time.Hour,
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

	// Second sync fails — store should keep previous data via last-known-good.
	syncer.syncAll()
	assert.Equal(t, 1, store.Size())
	_, matched := store.Check("evil.com")
	assert.True(t, matched)
}

func TestSyncer_NotModifiedPreservesData(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("ETag", "\"abc123\"")
			fmt.Fprintln(w, "0.0.0.0 evil.com")
			return
		}
		if r.Header.Get("If-None-Match") == "\"abc123\"" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		fmt.Fprintln(w, "0.0.0.0 evil.com")
	}))
	defer srv.Close()

	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "etag-feed", URL: srv.URL, Format: "hostfile"},
		},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)

	syncer.syncAll()
	assert.Equal(t, 1, store.Size())

	// Second sync gets 304 — store should still have the domain.
	syncer.syncAll()
	assert.Equal(t, 1, store.Size())
	_, matched := store.Check("evil.com")
	assert.True(t, matched)
}

func TestSyncer_PartialFeedFailurePreservesOtherFeed(t *testing.T) {
	calls := 0
	srvFlaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			fmt.Fprintln(w, "0.0.0.0 flaky-evil.com")
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srvFlaky.Close()

	srvStable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "stable-evil.com")
	}))
	defer srvStable.Close()

	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "flaky", URL: srvFlaky.URL, Format: "hostfile"},
			{Name: "stable", URL: srvStable.URL, Format: "domain-list"},
		},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)

	syncer.syncAll()
	assert.Equal(t, 2, store.Size())

	// Second sync: flaky fails, stable succeeds — both domains should remain.
	syncer.syncAll()
	assert.Equal(t, 2, store.Size())
	_, matched := store.Check("flaky-evil.com")
	assert.True(t, matched, "flaky feed's last-known-good should be preserved")
	_, matched = store.Check("stable-evil.com")
	assert.True(t, matched)
}

func TestSyncer_NonPositiveIntervalDefaults(t *testing.T) {
	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		SyncInterval: 0, // invalid
	}
	syncer := NewSyncer(store, cfg, nil)
	assert.Equal(t, 6*time.Hour, syncer.interval)
}

func TestSyncer_AllFailFirstSyncPreservesDiskCache(t *testing.T) {
	dir := t.TempDir()

	// Pre-populate disk cache.
	s1 := NewStore(dir, nil)
	s1.Update(map[string]FeedEntry{
		"cached-evil.com": {FeedName: "old-feed", AddedAt: time.Now()},
	})
	err := s1.SaveToDisk()
	require.NoError(t, err)

	// Create new store, load from disk.
	store := NewStore(dir, nil)
	err = store.LoadFromDisk()
	require.NoError(t, err)
	assert.Equal(t, 1, store.Size())

	// All feeds fail on first sync — should NOT wipe the disk-loaded cache.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "broken", URL: srv.URL, Format: "hostfile"},
		},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)
	syncer.syncAll()

	assert.Equal(t, 1, store.Size(), "disk-loaded cache should be preserved when all feeds fail")
	_, matched := store.Check("cached-evil.com")
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
	case <-time.After(2 * time.Second):
		t.Fatal("syncer did not stop after context cancellation")
	}
}

func TestSyncer_SavesToDiskOnShutdown(t *testing.T) {
	dir := t.TempDir()
	fetched := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "0.0.0.0 evil.com")
		select {
		case fetched <- struct{}{}:
		default:
		}
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

	// Wait for the initial sync to complete.
	select {
	case <-fetched:
	case <-time.After(5 * time.Second):
		t.Fatal("syncer did not fetch feed in time")
	}
	cancel()
	<-done

	_, err := os.Stat(filepath.Join(dir, "feeds.cache"))
	assert.NoError(t, err)
}
