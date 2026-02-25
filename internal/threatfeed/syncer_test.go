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
	syncer.syncAll(context.Background())

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
	syncer.syncAll(context.Background())

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
	syncer.syncAll(context.Background())

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

	syncer.syncAll(context.Background())
	assert.Equal(t, 1, store.Size())

	// Second sync fails — store should keep previous data via last-known-good.
	syncer.syncAll(context.Background())
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

	syncer.syncAll(context.Background())
	assert.Equal(t, 1, store.Size())

	// Second sync gets 304 — store should still have the domain.
	syncer.syncAll(context.Background())
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

	syncer.syncAll(context.Background())
	assert.Equal(t, 2, store.Size())

	// Second sync: flaky fails, stable succeeds — both domains should remain.
	syncer.syncAll(context.Background())
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
	syncer.syncAll(context.Background())

	assert.Equal(t, 1, store.Size(), "disk-loaded cache should be preserved when all feeds fail")
	_, matched := store.Check("cached-evil.com")
	assert.True(t, matched)
}

func TestSyncer_SuccessfulEmptySyncClearsStore(t *testing.T) {
	// First sync populates the store.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			fmt.Fprintln(w, "0.0.0.0 evil.com")
			return
		}
		// Second call: return empty (all domains removed from feed).
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "clearing", URL: srv.URL, Format: "hostfile"},
		},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)

	syncer.syncAll(context.Background())
	assert.Equal(t, 1, store.Size())

	// Second sync succeeds with empty result — stale entries should be cleared.
	syncer.syncAll(context.Background())
	assert.Equal(t, 0, store.Size(), "successful empty sync should clear stale entries")
}

func TestSyncer_DiskCachePartialFirstSyncFailure(t *testing.T) {
	dir := t.TempDir()

	// Pre-populate disk cache with entries from two feeds.
	s1 := NewStore(dir, nil)
	s1.Update(map[string]FeedEntry{
		"feed-a-evil.com": {FeedName: "feed-a", AddedAt: time.Now()},
		"feed-b-evil.com": {FeedName: "feed-b", AddedAt: time.Now()},
	})
	err := s1.SaveToDisk()
	require.NoError(t, err)

	// New store loads disk cache.
	store := NewStore(dir, nil)
	err = store.LoadFromDisk()
	require.NoError(t, err)
	assert.Equal(t, 2, store.Size())

	// feed-a succeeds, feed-b fails on first sync.
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "feed-a-evil.com")
	}))
	defer srvA.Close()

	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srvB.Close()

	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "feed-a", URL: srvA.URL, Format: "domain-list"},
			{Name: "feed-b", URL: srvB.URL, Format: "domain-list"},
		},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)
	syncer.syncAll(context.Background())

	// Both domains should be present: feed-a from fresh fetch, feed-b from seeded cache.
	assert.Equal(t, 2, store.Size(), "partial first-sync failure should retain cached entries for failed feed")
	_, matched := store.Check("feed-a-evil.com")
	assert.True(t, matched, "feed-a domain should be present from fresh fetch")
	_, matched = store.Check("feed-b-evil.com")
	assert.True(t, matched, "feed-b domain should be retained from disk cache")
}

func TestSyncer_NoSourcesClearsStaleDiskCache(t *testing.T) {
	dir := t.TempDir()

	// Pre-populate disk cache.
	s1 := NewStore(dir, nil)
	s1.Update(map[string]FeedEntry{
		"stale.com": {FeedName: "old-feed", AddedAt: time.Now()},
	})
	err := s1.SaveToDisk()
	require.NoError(t, err)

	// Load from disk, then sync with no sources configured.
	store := NewStore(dir, nil)
	err = store.LoadFromDisk()
	require.NoError(t, err)
	assert.Equal(t, 1, store.Size())

	cfg := config.ThreatFeedsConfig{
		SyncInterval: time.Hour,
		// No feeds, no local lists.
	}
	syncer := NewSyncer(store, cfg, nil)
	syncer.syncAll(context.Background())

	assert.Equal(t, 0, store.Size(), "no sources configured should clear stale disk cache")
}

func TestSyncer_LocalListUsesFullPathAsCacheKey(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "blocklist.txt")
	err := os.WriteFile(listPath, []byte("evil.com\n"), 0o644)
	require.NoError(t, err)

	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		LocalLists:   []string{listPath},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)
	syncer.syncAll(context.Background())

	// Internally, FeedName uses the full path for cache key consistency.
	entry, matched := store.Check("evil.com")
	require.True(t, matched)
	assert.Equal(t, "local:"+listPath, entry.FeedName)
}

func TestSyncer_LocalListBasenamCollisionKeepsSeparateCache(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	// Two lists with the same basename but different directories and content.
	list1 := filepath.Join(dir1, "blocklist.txt")
	list2 := filepath.Join(dir2, "blocklist.txt")
	err := os.WriteFile(list1, []byte("evil-from-list1.com\n"), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(list2, []byte("evil-from-list2.com\n"), 0o644)
	require.NoError(t, err)

	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		LocalLists:   []string{list1, list2},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)
	syncer.syncAll(context.Background())

	// Both domains should be present — no collision.
	assert.Equal(t, 2, store.Size(), "same-basename local lists should not collide")
	_, matched := store.Check("evil-from-list1.com")
	assert.True(t, matched)
	_, matched = store.Check("evil-from-list2.com")
	assert.True(t, matched)

	// Now make list1 fail — list2 should still work, and list1's cached data should be retained.
	os.Remove(list1)
	syncer.syncAll(context.Background())

	assert.Equal(t, 2, store.Size(), "failed list should use its own last-known-good, not the other list's")
	_, matched = store.Check("evil-from-list1.com")
	assert.True(t, matched, "list1 last-known-good should be retained independently")
	_, matched = store.Check("evil-from-list2.com")
	assert.True(t, matched)
}

func TestSyncer_RestartLocalFailRemoteSuccessRetainsCachedLocal(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "local.txt")

	// Pre-populate disk cache with a local list entry and a remote feed entry.
	s1 := NewStore(dir, nil)
	s1.Update(map[string]FeedEntry{
		"local-evil.com":  {FeedName: "local:" + listPath, AddedAt: time.Now()},
		"remote-evil.com": {FeedName: "remote-feed", AddedAt: time.Now()},
	})
	err := s1.SaveToDisk()
	require.NoError(t, err)

	// Simulate restart: load from disk.
	store := NewStore(dir, nil)
	err = store.LoadFromDisk()
	require.NoError(t, err)
	assert.Equal(t, 2, store.Size())

	// Remote feed succeeds, local list file is missing (fails).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "remote-evil.com")
	}))
	defer srv.Close()

	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "remote-feed", URL: srv.URL, Format: "domain-list"},
		},
		LocalLists:   []string{listPath}, // file doesn't exist — will fail
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)
	syncer.syncAll(context.Background())

	// Both domains should be present: remote from fresh fetch, local from seeded cache.
	assert.Equal(t, 2, store.Size(), "local list cached entries should survive restart + failure")
	_, matched := store.Check("remote-evil.com")
	assert.True(t, matched)
	_, matched = store.Check("local-evil.com")
	assert.True(t, matched, "local list entries should be retained from disk cache via seeded lastGood")
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
	syncer.syncAll(context.Background())

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

func TestSyncer_CancelDuringFetch(t *testing.T) {
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		// Block until the request context is cancelled.
		<-r.Context().Done()
	}))
	defer srv.Close()

	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "slow", URL: srv.URL, Format: "hostfile"},
		},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		syncer.syncAll(ctx)
		close(done)
	}()

	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("syncAll did not return after context cancellation during fetch")
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

func TestSyncer_RemovedFeedNotRetainedOnAllFail(t *testing.T) {
	dir := t.TempDir()

	// Pre-populate disk cache with entries from two feeds.
	s1 := NewStore(dir, nil)
	s1.Update(map[string]FeedEntry{
		"old-feed-evil.com": {FeedName: "old-feed", AddedAt: time.Now()},
		"current-evil.com":  {FeedName: "current-feed", AddedAt: time.Now()},
	})
	err := s1.SaveToDisk()
	require.NoError(t, err)

	// Load from disk, then sync with only "current-feed" configured (old-feed removed).
	store := NewStore(dir, nil)
	err = store.LoadFromDisk()
	require.NoError(t, err)
	assert.Equal(t, 2, store.Size())

	// current-feed fails on first sync.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "current-feed", URL: srv.URL, Format: "domain-list"},
		},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)
	syncer.syncAll(context.Background())

	// current-feed's cached entry should be retained, but old-feed's should be gone.
	_, matched := store.Check("current-evil.com")
	assert.True(t, matched, "current feed's cached entry should be retained")
	_, matched = store.Check("old-feed-evil.com")
	assert.False(t, matched, "removed feed's entry should NOT be retained")
}

func TestSyncer_DuplicateURLDifferentNames(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("ETag", fmt.Sprintf("\"etag-%d\"", calls))
		fmt.Fprintln(w, "evil.com")
	}))
	defer srv.Close()

	store := NewStore("", nil)
	cfg := config.ThreatFeedsConfig{
		Feeds: []config.ThreatFeedEntry{
			{Name: "feed-a", URL: srv.URL, Format: "domain-list"},
			{Name: "feed-b", URL: srv.URL, Format: "domain-list"},
		},
		SyncInterval: time.Hour,
	}
	syncer := NewSyncer(store, cfg, nil)
	syncer.syncAll(context.Background())

	// Both feeds should have been fetched (no premature 304).
	assert.Equal(t, 2, calls, "both feeds should fetch independently despite same URL")
	assert.Equal(t, 1, store.Size())
	_, matched := store.Check("evil.com")
	assert.True(t, matched)
}
