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

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	_, err := os.Stat(filepath.Join(dir, "feeds.cache"))
	assert.NoError(t, err)
}
