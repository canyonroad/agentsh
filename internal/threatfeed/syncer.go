package threatfeed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/agentsh/agentsh/internal/config"
)

const maxFeedSize = 100 * 1024 * 1024 // 100 MB

var (
	errNotModified = errors.New("not modified")
	errTruncated   = errors.New("feed exceeds maximum size, skipping to avoid partial data")
)

// Syncer periodically downloads threat feeds and updates the store.
type Syncer struct {
	store    *Store
	feeds    []config.ThreatFeedEntry
	locals   []string
	interval time.Duration
	client   *http.Client
	logger   *slog.Logger
	etags    map[string]string
	// Per-feed last-known-good domain snapshots. Keyed by feed name.
	lastGood    map[string][]string
	seededCache bool // true after lastGood has been seeded from store
}

// NewSyncer creates a new feed syncer. Pass nil for logger to disable logging.
func NewSyncer(store *Store, cfg config.ThreatFeedsConfig, logger *slog.Logger) *Syncer {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	interval := cfg.SyncInterval
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &Syncer{
		store:    store,
		feeds:    cfg.Feeds,
		locals:   cfg.LocalLists,
		interval: interval,
		client:   &http.Client{Timeout: 30 * time.Second},
		logger:   logger,
		etags:    make(map[string]string),
		lastGood: make(map[string][]string),
	}
}

// Run starts the periodic sync loop. It blocks until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	s.syncAll(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := s.store.SaveToDisk(); err != nil {
				s.logger.Warn("threat feed disk save failed on shutdown", "error", err)
			}
			return
		case <-ticker.C:
			s.syncAll(ctx)
		}
	}
}

// syncAll fetches all feeds and local lists, merges results, and updates the store.
// On fetch failure or 304 Not Modified, the feed's last-known-good data is preserved.
func (s *Syncer) syncAll(ctx context.Context) {
	// On first sync, seed lastGood from the store's disk-loaded data, but only
	// for feeds that are currently configured. This prevents domains from removed
	// feeds from persisting indefinitely.
	needsPrune := false
	if !s.seededCache {
		s.seededCache = true
		configuredKeys := s.configuredFeedKeys()
		for feedName, domains := range s.store.Snapshot() {
			if _, configured := configuredKeys[feedName]; !configured {
				needsPrune = true // disk cache has entries from removed feeds
				continue
			}
			if _, exists := s.lastGood[feedName]; !exists {
				s.lastGood[feedName] = domains
			}
		}
	}

	merged := make(map[string]FeedEntry)
	anySucceeded := false
	hasSources := len(s.feeds) > 0 || len(s.locals) > 0

	for _, feed := range s.feeds {
		domains, err := s.fetchFeed(ctx, feed)
		if err != nil {
			if errors.Is(err, errNotModified) {
				// 304: reuse last-known-good data for this feed.
				s.logger.Debug("threat feed not modified", "feed", feed.Name)
				anySucceeded = true // 304 means source is reachable
			} else {
				// Fetch failure: reuse last-known-good, log warning.
				s.logger.Warn("threat feed fetch failed, using cached data",
					"feed", feed.Name, "url", sanitizeURL(feed.URL), "error", err)
			}
			domains = s.lastGood[feed.Name]
		} else {
			// Success: update last-known-good snapshot.
			s.lastGood[feed.Name] = domains
			s.logger.Info("threat feed synced",
				"feed", feed.Name, "domains", len(domains))
			anySucceeded = true
		}
		now := time.Now()
		for _, d := range domains {
			if _, exists := merged[d]; !exists {
				merged[d] = FeedEntry{FeedName: feed.Name, AddedAt: now}
			}
		}
	}

	for _, path := range s.locals {
		cacheKey := "local:" + path // unique key for lastGood and FeedEntry
		domains, err := s.parseLocalFile(path)
		if err != nil {
			s.logger.Warn("local threat list failed, using cached data",
				"path", path, "error", err)
			domains = s.lastGood[cacheKey]
		} else {
			s.lastGood[cacheKey] = domains
			anySucceeded = true
		}
		now := time.Now()
		for _, d := range domains {
			if _, exists := merged[d]; !exists {
				merged[d] = FeedEntry{FeedName: cacheKey, AddedAt: now}
			}
		}
	}

	// Update the store if at least one source succeeded (even if the result is
	// empty — that legitimately clears stale entries). Also update when no sources
	// are configured to clear any stale disk cache, or when we need to prune
	// entries from removed feeds. Skip the update only when sources exist but
	// ALL failed and no pruning is needed, to preserve the disk-loaded cache.
	if anySucceeded || !hasSources || len(merged) > 0 || needsPrune {
		s.store.Update(merged)
		if err := s.store.SaveToDisk(); err != nil {
			s.logger.Warn("threat feed disk save failed", "error", err)
		}
	}
}

func (s *Syncer) fetchFeed(ctx context.Context, feed config.ThreatFeedEntry) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", feed.URL, nil)
	if err != nil {
		return nil, err
	}
	if etag, ok := s.etags[feed.Name]; ok {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, errNotModified
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if etag := resp.Header.Get("ETag"); etag != "" {
		s.etags[feed.Name] = etag
	}

	// Use maxFeedSize+1 so we can distinguish "exactly at limit" from "truncated".
	lr := &io.LimitedReader{R: resp.Body, N: maxFeedSize + 1}
	parser := ParserForFormat(feed.Format)
	domains, err := parser.Parse(lr)
	if err != nil {
		return nil, err
	}
	// If the extra byte was consumed (N == 0), the feed exceeded maxFeedSize.
	if lr.N == 0 {
		return nil, errTruncated
	}
	return domains, nil
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

// configuredFeedKeys returns the set of feed keys (remote names + local cache keys)
// that are currently configured, used to filter out stale cache entries from removed feeds.
func (s *Syncer) configuredFeedKeys() map[string]struct{} {
	keys := make(map[string]struct{}, len(s.feeds)+len(s.locals))
	for _, feed := range s.feeds {
		keys[feed.Name] = struct{}{}
	}
	for _, path := range s.locals {
		keys["local:"+path] = struct{}{}
	}
	return keys
}

// sanitizeURL strips everything except scheme and host from a URL for safe
// logging. Path segments may contain tokens or secrets in some feed URLs.
func sanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid-url>"
	}
	return u.Scheme + "://" + u.Host
}
