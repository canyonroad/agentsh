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
	etags    map[string]string
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
		return nil, nil
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
