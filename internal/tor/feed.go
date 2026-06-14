package tor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/ipset"
)

const maxOnionooSize = 200 * 1024 * 1024 // 200 MB; onionoo details is large

// parseOnionoo extracts relay host IPs from an onionoo `details` document.
// Unparseable or_addresses entries are skipped (best-effort).
func parseOnionoo(r io.Reader) ([]string, error) {
	var doc struct {
		Relays []struct {
			OrAddresses []string `json:"or_addresses"`
		} `json:"relays"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}
	var ips []string
	for _, relay := range doc.Relays {
		for _, addr := range relay.OrAddresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				continue
			}
			if net.ParseIP(host) == nil {
				continue
			}
			ips = append(ips, host)
		}
	}
	return ips, nil
}

// buildSet constructs an ipset.Set from a list of IP/CIDR strings,
// skipping invalid entries.
func buildSet(entries []string) *ipset.Set {
	s := ipset.New()
	for _, e := range entries {
		_ = s.Add(e)
	}
	return s
}

// Syncer periodically refreshes a Policy's relay set from onionoo
// sources + local lists. Modeled on internal/threatfeed.Syncer.
type Syncer struct {
	pol      *Policy
	sources  []string
	locals   []string
	interval time.Duration
	cacheDir string
	client   *http.Client
	logger   *slog.Logger
	lastGood map[string][]string // per-source ("local:"+path for files) last-good IPs
}

// NewSyncer builds a relay-feed syncer for the given Policy.
func NewSyncer(pol *Policy, logger *slog.Logger) *Syncer {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	cfg := pol.RelayFeedConfig()
	interval := cfg.SyncInterval
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &Syncer{
		pol:      pol,
		sources:  cfg.Sources,
		locals:   cfg.LocalLists,
		interval: interval,
		cacheDir: cfg.CacheDir,
		client:   &http.Client{Timeout: 60 * time.Second},
		logger:   logger,
		lastGood: make(map[string][]string),
	}
}

// Run loads the disk cache, performs an initial sync, then refreshes on
// the configured interval until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	if cached := s.loadCache(); len(cached) > 0 {
		s.pol.SetRelays(buildSet(cached))
		s.logger.Info("tor relay cache loaded", "ips", len(cached))
	}
	s.sync(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sync(ctx)
		}
	}
}

func (s *Syncer) sync(ctx context.Context) {
	if s.lastGood == nil {
		s.lastGood = make(map[string][]string)
	}
	var all []string
	for _, src := range s.sources {
		ips, err := s.fetch(ctx, src)
		if err != nil {
			s.logger.Warn("tor relay feed fetch failed, using last-good",
				"source", src, "error", err, "last_good_ips", len(s.lastGood[src]))
			all = append(all, s.lastGood[src]...) // substitute this source's last-good
			continue
		}
		s.lastGood[src] = ips
		all = append(all, ips...)
	}
	for _, path := range s.locals {
		key := "local:" + path
		ips, err := s.parseLocal(path)
		if err != nil {
			s.logger.Warn("tor relay local list failed, using last-good",
				"path", path, "error", err, "last_good_ips", len(s.lastGood[key]))
			all = append(all, s.lastGood[key]...)
			continue
		}
		s.lastGood[key] = ips
		all = append(all, ips...)
	}
	// An empty merged result is a non-success: retain the prior applied set
	// (and the immutable seed in Policy). Covers all-sources-failed AND a
	// source returning 200 with zero relays.
	if len(all) == 0 {
		s.logger.Warn("tor relay feed: empty merged result, retaining prior set+seed")
		return
	}
	s.pol.SetRelays(buildSet(all))
	if err := s.saveCache(all); err != nil {
		s.logger.Warn("tor relay cache save failed", "error", err)
	}
	s.logger.Info("tor relay feed synced", "ips", len(all))
}

func (s *Syncer) fetch(ctx context.Context, src string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", src, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseOnionoo(&io.LimitedReader{R: resp.Body, N: maxOnionooSize})
}

func (s *Syncer) parseLocal(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var ips []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips = append(ips, line) // IP or CIDR; ipset.Add validates
	}
	return ips, sc.Err()
}

func (s *Syncer) cachePath() string {
	dir := s.cacheDir
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "tor-relays.txt")
}

func (s *Syncer) loadCache() []string {
	p := s.cachePath()
	if p == "" {
		return nil
	}
	ips, err := s.parseLocal(p)
	if err != nil {
		return nil
	}
	return ips
}

func (s *Syncer) saveCache(ips []string) error {
	p := s.cachePath()
	if p == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(strings.Join(ips, "\n")), 0o644)
}
