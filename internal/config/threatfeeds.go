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
