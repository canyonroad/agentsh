package config

import (
	"testing"
	"time"
)

func TestThreatFeedsDefaults(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	if cfg.ThreatFeeds.Action != "deny" {
		t.Errorf("expected default Action %q, got %q", "deny", cfg.ThreatFeeds.Action)
	}
	if cfg.ThreatFeeds.SyncInterval != 6*time.Hour {
		t.Errorf("expected default SyncInterval %v, got %v", 6*time.Hour, cfg.ThreatFeeds.SyncInterval)
	}
	if cfg.ThreatFeeds.Realtime.Timeout != 500*time.Millisecond {
		t.Errorf("expected default Realtime.Timeout %v, got %v", 500*time.Millisecond, cfg.ThreatFeeds.Realtime.Timeout)
	}
	if cfg.ThreatFeeds.Realtime.CacheTTL != 1*time.Hour {
		t.Errorf("expected default Realtime.CacheTTL %v, got %v", 1*time.Hour, cfg.ThreatFeeds.Realtime.CacheTTL)
	}
	if cfg.ThreatFeeds.Realtime.OnTimeout != "local-only" {
		t.Errorf("expected default Realtime.OnTimeout %q, got %q", "local-only", cfg.ThreatFeeds.Realtime.OnTimeout)
	}
}

func TestThreatFeedsDefaultsNotOverridden(t *testing.T) {
	cfg := &Config{}
	cfg.ThreatFeeds.Action = "log"
	cfg.ThreatFeeds.SyncInterval = 1 * time.Hour
	cfg.ThreatFeeds.Realtime.Timeout = 200 * time.Millisecond
	cfg.ThreatFeeds.Realtime.CacheTTL = 30 * time.Minute
	cfg.ThreatFeeds.Realtime.OnTimeout = "allow"

	applyDefaults(cfg)

	if cfg.ThreatFeeds.Action != "log" {
		t.Errorf("expected Action %q to not be overridden, got %q", "log", cfg.ThreatFeeds.Action)
	}
	if cfg.ThreatFeeds.SyncInterval != 1*time.Hour {
		t.Errorf("expected SyncInterval %v to not be overridden, got %v", 1*time.Hour, cfg.ThreatFeeds.SyncInterval)
	}
	if cfg.ThreatFeeds.Realtime.Timeout != 200*time.Millisecond {
		t.Errorf("expected Realtime.Timeout %v to not be overridden, got %v", 200*time.Millisecond, cfg.ThreatFeeds.Realtime.Timeout)
	}
	if cfg.ThreatFeeds.Realtime.CacheTTL != 30*time.Minute {
		t.Errorf("expected Realtime.CacheTTL %v to not be overridden, got %v", 30*time.Minute, cfg.ThreatFeeds.Realtime.CacheTTL)
	}
	if cfg.ThreatFeeds.Realtime.OnTimeout != "allow" {
		t.Errorf("expected Realtime.OnTimeout %q to not be overridden, got %q", "allow", cfg.ThreatFeeds.Realtime.OnTimeout)
	}
}

func TestThreatFeedsConfigStruct(t *testing.T) {
	cfg := ThreatFeedsConfig{
		Enabled: true,
		Action:  "deny",
		Feeds: []ThreatFeedEntry{
			{Name: "test", URL: "https://example.com/hosts", Format: "hostfile"},
		},
		LocalLists:   []string{"/etc/agentsh/blocklist.txt"},
		Allowlist:     []string{"safe.example.com"},
		SyncInterval:  6 * time.Hour,
		CacheDir:      "/tmp/feeds",
		Realtime: RealtimeConfig{
			Provider:  "virustotal",
			APIKey:    "test-key",
			Timeout:   500 * time.Millisecond,
			CacheTTL:  1 * time.Hour,
			OnTimeout: "local-only",
		},
	}

	if !cfg.Enabled {
		t.Error("expected Enabled to be true")
	}
	if len(cfg.Feeds) != 1 {
		t.Errorf("expected 1 feed entry, got %d", len(cfg.Feeds))
	}
	if cfg.Feeds[0].Format != "hostfile" {
		t.Errorf("expected feed format %q, got %q", "hostfile", cfg.Feeds[0].Format)
	}
	if cfg.Realtime.Provider != "virustotal" {
		t.Errorf("expected provider %q, got %q", "virustotal", cfg.Realtime.Provider)
	}
}

func TestThreatFeedsValidation_InvalidAction(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.ThreatFeeds.Action = "typo"
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for invalid threat_feeds.action")
	}
}

func TestThreatFeedsValidation_InvalidFormat(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.ThreatFeeds.Feeds = []ThreatFeedEntry{
		{Name: "test", URL: "https://example.com", Format: "csv"},
	}
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for invalid feed format")
	}
}

func TestThreatFeedsValidation_InvalidOnTimeout(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.ThreatFeeds.Realtime.OnTimeout = "crash"
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for invalid realtime.on_timeout")
	}
}

func TestThreatFeedsValidation_ValidConfig(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.ThreatFeeds.Action = "audit"
	cfg.ThreatFeeds.Feeds = []ThreatFeedEntry{
		{Name: "test", URL: "https://example.com", Format: "domain-list"},
	}
	cfg.ThreatFeeds.Realtime.OnTimeout = "allow"
	err := validateConfig(cfg)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestThreatFeedsValidation_DuplicateFeedNames(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.ThreatFeeds.Feeds = []ThreatFeedEntry{
		{Name: "dup", URL: "https://a.com", Format: "hostfile"},
		{Name: "dup", URL: "https://b.com", Format: "hostfile"},
	}
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for duplicate feed names")
	}
}

func TestThreatFeedsValidation_EmptyFeedName(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.ThreatFeeds.Feeds = []ThreatFeedEntry{
		{Name: "", URL: "https://a.com", Format: "hostfile"},
	}
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for empty feed name")
	}
}

func TestThreatFeedsValidation_EmptyFeedFormat(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.ThreatFeeds.Feeds = []ThreatFeedEntry{
		{Name: "test", URL: "https://a.com", Format: ""},
	}
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for empty feed format")
	}
}
