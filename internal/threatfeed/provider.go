package threatfeed

import "context"

// Provider defines the interface for real-time domain threat checking.
// This is reserved for the paid tier (Web Risk API, VirusTotal, etc.)
// and is not implemented in v1.
type Provider interface {
	Check(ctx context.Context, domain string) (ThreatResult, error)
	Name() string
}

// ThreatResult holds the result of a real-time threat check.
type ThreatResult struct {
	Matched    bool
	FeedName   string
	ThreatType string // "malware", "phishing", "unwanted", etc.
}
