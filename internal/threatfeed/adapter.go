package threatfeed

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/agentsh/agentsh/internal/policy"
)

// PolicyAdapter adapts a Store to the policy.ThreatChecker interface.
type PolicyAdapter struct {
	Store *Store
}

// Check implements policy.ThreatChecker.
func (a *PolicyAdapter) Check(domain string) (policy.ThreatCheckResult, bool) {
	if a == nil || a.Store == nil {
		return policy.ThreatCheckResult{}, false
	}
	entry, matched := a.Store.Check(domain)
	if !matched {
		return policy.ThreatCheckResult{}, false
	}
	return policy.ThreatCheckResult{
		FeedName:      redactFeedName(entry.FeedName),
		MatchedDomain: entry.MatchedDomain,
	}, true
}

// redactFeedName strips directory paths from local list feed names so that
// filesystem paths are not exposed in policy decisions, logs, or events.
// The basename is sanitized and a short hash of the full path is appended
// to distinguish local lists that share the same basename.
func redactFeedName(name string) string {
	if strings.HasPrefix(name, "local:") {
		fullPath := strings.TrimPrefix(name, "local:")
		base := sanitizeBasename(filepath.Base(fullPath))
		h := sha256.Sum256([]byte(fullPath))
		suffix := hex.EncodeToString(h[:4]) // 8 hex chars
		return "local:" + base + "." + suffix
	}
	return name
}

// sanitizeBasename replaces characters outside [A-Za-z0-9._-] with underscores.
func sanitizeBasename(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
