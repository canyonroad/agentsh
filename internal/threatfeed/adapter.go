package threatfeed

import (
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
// The basename is also sanitized to the safe charset [A-Za-z0-9._-] to
// prevent unusual filenames from injecting into rule/message fields.
func redactFeedName(name string) string {
	if strings.HasPrefix(name, "local:") {
		base := filepath.Base(strings.TrimPrefix(name, "local:"))
		return "local:" + sanitizeBasename(base)
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
