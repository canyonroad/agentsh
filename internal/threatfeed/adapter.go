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
func redactFeedName(name string) string {
	if strings.HasPrefix(name, "local:") {
		return "local:" + filepath.Base(strings.TrimPrefix(name, "local:"))
	}
	return name
}
