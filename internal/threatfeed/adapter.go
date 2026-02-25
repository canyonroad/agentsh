package threatfeed

import "github.com/agentsh/agentsh/internal/policy"

// PolicyAdapter adapts a Store to the policy.ThreatChecker interface.
type PolicyAdapter struct {
	Store *Store
}

// Check implements policy.ThreatChecker.
func (a *PolicyAdapter) Check(domain string) (policy.ThreatCheckResult, bool) {
	entry, matched := a.Store.Check(domain)
	if !matched {
		return policy.ThreatCheckResult{}, false
	}
	return policy.ThreatCheckResult{
		FeedName:      entry.FeedName,
		MatchedDomain: entry.MatchedDomain,
	}, true
}
