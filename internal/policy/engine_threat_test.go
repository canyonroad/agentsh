package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentsh/agentsh/pkg/types"
)

// mockThreatStore implements ThreatChecker for testing.
type mockThreatStore struct {
	domains map[string]ThreatCheckResult
}

func (m *mockThreatStore) Check(domain string) (ThreatCheckResult, bool) {
	// Exact match first
	if entry, ok := m.domains[domain]; ok {
		return entry, true
	}
	// Walk parent domains (same logic as threatfeed.Store)
	d := domain
	for {
		idx := 0
		for i, c := range d {
			if c == '.' {
				idx = i
				break
			}
		}
		if idx == 0 {
			break
		}
		d = d[idx+1:]
		if d == "" {
			break
		}
		// Skip bare TLDs
		hasDot := false
		for _, c := range d {
			if c == '.' {
				hasDot = true
				break
			}
		}
		if !hasDot {
			break
		}
		if entry, ok := m.domains[d]; ok {
			return entry, true
		}
	}
	return ThreatCheckResult{}, false
}

func TestCheckNetworkCtx_ThreatFeedDeny(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	store := &mockThreatStore{domains: map[string]ThreatCheckResult{
		"evil.com": {FeedName: "urlhaus", MatchedDomain: "evil.com"},
	}}
	e.SetThreatStore(store, "deny")

	dec := e.CheckNetworkCtx(context.Background(), "evil.com", 443)
	assert.Equal(t, types.DecisionDeny, dec.EffectiveDecision)
	assert.Equal(t, "threat-feed:urlhaus", dec.Rule)
}

func TestCheckNetworkCtx_ThreatFeedAudit(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	store := &mockThreatStore{domains: map[string]ThreatCheckResult{
		"evil.com": {FeedName: "urlhaus", MatchedDomain: "evil.com"},
	}}
	e.SetThreatStore(store, "audit")

	dec := e.CheckNetworkCtx(context.Background(), "evil.com", 443)
	assert.Equal(t, types.DecisionAudit, dec.PolicyDecision)
	assert.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	assert.Equal(t, "threat-feed:urlhaus", dec.Rule)
}

func TestCheckNetworkCtx_ThreatFeedNoMatchFallsThrough(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "deny-bad", Domains: []string{"bad.org"}, Decision: "deny"},
		{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	store := &mockThreatStore{domains: map[string]ThreatCheckResult{
		"evil.com": {FeedName: "urlhaus", MatchedDomain: "evil.com"},
	}}
	e.SetThreatStore(store, "deny")

	dec := e.CheckNetworkCtx(context.Background(), "safe.com", 443)
	assert.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	assert.Equal(t, "allow-all", dec.Rule)
}

func TestCheckNetworkCtx_NilThreatStoreSkipsCheck(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	dec := e.CheckNetworkCtx(context.Background(), "evil.com", 443)
	assert.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	assert.Equal(t, "allow-all", dec.Rule)
}

func TestCheckNetworkCtx_ThreatFeedParentDomainMatch(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	store := &mockThreatStore{domains: map[string]ThreatCheckResult{
		"evil.com": {FeedName: "urlhaus", MatchedDomain: "evil.com"},
	}}
	e.SetThreatStore(store, "deny")

	dec := e.CheckNetworkCtx(context.Background(), "sub.evil.com", 443)
	assert.Equal(t, types.DecisionDeny, dec.EffectiveDecision)
	assert.Equal(t, "threat-feed:urlhaus", dec.Rule)
	assert.Contains(t, dec.Message, "evil.com")
}

func TestCheckNetworkCtx_ThreatFeedFields(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	store := &mockThreatStore{domains: map[string]ThreatCheckResult{
		"evil.com": {FeedName: "urlhaus", MatchedDomain: "evil.com"},
	}}
	e.SetThreatStore(store, "deny")

	dec := e.CheckNetworkCtx(context.Background(), "sub.evil.com", 443)
	assert.Equal(t, "urlhaus", dec.ThreatFeed)
	assert.Equal(t, "evil.com", dec.ThreatMatch)
}

func TestCheckNetworkIP_ThreatFeedDeny(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	store := &mockThreatStore{domains: map[string]ThreatCheckResult{
		"evil.com": {FeedName: "urlhaus", MatchedDomain: "evil.com"},
	}}
	e.SetThreatStore(store, "deny")

	dec := e.CheckNetworkIP("evil.com", nil, 443)
	assert.Equal(t, types.DecisionDeny, dec.EffectiveDecision)
	assert.Equal(t, "threat-feed:urlhaus", dec.Rule)
}

func TestSetThreatStore_InvalidActionDefaultsToDeny(t *testing.T) {
	p := &Policy{Version: 1, Name: "test", NetworkRules: []NetworkRule{
		{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	store := &mockThreatStore{domains: map[string]ThreatCheckResult{
		"evil.com": {FeedName: "urlhaus", MatchedDomain: "evil.com"},
	}}
	e.SetThreatStore(store, "typo-dney")

	dec := e.CheckNetworkCtx(context.Background(), "evil.com", 443)
	assert.Equal(t, types.DecisionDeny, dec.EffectiveDecision, "invalid action should default to deny")
}
