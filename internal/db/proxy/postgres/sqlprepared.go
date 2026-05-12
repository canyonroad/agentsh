//go:build linux

package postgres

import (
	"strings"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/preparedcache"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

// Intercept implements the spec §7.4 SQL-level prepared statement plus
// §9.2 R1 DISCARD coverage on the Simple Query path. Called from handleQuery
// after classify and evaluate; mutates the cache, may rewrite stmts[0] in
// place (for EXECUTE cache hits), and signals whether the caller still
// needs to forward the Q frame.
//
// Returns Handled=true with an Action sequence when the proxy must NOT
// forward to upstream — currently:
//   - PREPARE deny: cache untouched; emit DenyRoute.
//   - EXECUTE cache miss: emit SynthError + RFQ.
//
// Returns Handled=false when the caller should continue with its normal
// forward path. In that case, stmts[0] may have been rewritten:
//   - PREPARE allow/audit: cache populated; stmts unchanged.
//   - EXECUTE cache hit: stmts[0] replaced with cached classification so the
//     caller's subsequent Evaluate sees the right effect set.
//   - DEALLOCATE: cache entry removed (or cleared); stmts unchanged.
//   - DISCARD ALL / DISCARD PLANS: cache cleared; stmts unchanged.
//   - DISCARD TEMP / DISCARD SEQUENCES: no cache change; stmts unchanged.
//   - Any other RawVerb: no-op.
//
// `decisions` may be nil for verbs that don't require a prior evaluation
// (EXECUTE — the cached classification is the source of truth for re-eval
// inside the caller). `rs` may be nil in pure-unit tests; the deny path
// then falls through with a zero-valued StatementRule.
func Intercept(
	stmts []effects.ClassifiedStatement,
	decisions []policy.Decision,
	cache *preparedcache.Cache,
	s statemachine.ConnState,
	rs *policy.RuleSet,
) (handled bool, actions []statemachine.Action) {
	if len(stmts) == 0 {
		return false, nil
	}
	first := &stmts[0]

	switch {
	case strings.HasPrefix(first.RawVerb, "PREPARE"):
		// PREPARE name AS <inner>. RawVerb is "PREPARE" (no inner) or
		// "PREPARE_<INNER_VERB>". Decisions[0] is the inner-stmt result.
		if len(decisions) > 0 && decisions[0].Verb == policy.VerbDeny {
			rule := lookupStatementRuleByName(rs, decisions[0].RuleName)
			msg := "denied by AgentSH policy: " + decisions[0].RuleName
			return true, statemachine.DenyRoute(s, rule, msg, "42501")
		}
		// Allow path: populate cache with inner classification.
		inner := *first
		inner.RawVerb = strings.TrimPrefix(first.RawVerb, "PREPARE_")
		inner.PreparedName = ""
		cache.Put(first.PreparedName, preparedcache.Entry{Classification: inner})
		return false, nil

	case first.RawVerb == "EXECUTE":
		e, ok := cache.Get(first.PreparedName)
		if !ok {
			return true, []statemachine.Action{
				&statemachine.ActionSynthError{
					SQLState: "26000",
					Message:  "SQL_PREPARED_CACHE_MISS: prepared statement \"" + first.PreparedName + "\" does not exist in AgentSH proxy cache",
				},
				&statemachine.ActionSynthReadyForQuery{Status: 'I'},
			}
		}
		// Rewrite stmts[0] with cached classification so the caller's
		// downstream Evaluate sees the inner effect set, not Unknown.
		first.Effects = e.Classification.Effects
		first.Error = ""
		return false, nil

	case first.RawVerb == "DEALLOCATE":
		if first.PreparedName == "" {
			cache.Clear()
		} else {
			cache.Delete(first.PreparedName)
		}
		return false, nil

	case first.RawVerb == "DISCARD":
		if len(first.Effects) > 0 {
			switch first.Effects[0].Subtype {
			case effects.SubtypeDiscardAll, effects.SubtypeDiscardPlans:
				cache.Clear()
			}
		}
		return false, nil
	}

	return false, nil
}
