package policy

import "github.com/agentsh/agentsh/internal/db/effects"

// EvaluateConnection applies connection-rule policy to a candidate connection.
// Returns implicit deny if no rule matches.
func EvaluateConnection(info ConnectionInfo, rs *RuleSet) Decision {
	if rs == nil {
		return Decision{
			Verb:                VerbDeny,
			RuleKind:            connectionRuleKindFor(info.MatchKind),
			MatchingEffectIndex: -1,
			MatchingEffectGroup: effects.GroupUnknown,
			Reason:              "policy not loaded",
		}
	}
	var matched []*compiledConnectionRule
	for _, r := range rs.connection {
		if r.matchKind != info.MatchKind {
			continue
		}
		if r.serviceFilter.service != "" && r.serviceFilter.service != info.Service {
			continue
		}
		if !connRuleMatchesInfo(r, info) {
			continue
		}
		matched = append(matched, r)
	}

	if len(matched) == 0 {
		return Decision{
			Verb:                VerbDeny,
			RuleKind:            connectionRuleKindFor(info.MatchKind),
			MatchingEffectIndex: -1,
			MatchingEffectGroup: effects.GroupUnknown,
			Reason:              "no connection rule matched",
		}
	}

	best := matched[0]
	for _, r := range matched[1:] {
		if compareConnVerb(r.verb, best.verb) > 0 {
			best = r
		}
	}
	d := Decision{
		Verb:                best.verb,
		RuleKind:            connectionRuleKindFor(info.MatchKind),
		RuleName:            best.src.Name,
		MatchingEffectIndex: -1,
		MatchingEffectGroup: effects.GroupUnknown,
		Reason: best.renderMessage(messageContext{
			Operation: connKindString(info.MatchKind),
		}),
	}
	if best.verb == VerbApprove {
		d.Approval = &ApprovalRequest{
			Timeout:                  best.timeout,
			ContributingApproveRules: []string{best.src.Name},
		}
	}
	return d
}

func connRuleMatchesInfo(r *compiledConnectionRule, info ConnectionInfo) bool {
	if len(r.dbUsers) > 0 {
		if _, ok := r.dbUsers[info.DBUser]; !ok {
			return false
		}
	}
	if r.database != "" && r.database != info.Database {
		return false
	}
	if r.applicationName != nil && !r.applicationName.Match(info.ApplicationName) {
		return false
	}
	if r.clientIdentity != nil && !r.clientIdentity.Match(info.ClientIdentity) {
		return false
	}
	return true
}

func connectionRuleKindFor(mk ConnectionMatchKind) RuleKind {
	switch mk {
	case MatchCancel:
		return RuleKindCancel
	default:
		return RuleKindConnection
	}
}

func connKindString(mk ConnectionMatchKind) string {
	switch mk {
	case MatchConnect:
		return "connect"
	case MatchCancel:
		return "cancel"
	case MatchReplication:
		return "replication"
	default:
		return ""
	}
}

// compareConnVerb: most-restrictive ordering for connection-level verbs.
// allow < audit < approve < deny
func compareConnVerb(a, b DecisionVerb) int {
	rank := func(v DecisionVerb) int {
		switch v {
		case VerbAllow:
			return 0
		case VerbAudit:
			return 1
		case VerbApprove:
			return 2
		case VerbDeny:
			return 3
		}
		return -1
	}
	return rank(a) - rank(b)
}
