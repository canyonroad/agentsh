//go:build linux

package statemachine

import (
	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

// PolicyClassifier is the minimal classifier surface Transition needs at the
// state-machine boundary. The dispatcher injects a real classify_pg.Parser
// via TransitionWithParser; transition_test.go uses the live parser via
// classify_pg.New(classify_pg.DialectPostgres).
type PolicyClassifier interface {
	Classify(sql string, sess classify_pg.SessionState, opts classify_pg.Options) ([]effects.ClassifiedStatement, error)
}

// Transition is the pure state-transition function. It consumes the current
// ConnState, the next inbound frontend frame, a CacheView (mutated directly
// for Put/Delete/Clear), the active RuleSet, and the per-connection service
// identifier (used to scope policy evaluation). Returns the next state and
// the Action stream the dispatcher must execute.
//
// Plan 05a implements: Sync, Parse, Bind, Describe, Execute, Flush, Close,
// Query (Simple Query), Terminate. Other frame kinds fall through to a
// default-deny path that produces SynthError(0A000) + Close. Plan 05b lifts
// FunctionCall and SQL prepared interception; Plan 05c lifts COPY frames
// and the approval-wait variant.
func Transition(
	s ConnState,
	frame Frame,
	cache CacheView,
	rules *policy.RuleSet,
	svc policy.ServiceID,
) (ConnState, []Action) {
	parser := classify_pg.New(classify_pg.DialectPostgres)
	return TransitionWithParser(s, frame, cache, rules, svc, parser)
}

// TransitionWithParser is the parser-injected variant; tests use it when
// they need to assert against a non-postgres dialect or a mock classifier.
func TransitionWithParser(
	s ConnState,
	frame Frame,
	cache CacheView,
	rules *policy.RuleSet,
	svc policy.ServiceID,
	parser PolicyClassifier,
) (ConnState, []Action) {
	switch f := frame.(type) {
	case *SyncFrame:
		return handleSync(s, f)
	case *QueryFrame:
		return handleQuery(s, f, rules, svc, parser)
	case *ParseFrame:
		return handleParse(s, f, cache, rules, svc, parser)
	case *BindFrame:
		return handleBind(s, f, cache)
	case *DescribeFrame:
		return handleDescribe(s, f)
	case *ExecuteFrame:
		return handleExecute(s, f, cache, rules, svc)
	case *FlushFrame:
		return handleFlush(s, f)
	case *CloseFrame:
		return handleClose(s, f, cache)
	case *TerminateFrame:
		return s, []Action{&ActionForward{}, &ActionClose{}}
	default:
		_ = f
		return s, []Action{
			&ActionSynthError{SQLState: "0A000", Message: "frame not supported"},
			&ActionClose{},
		}
	}
}

func handleSync(s ConnState, _ *SyncFrame) (ConnState, []Action) {
	switch {
	case !s.Absorbing && !s.UpstreamDirtySinceSync:
		// §14.2 case (1): forward and let upstream RFQ pass.
		return s, []Action{&ActionForward{}}
	case s.Absorbing && s.UpstreamDirtySinceSync:
		// §14.2 case (2): forward Sync; dispatcher drains until RFQ.
		next := s
		next.Absorbing = false
		next.UpstreamDirtySinceSync = false
		return next, []Action{&ActionForward{}, &ActionDrainUntilRFQ{}}
	case s.Absorbing && !s.UpstreamDirtySinceSync:
		// §14.2 case (3): synth RFQ(I) locally; reset absorbing.
		next := s
		next.Absorbing = false
		return next, []Action{&ActionSynthReadyForQuery{Status: 'I'}}
	default:
		// Not absorbing but dirty: forward; upstream RFQ flows back.
		return s, []Action{&ActionForward{}}
	}
}

func handleParse(
	s ConnState,
	f *ParseFrame,
	cache CacheView,
	rules *policy.RuleSet,
	svc policy.ServiceID,
	parser PolicyClassifier,
) (ConnState, []Action) {
	if s.Absorbing {
		return s, []Action{&ActionSuppress{}}
	}
	stmts, _ := parser.Classify(f.SQL, classify_pg.SessionState{}, classify_pg.Options{})
	anyDeny := false
	var denyDecision policy.Decision
	var denyRule policy.StatementRule
	for _, cs := range stmts {
		d := policy.Evaluate(cs, rules, svc)
		if d.Verb == policy.VerbApprove {
			// Plan 05a still stubs approve as deny + APPROVE_NOT_YET_SUPPORTED.
			d.Verb = policy.VerbDeny
			if d.Reason == "" {
				d.Reason = "APPROVE_NOT_YET_SUPPORTED"
			}
		}
		if d.Verb == policy.VerbDeny {
			anyDeny = true
			denyDecision = d
			denyRule = lookupStatementRule(rules, d.RuleName)
			break
		}
	}
	if anyDeny {
		msg := renderDenyMessage(denyDecision)
		actions := DenyRoute(s, denyRule, msg, sqlstateForDecision(denyDecision))
		next := s
		// Don't enter absorbing if Close is part of the action list — the
		// connection is going away. Otherwise set Absorbing.
		if !containsClose(actions) {
			next.Absorbing = true
		}
		return next, actions
	}
	// Allow path: Forward, mutate cache directly.
	verb := ""
	if len(stmts) > 0 {
		verb = stmts[0].RawVerb
	}
	var groupID uint8
	if len(stmts) > 0 && len(stmts[0].Effects) > 0 {
		groupID = uint8(stmts[0].Effects[0].Group)
	}
	cache.Put(f.Name, CacheValue{Verb: verb, GroupID: groupID})
	next := s
	next.UpstreamDirtySinceSync = true
	return next, []Action{&ActionForward{}}
}

func handleBind(s ConnState, f *BindFrame, cache CacheView) (ConnState, []Action) {
	if s.Absorbing {
		return s, []Action{&ActionSuppress{}}
	}
	if _, ok := cache.Get(f.Statement); !ok {
		next := s
		next.Absorbing = true
		return next, []Action{
			&ActionSynthError{SQLState: "34000", Message: "prepared statement \"" + f.Statement + "\" does not exist"},
		}
	}
	next := s
	next.UpstreamDirtySinceSync = true
	return next, []Action{&ActionForward{}}
}

func handleDescribe(s ConnState, _ *DescribeFrame) (ConnState, []Action) {
	if s.Absorbing {
		return s, []Action{&ActionSuppress{}}
	}
	next := s
	next.UpstreamDirtySinceSync = true
	return next, []Action{&ActionForward{}}
}

func handleExecute(
	s ConnState, f *ExecuteFrame, cache CacheView,
	rules *policy.RuleSet, svc policy.ServiceID,
) (ConnState, []Action) {
	if s.Absorbing {
		return s, []Action{&ActionSuppress{}}
	}
	// Portal name → prepared-statement classification. Plan 05a does not
	// maintain a portal→statement map separately; the client-issued portal
	// name is used as the cache key directly. In the typical pgx pipeline
	// the portal name == statement name. Plan 05b adds a portal map for
	// workloads that use distinct portal/statement names.
	if _, ok := cache.Get(f.Portal); !ok {
		next := s
		next.Absorbing = true
		return next, []Action{
			&ActionSynthError{SQLState: "34000", Message: "portal \"" + f.Portal + "\" does not exist"},
		}
	}
	_ = rules
	_ = svc
	// Plan 05a's wire prepared cache was populated only on Parse-allow,
	// so a cache hit implies the cached statement was allowed under the
	// rules in effect at Parse time. Plan 05b lifts the re-eval surface.
	next := s
	next.UpstreamDirtySinceSync = true
	return next, []Action{&ActionForward{}}
}

func handleFlush(s ConnState, _ *FlushFrame) (ConnState, []Action) {
	if s.Absorbing {
		return s, []Action{&ActionSuppress{}}
	}
	return s, []Action{&ActionForward{}}
}

func handleClose(s ConnState, f *CloseFrame, cache CacheView) (ConnState, []Action) {
	if s.Absorbing {
		return s, []Action{&ActionSuppress{}}
	}
	if f.ObjectType == 'S' {
		cache.Delete(f.Name)
	}
	next := s
	next.UpstreamDirtySinceSync = true
	return next, []Action{&ActionForward{}}
}

func handleQuery(
	s ConnState, f *QueryFrame,
	rules *policy.RuleSet, svc policy.ServiceID,
	parser PolicyClassifier,
) (ConnState, []Action) {
	stmts, _ := parser.Classify(f.SQL, classify_pg.SessionState{}, classify_pg.Options{})
	var denyDecision policy.Decision
	var denyRule policy.StatementRule
	anyDeny := false
	for _, cs := range stmts {
		d := policy.Evaluate(cs, rules, svc)
		if d.Verb == policy.VerbApprove {
			d.Verb = policy.VerbDeny
			if d.Reason == "" {
				d.Reason = "APPROVE_NOT_YET_SUPPORTED"
			}
		}
		if d.Verb == policy.VerbDeny {
			anyDeny = true
			denyDecision = d
			denyRule = lookupStatementRule(rules, d.RuleName)
			break
		}
	}
	if !anyDeny {
		// Q is atomic per Sync; no Absorbing change on allow.
		return s, []Action{&ActionForward{}}
	}
	msg := renderDenyMessage(denyDecision)
	actions := DenyRoute(s, denyRule, msg, sqlstateForDecision(denyDecision))
	return s, actions
}

// lookupStatementRule finds the named rule in rs.AllStatementRules().
// RuleName == "" returns the zero StatementRule, which is fine for
// implicit-deny: DenyModeInTx is empty (== terminate).
func lookupStatementRule(rs *policy.RuleSet, name string) policy.StatementRule {
	if rs == nil || name == "" {
		return policy.StatementRule{}
	}
	for _, r := range rs.AllStatementRules() {
		if r.Name == name {
			return r
		}
	}
	return policy.StatementRule{}
}

func renderDenyMessage(d policy.Decision) string {
	if d.RuleName != "" {
		return "denied by AgentSH policy: " + d.RuleName
	}
	if d.Reason != "" {
		return "denied by AgentSH policy: " + d.Reason
	}
	return "denied by AgentSH policy"
}

func sqlstateForDecision(d policy.Decision) string {
	if d.RuleKind == policy.RuleKindConnection {
		return "28000"
	}
	return "42501"
}

func containsClose(acts []Action) bool {
	for _, a := range acts {
		if _, ok := a.(*ActionClose); ok {
			return true
		}
	}
	return false
}
