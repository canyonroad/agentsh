//go:build linux

package postgres

import (
	"context"

	"github.com/agentsh/agentsh/internal/db/policy"
)

// evaluateConnect runs Plan 02's connection-rule evaluator with
// match_kind=connect against the parsed StartupMessage state. Returns
// the Decision so callers can choose between allow-path (synthesize
// not-yet-wired) and deny-path (§13.3 deny synthesis).
func (pc *proxyConn) evaluateConnect(_ context.Context) policy.Decision {
	return policy.EvaluateConnection(policy.ConnectionInfo{
		Service:         policy.ServiceID(pc.svc.Name),
		MatchKind:       policy.MatchConnect,
		DBUser:          pc.state.dbUser,
		Database:        pc.state.database,
		ApplicationName: pc.state.appName,
		ClientIdentity:  pc.state.clientIdentity,
	}, pc.srv.cfg.Policy)
}
