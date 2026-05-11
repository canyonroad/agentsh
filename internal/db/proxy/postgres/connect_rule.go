//go:build linux

package postgres

import (
	"context"

	"github.com/agentsh/agentsh/internal/db/policy"
)

// evaluateConnection runs Plan 02's connection-rule evaluator with the
// given match_kind against the parsed StartupMessage state. Returns the
// Decision so callers can choose between allow-path and deny-path.
func (pc *proxyConn) evaluateConnection(_ context.Context, mk policy.ConnectionMatchKind) policy.Decision {
	return policy.EvaluateConnection(policy.ConnectionInfo{
		Service:         policy.ServiceID(pc.svc.Name),
		MatchKind:       mk,
		DBUser:          pc.state.dbUser,
		Database:        pc.state.database,
		ApplicationName: pc.state.appName,
		ClientIdentity:  pc.state.clientIdentity,
	}, pc.srv.cfg.Policy)
}

// evaluateConnect is the original 04b helper kept as a thin wrapper around
// evaluateConnection(MatchConnect) so existing callers compile unchanged.
func (pc *proxyConn) evaluateConnect(ctx context.Context) policy.Decision {
	return pc.evaluateConnection(ctx, policy.MatchConnect)
}

// evaluateReplication is the match_kind=replication entry point.
func (pc *proxyConn) evaluateReplication(ctx context.Context) policy.Decision {
	return pc.evaluateConnection(ctx, policy.MatchReplication)
}

// evaluateCancel is the match_kind=cancel entry point.
func (pc *proxyConn) evaluateCancel(ctx context.Context) policy.Decision {
	return pc.evaluateConnection(ctx, policy.MatchCancel)
}
