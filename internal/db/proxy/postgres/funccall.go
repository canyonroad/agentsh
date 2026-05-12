//go:build linux

package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

// handleFunctionCall handles an 'F' FunctionCall frame. Default behavior
// (when the live policy's DBService.AllowFunctionCallProtocol is false) preserves
// 04c's 42501 stub: emit lifecycle event, synth FATAL error, return errUnsupportedFrame.
// Opt-in behavior classifies as procedural/function_call_protocol with FunctionOID,
// evaluates, and either forwards or routes through DenyRoute.
func (pc *proxyConn) handleFunctionCall(ctx context.Context, msg *pgproto3.FunctionCall) error {
	// Always read from the live policy so that YAML changes take effect without
	// a server restart.  If the service is not found in the policy (nil RuleSet
	// or missing entry) AllowFunctionCallProtocol defaults to false.
	rs := pc.srv.policy()
	liveSvc, _ := rs.Service(policy.ServiceID(pc.svc.Name))
	if !liveSvc.AllowFunctionCallProtocol {
		// 04c default path: preserve the existing stub behavior from handleUnsupportedFrame.
		pc.emitUnsupportedFrame(ctx, "FUNCTION_CALL_PROTOCOL_DENIED", "FunctionCall")
		_ = pc.synthesizeError(sqlstateInsufficientPrivilege, "FunctionCall sub-protocol denied by AgentSH policy")
		return errUnsupportedFrame
	}

	// Opt-in: build the ClassifiedStatement, evaluate, route.
	oid := int32(msg.Function)
	cs := effects.ClassifiedStatement{
		RawVerb: "FUNCTION_CALL",
		Effects: []effects.Effect{{
			Group:       effects.GroupProcedural,
			Subtype:     effects.SubtypeFunctionCallProtocol,
			FunctionOID: &oid,
		}},
	}
	d := policy.Evaluate(cs, rs, policy.ServiceID(pc.svc.Name))
	if d.Verb == policy.VerbApprove {
		d = synthApproveAsDeny(d)
	}

	if d.Verb == policy.VerbDeny {
		denyRule := lookupStatementRuleByName(rs, d.RuleName)
		da := denyActionForState(pc.state.smState, denyRule)
		// Deny path has no upstream round-trip; pass zero-valued result.
		pc.emitFunctionCallEvent(ctx, cs, d, da, upstreamResult{})
		denyMsg := renderDenyMessage(d)
		actions := statemachine.DenyRoute(*pc.state.smState, denyRule, denyMsg, sqlstateInsufficientPrivilege)
		return pc.executeActions(ctx, msg, actions)
	}

	// Allow path: forward to upstream.
	pc.state.upstreamFE.Send(msg)
	if err := pc.state.upstreamFE.Flush(); err != nil {
		return err
	}
	// Drain upstream until RFQ; emit allow event with result counters.
	result, ferr := pc.forwardUpstreamUntilRFQ(ctx, timeNow(), 0)
	pc.emitFunctionCallEvent(ctx, cs, d, "none", result)
	return ferr
}

// emitFunctionCallEvent emits one db_statement event for a FunctionCall frame.
// The FunctionCall has no SQL string so we pass an empty string; the event's
// Effects + RawVerb carry the semantically meaningful information.
// r carries BytesOut and LatencyMs from the upstream round-trip (zero-valued
// for the deny path, which has no upstream interaction).
func (pc *proxyConn) emitFunctionCallEvent(
	ctx context.Context,
	cs effects.ClassifiedStatement,
	d policy.Decision,
	denyAction string,
	r upstreamResult,
) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	ev := buildStatementEvent(buildArgs{
		Stmt:       cs,
		StmtIndex:  0,
		BatchTotal: 1,
		Decision:   d,
		SQL:        "",
		Tier:       pc.state.redactionTier,
		Conn:       *pc.state,
		BytesIn:    0,  // FunctionCall frames carry no SQL body to measure
		BytesOut:   r.BytesOut,
		LatencyMs:  r.LatencyMs,
		DenyAction: denyAction,
		BatchSHA:   "", // FunctionCall frames have no SQL body to hash
		Parser:     pc.srv.classifierFor(pc.svc.Dialect),
	})
	if err := pc.srv.cfg.Sink.EmitStatement(ctx, ev); err != nil {
		pc.logger.Warn("emit function call event failed", "err", err)
	}
}
