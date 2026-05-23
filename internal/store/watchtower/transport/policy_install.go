package transport

import (
	"context"
	"log/slog"

	wtpv1 "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1"
)

// applyPushedPolicy hands a PolicyPushed payload to the caller-supplied
// OnPolicyPushed hook. Used by both the SessionAck install path
// (state_connecting.go) and the mid-session PolicyPush path
// (state_live.go). The hook itself is idempotent — re-delivering the
// same (policy_id, content_hash) is a no-op on the agent.
//
// source is a free-form label included in the log line; values are
// "session_ack" or "policy_push" so an operator can tell which arm
// installed the policy.
func (t *Transport) applyPushedPolicy(ctx context.Context, p PolicyPushed, source string) {
	t.opts.Logger.LogAttrs(ctx, slog.LevelInfo,
		"wtp: applying pushed policy",
		slog.String("source", source),
		slog.String("policy_id", p.PolicyID),
		slog.Uint64("policy_version", uint64(p.PolicyVersion)),
		slog.String("policy_content_hash", p.ContentHash),
		slog.Int("policy_content_len", len(p.Content)),
		slog.Int("policy_signature_len", len(p.Signature)),
		slog.String("policy_signer_key_id", p.SignerKeyID),
		slog.String("session_id", t.opts.SessionID))
	if cb := t.opts.OnPolicyPushed; cb != nil {
		cb(p)
	}
}

// fromWirePolicyPush copies a wire *wtpv1.PolicyPush into the agent's
// internal PolicyPushed shape. Field semantics are 1:1 with the
// equivalent SessionAck policy_* fields so a single install hook can
// service both arms.
func fromWirePolicyPush(pp *wtpv1.PolicyPush) PolicyPushed {
	return PolicyPushed{
		PolicyID:      pp.GetPolicyId(),
		PolicyVersion: pp.GetPolicyVersion(),
		ContentHash:   pp.GetPolicyContentHash(),
		Content:       pp.GetPolicyContent(),
		Signature:     pp.GetPolicySignature(),
		SignerKeyID:   pp.GetPolicySignerKeyId(),
		OverlayIDs:    pp.GetOverlayIds(),
	}
}
