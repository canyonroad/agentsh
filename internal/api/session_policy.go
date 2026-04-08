package api

import (
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
)

// policyEngineFor returns the effective policy engine to consult for the given
// session. It prefers the session's own engine (compiled from the session's
// named policy file with per-session variable expansion) and falls back to the
// process-global engine (a.policy) when the session has no engine of its own
// or when s is nil.
//
// This exists to fix canyonroad/agentsh#191: before this helper, the command
// precheck and wrap-time Landlock derivation paths used a.policy directly,
// which silently ignored custom rules authored in any non-default policy file.
// All new call sites that need to consult "the policy for this session" should
// use this helper rather than touching a.policy directly.
func (a *App) policyEngineFor(s *session.Session) *policy.Engine {
	if s != nil {
		if sp := s.PolicyEngine(); sp != nil {
			return sp
		}
	}
	return a.policy
}
