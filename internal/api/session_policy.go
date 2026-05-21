package api

import (
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
)

// policyEngineFor returns the effective policy engine to consult for the given
// session. It prefers the session's own engine (compiled from the session's
// named policy file with per-session variable expansion) and falls back to the
// process-global engine (a.Policy()) when the session has no engine of its own
// or when s is nil.
//
// Reads the global engine via a.Policy() so a SwapPolicy by the WTP
// pushed-policy install hook is observed by every subsequent session.
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
	return a.Policy()
}

// Policy returns the current process-global policy engine. Read under
// the App's RWMutex so a concurrent SwapPolicy doesn't race against
// the pointer assignment.
func (a *App) Policy() *policy.Engine {
	a.policyMu.RLock()
	defer a.policyMu.RUnlock()
	return a.policy
}

// SwapPolicy atomically replaces the process-global policy engine.
// Used by the WTP pushed-policy install hook after Manager.Reload
// produces a fresh *policy.Policy and NewEngine wraps it. Returns the
// previous engine so callers can decide whether to tear down
// engine-bound resources (none today, but kept for symmetry with the
// signal-handler integration roadmap).
//
// Note: long-lived components that captured the prior engine pointer
// at construction time (today: the network proxy, transparent TCP
// interceptor, DNS interceptor) will NOT observe this swap. The
// command-time CheckCommand / CheckExecve / CheckFile paths that run
// through a.policyEngineFor DO observe it on the next decision, which
// is what the demo (curl allowed → curl blocked at exec) depends on.
func (a *App) SwapPolicy(eng *policy.Engine) *policy.Engine {
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	prev := a.policy
	a.policy = eng
	return prev
}
