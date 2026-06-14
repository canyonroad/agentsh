package tor

import (
	"net"

	"github.com/agentsh/agentsh/internal/policy"
)

// PolicyAdapter adapts *Policy to policy.TorChecker (policy→tor would be
// an import cycle, so the bridge lives here, like threatfeed.PolicyAdapter).
type PolicyAdapter struct {
	Policy *Policy
}

func conv(v Verdict, ok bool) (policy.TorVerdict, bool) {
	if !ok {
		return policy.TorVerdict{}, false
	}
	return policy.TorVerdict{Vector: v.Vector, Mode: v.Mode, Decision: v.Decision, Target: v.Target}, true
}

func (a *PolicyAdapter) EvalExecve(filename string, argv []string) (policy.TorVerdict, bool) {
	if a == nil || a.Policy == nil {
		return policy.TorVerdict{}, false
	}
	return conv(a.Policy.EvalExecve(filename, argv))
}

func (a *PolicyAdapter) EvalConnect(ip net.IP, port int) (policy.TorVerdict, bool) {
	if a == nil || a.Policy == nil {
		return policy.TorVerdict{}, false
	}
	return conv(a.Policy.EvalConnect(ip, port))
}

func (a *PolicyAdapter) EvalOnionName(host string) (policy.TorVerdict, bool) {
	if a == nil || a.Policy == nil {
		return policy.TorVerdict{}, false
	}
	return conv(a.Policy.EvalOnionName(host))
}
