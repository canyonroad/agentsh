//go:build windows

package windows

import (
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/gobwas/glob"
)

// RegistryPolicyResponse contains the policy decision for a registry operation.
type RegistryPolicyResponse struct {
	Decision PolicyDecision
	CacheTTL uint32 // milliseconds
	Notify   bool
	LogEvent bool
	RuleName string
	RiskInfo *RegistryPathPolicy // non-nil if high-risk path
}

// compiledRegRule holds a pre-compiled registry policy rule.
type compiledRegRule struct {
	name     string
	globs    []glob.Glob
	ops      map[string]struct{}
	action   PolicyDecision
	priority int
	cacheTTL uint32
	notify   bool
}

// RegistryPolicyEvaluator evaluates registry policy rules.
type RegistryPolicyEvaluator struct {
	mu              sync.RWMutex
	rules           []compiledRegRule
	defaultAction   PolicyDecision
	defaultCacheTTL uint32
	logAll          bool
}

// NewRegistryPolicyEvaluator creates a new evaluator from config.
func NewRegistryPolicyEvaluator(cfg *config.RegistryPolicyConfig) (*RegistryPolicyEvaluator, error) {
	e := &RegistryPolicyEvaluator{
		defaultAction:   DecisionDeny,
		defaultCacheTTL: 30000,
		logAll:          cfg != nil && cfg.LogAll,
	}

	if cfg == nil {
		return e, nil
	}

	switch strings.ToLower(cfg.DefaultAction) {
	case "allow":
		e.defaultAction = DecisionAllow
	case "deny", "":
		e.defaultAction = DecisionDeny
	}

	if cfg.DefaultCacheTTL > 0 {
		e.defaultCacheTTL = uint32(cfg.DefaultCacheTTL) * 1000
	}

	for _, r := range cfg.Rules {
		cr := compiledRegRule{
			name:     r.Name,
			ops:      make(map[string]struct{}),
			priority: r.Priority,
			notify:   r.Notify,
		}

		switch strings.ToLower(r.Action) {
		case "allow":
			cr.action = DecisionAllow
		case "deny":
			cr.action = DecisionDeny
		case "approve":
			cr.action = DecisionPending
		default:
			cr.action = DecisionDeny
		}

		for _, op := range r.Operations {
			cr.ops[strings.ToLower(op)] = struct{}{}
		}

		if r.CacheTTL > 0 {
			cr.cacheTTL = uint32(r.CacheTTL) * 1000
		} else {
			cr.cacheTTL = e.defaultCacheTTL
		}

		for _, pat := range r.Paths {
			escapedPat := strings.ReplaceAll(pat, `\`, `\\`)
			g, err := glob.Compile(escapedPat)
			if err != nil {
				continue
			}
			cr.globs = append(cr.globs, g)
		}

		e.rules = append(e.rules, cr)
	}

	// Sort by priority (higher first)
	for i := 0; i < len(e.rules)-1; i++ {
		for j := i + 1; j < len(e.rules); j++ {
			if e.rules[j].priority > e.rules[i].priority {
				e.rules[i], e.rules[j] = e.rules[j], e.rules[i]
			}
		}
	}

	return e, nil
}

// Evaluate evaluates a registry request against policy rules.
func (e *RegistryPolicyEvaluator) Evaluate(req *RegistryRequest) *RegistryPolicyResponse {
	e.mu.RLock()
	defer e.mu.RUnlock()

	resp := &RegistryPolicyResponse{
		Decision: e.defaultAction,
		CacheTTL: e.defaultCacheTTL,
		LogEvent: e.logAll,
	}

	isHighRisk, riskPolicy := IsHighRiskPath(req.KeyPath)
	if isHighRisk {
		resp.RiskInfo = riskPolicy
		if isWriteOp(req.Operation) {
			resp.Decision = DecisionDeny
			resp.Notify = true
			resp.LogEvent = true
		}
	}

	opStr := driverOpToString(req.Operation)

	for _, r := range e.rules {
		if !matchRegOp(r.ops, opStr) {
			continue
		}
		for _, g := range r.globs {
			if g.Match(req.KeyPath) || g.Match(strings.ToUpper(req.KeyPath)) {
				resp.Decision = r.action
				resp.CacheTTL = r.cacheTTL
				resp.Notify = r.notify
				resp.RuleName = r.name
				resp.LogEvent = e.logAll || r.notify
				return resp
			}
		}
	}

	return resp
}

func isWriteOp(op DriverRegistryOp) bool {
	switch op {
	case DriverRegOpSetValue, DriverRegOpDeleteKey, DriverRegOpDeleteValue, DriverRegOpCreateKey, DriverRegOpRenameKey:
		return true
	default:
		return false
	}
}

func driverOpToString(op DriverRegistryOp) string {
	switch op {
	case DriverRegOpQueryValue:
		return "read"
	case DriverRegOpSetValue:
		return "write"
	case DriverRegOpDeleteKey, DriverRegOpDeleteValue:
		return "delete"
	case DriverRegOpCreateKey:
		return "create"
	case DriverRegOpRenameKey:
		return "rename"
	default:
		return "unknown"
	}
}

func matchRegOp(ops map[string]struct{}, op string) bool {
	if len(ops) == 0 {
		return true
	}
	if _, ok := ops["*"]; ok {
		return true
	}
	_, ok := ops[op]
	return ok
}
