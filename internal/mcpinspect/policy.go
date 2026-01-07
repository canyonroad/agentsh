package mcpinspect

import (
	"strings"

	"github.com/agentsh/agentsh/internal/config"
)

// PolicyDecision represents the result of a policy evaluation.
type PolicyDecision struct {
	Allowed bool
	Reason  string
	Rule    *config.MCPToolRule // The rule that matched, if any
}

// PolicyEvaluator evaluates MCP tool access based on configured policies.
type PolicyEvaluator struct {
	cfg config.SandboxMCPConfig
}

// NewPolicyEvaluator creates a new policy evaluator.
func NewPolicyEvaluator(cfg config.SandboxMCPConfig) *PolicyEvaluator {
	return &PolicyEvaluator{cfg: cfg}
}

// IsAllowed checks if a tool invocation is permitted.
func (p *PolicyEvaluator) IsAllowed(serverID, toolName string) bool {
	decision := p.Evaluate(serverID, toolName, "")
	return decision.Allowed
}

// IsAllowedWithHash checks if a tool invocation is permitted with hash verification.
func (p *PolicyEvaluator) IsAllowedWithHash(serverID, toolName, hash string) bool {
	decision := p.Evaluate(serverID, toolName, hash)
	return decision.Allowed
}

// Evaluate performs a full policy evaluation and returns the decision.
func (p *PolicyEvaluator) Evaluate(serverID, toolName, hash string) PolicyDecision {
	if !p.cfg.EnforcePolicy {
		return PolicyDecision{Allowed: true, Reason: "policy enforcement disabled"}
	}

	switch p.cfg.ToolPolicy {
	case "allowlist":
		return p.evaluateAllowlist(serverID, toolName, hash)
	case "denylist":
		return p.evaluateDenylist(serverID, toolName, hash)
	default:
		return PolicyDecision{Allowed: true, Reason: "no policy configured"}
	}
}

func (p *PolicyEvaluator) evaluateAllowlist(serverID, toolName, hash string) PolicyDecision {
	for _, rule := range p.cfg.AllowedTools {
		if p.matchesRule(rule, serverID, toolName, hash) {
			return PolicyDecision{Allowed: true, Reason: "matched allowlist rule", Rule: &rule}
		}
	}
	if p.cfg.FailClosed {
		return PolicyDecision{Allowed: false, Reason: "no matching allowlist rule (fail closed)"}
	}
	return PolicyDecision{Allowed: false, Reason: "no matching allowlist rule"}
}

func (p *PolicyEvaluator) evaluateDenylist(serverID, toolName, hash string) PolicyDecision {
	for _, rule := range p.cfg.DeniedTools {
		if p.matchesRule(rule, serverID, toolName, hash) {
			return PolicyDecision{Allowed: false, Reason: "matched denylist rule", Rule: &rule}
		}
	}
	return PolicyDecision{Allowed: true, Reason: "no matching denylist rule"}
}

func (p *PolicyEvaluator) matchesRule(rule config.MCPToolRule, serverID, toolName, hash string) bool {
	// Check server match
	if rule.Server != "*" && !strings.EqualFold(rule.Server, serverID) {
		return false
	}

	// Check tool match
	if rule.Tool != "*" && !strings.EqualFold(rule.Tool, toolName) {
		return false
	}

	// Check hash if specified in rule
	if rule.ContentHash != "" && rule.ContentHash != hash {
		return false
	}

	return true
}
