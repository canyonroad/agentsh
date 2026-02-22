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
// Evaluation order: server-level policy first, then tool-level policy.
func (p *PolicyEvaluator) Evaluate(serverID, toolName, hash string) PolicyDecision {
	if !p.cfg.EnforcePolicy {
		return PolicyDecision{Allowed: true, Reason: "policy enforcement disabled"}
	}

	// 1. Server-level policy check (runs before tool-level)
	if decision, checked := p.evaluateServerPolicy(serverID); checked {
		if !decision.Allowed {
			return decision
		}
	}

	// 2. Tool-level policy check
	switch p.cfg.ToolPolicy {
	case "allowlist":
		return p.evaluateAllowlist(serverID, toolName, hash)
	case "denylist":
		return p.evaluateDenylist(serverID, toolName, hash)
	default:
		return PolicyDecision{Allowed: true, Reason: "no tool policy configured"}
	}
}

// evaluateServerPolicy checks server-level allow/deny rules.
// Returns (decision, true) if a server-level decision was made, or (_, false) if
// no server policy is configured (skip to tool-level).
func (p *PolicyEvaluator) evaluateServerPolicy(serverID string) (PolicyDecision, bool) {
	switch p.cfg.ServerPolicy {
	case "allowlist":
		for _, rule := range p.cfg.AllowedServers {
			if matchesServerRule(rule, serverID) {
				return PolicyDecision{Allowed: true, Reason: "server in allowlist"}, true
			}
		}
		return PolicyDecision{Allowed: false, Reason: "server not in allowlist"}, true

	case "denylist":
		for _, rule := range p.cfg.DeniedServers {
			if matchesServerRule(rule, serverID) {
				return PolicyDecision{Allowed: false, Reason: "server in denylist"}, true
			}
		}
		// Server not denied — pass through to tool-level check
		return PolicyDecision{}, false

	default:
		// No server policy — skip to tool-level
		return PolicyDecision{}, false
	}
}

// matchesServerRule checks if a server ID matches a server rule.
// Supports "*" wildcard to match any server.
func matchesServerRule(rule config.MCPServerRule, serverID string) bool {
	if rule.ID == "*" {
		return true
	}
	return strings.EqualFold(rule.ID, serverID)
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
