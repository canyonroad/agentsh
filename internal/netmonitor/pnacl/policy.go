package pnacl

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gobwas/glob"
)

// Decision represents a policy decision for a network connection.
type Decision string

const (
	// DecisionAllow permits the connection silently.
	DecisionAllow Decision = "allow"
	// DecisionDeny blocks the connection silently.
	DecisionDeny Decision = "deny"
	// DecisionApprove blocks and prompts the user for approval.
	DecisionApprove Decision = "approve"
	// DecisionAllowOnceThenApprove allows first connection, then prompts.
	DecisionAllowOnceThenApprove Decision = "allow_once_then_approve"
	// DecisionAudit allows but logs for review.
	DecisionAudit Decision = "audit"
)

// NetworkTarget specifies allowed/denied network destinations.
type NetworkTarget struct {
	// Host is the hostname pattern with glob support (e.g., "*.anthropic.com").
	Host string `yaml:"target"`
	// IP is a specific IP address (e.g., "104.18.0.1").
	IP string `yaml:"ip,omitempty"`
	// CIDR is a CIDR block (e.g., "10.0.0.0/8").
	CIDR string `yaml:"cidr,omitempty"`
	// Port is the port specification: single ("443"), range ("8000-9000"), or wildcard ("*").
	Port string `yaml:"port,omitempty"`
	// Protocol is "tcp", "udp", or "*" (default: "*").
	Protocol string `yaml:"protocol,omitempty"`
	// Decision is the policy decision for this target.
	Decision Decision `yaml:"decision"`
}

// NetworkRule is a compiled network rule for efficient evaluation.
type NetworkRule struct {
	target   NetworkTarget
	hostGlob glob.Glob
	ipNet    *net.IPNet
	ip       net.IP
	portMin  int
	portMax  int
	portAny  bool
	protocol string
}

// CompileNetworkRule compiles a NetworkTarget into a NetworkRule for evaluation.
func CompileNetworkRule(t NetworkTarget) (*NetworkRule, error) {
	r := &NetworkRule{
		target:   t,
		protocol: strings.ToLower(t.Protocol),
	}

	// Default protocol to any.
	if r.protocol == "" || r.protocol == "*" {
		r.protocol = "*"
	}

	// Compile host glob if specified.
	if t.Host != "" {
		g, err := glob.Compile(strings.ToLower(t.Host), '.')
		if err != nil {
			return nil, fmt.Errorf("compile host pattern %q: %w", t.Host, err)
		}
		r.hostGlob = g
	}

	// Parse IP if specified.
	if t.IP != "" {
		r.ip = net.ParseIP(t.IP)
		if r.ip == nil {
			return nil, fmt.Errorf("invalid IP address %q", t.IP)
		}
	}

	// Parse CIDR if specified.
	if t.CIDR != "" {
		_, ipnet, err := net.ParseCIDR(t.CIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", t.CIDR, err)
		}
		r.ipNet = ipnet
	}

	// Parse port specification.
	if err := r.parsePort(t.Port); err != nil {
		return nil, err
	}

	return r, nil
}

// parsePort parses the port specification.
func (r *NetworkRule) parsePort(spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		r.portAny = true
		return nil
	}

	// Check for range.
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid port range %q", spec)
		}
		min, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return fmt.Errorf("invalid port range start %q: %w", parts[0], err)
		}
		max, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return fmt.Errorf("invalid port range end %q: %w", parts[1], err)
		}
		if min > max {
			return fmt.Errorf("port range start %d > end %d", min, max)
		}
		if min < 1 || max > 65535 {
			return fmt.Errorf("port range out of bounds: %d-%d", min, max)
		}
		r.portMin = min
		r.portMax = max
		return nil
	}

	// Single port.
	port, err := strconv.Atoi(spec)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", spec, err)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port out of range: %d", port)
	}
	r.portMin = port
	r.portMax = port
	return nil
}

// Matches checks if a connection matches this rule.
func (r *NetworkRule) Matches(host string, ip net.IP, port int, protocol string) bool {
	// Check protocol.
	if r.protocol != "*" {
		if strings.ToLower(protocol) != r.protocol {
			return false
		}
	}

	// Check port.
	if !r.portAny {
		if port < r.portMin || port > r.portMax {
			return false
		}
	}

	// Check host pattern.
	if r.hostGlob != nil {
		if !r.hostGlob.Match(strings.ToLower(host)) {
			return false
		}
	}

	// Check specific IP.
	if r.ip != nil {
		if ip == nil || !r.ip.Equal(ip) {
			return false
		}
	}

	// Check CIDR.
	if r.ipNet != nil {
		if ip == nil || !r.ipNet.Contains(ip) {
			return false
		}
	}

	return true
}

// Decision returns the decision for this rule.
func (r *NetworkRule) Decision() Decision {
	return r.target.Decision
}

// Target returns the original target configuration.
func (r *NetworkRule) Target() NetworkTarget {
	return r.target
}

// ProcessPolicy defines network policy for a specific process.
type ProcessPolicy struct {
	// Name is a human-readable name for this policy.
	Name string
	// Match defines the process matching criteria.
	Match ProcessMatchCriteria
	// Default is the default decision for this process.
	Default Decision
	// Rules are the network rules for this process.
	Rules []*NetworkRule
	// Children are policies for child processes.
	Children []*ChildPolicy
	// Matcher is the compiled process matcher.
	Matcher *ProcessMatcher
}

// ChildPolicy defines network policy for child processes.
type ChildPolicy struct {
	// Name is a human-readable name for this child policy.
	Name string
	// Match defines the child process matching criteria.
	Match ProcessMatchCriteria
	// Inherit specifies whether to inherit parent rules.
	Inherit bool
	// Rules are additional rules for the child process.
	Rules []*NetworkRule
	// Matcher is the compiled process matcher.
	Matcher *ProcessMatcher
}

// PolicyEngine evaluates network policies for processes.
type PolicyEngine struct {
	// GlobalDefault is the default decision when no process-specific policy matches.
	GlobalDefault Decision
	// ProcessPolicies are the compiled process-specific policies.
	ProcessPolicies []*ProcessPolicy
}

// NewPolicyEngine creates a new policy engine from configuration.
func NewPolicyEngine(config *Config) (*PolicyEngine, error) {
	engine := &PolicyEngine{
		GlobalDefault: DecisionDeny,
	}

	if config.Default != "" {
		engine.GlobalDefault = Decision(config.Default)
	}

	for _, pc := range config.Processes {
		pp, err := compileProcessPolicy(pc)
		if err != nil {
			return nil, fmt.Errorf("compile process policy %q: %w", pc.Name, err)
		}
		engine.ProcessPolicies = append(engine.ProcessPolicies, pp)
	}

	return engine, nil
}

// compileProcessPolicy compiles a process policy configuration.
func compileProcessPolicy(pc ProcessConfig) (*ProcessPolicy, error) {
	matcher, err := NewProcessMatcher(pc.Match)
	if err != nil {
		return nil, fmt.Errorf("create matcher: %w", err)
	}

	pp := &ProcessPolicy{
		Name:    pc.Name,
		Match:   pc.Match,
		Default: DecisionApprove, // Default to approve if not specified
		Matcher: matcher,
	}

	if pc.Default != "" {
		pp.Default = Decision(pc.Default)
	}

	// Compile rules.
	for i, rc := range pc.Rules {
		rule, err := CompileNetworkRule(rc)
		if err != nil {
			return nil, fmt.Errorf("compile rule %d: %w", i, err)
		}
		pp.Rules = append(pp.Rules, rule)
	}

	// Compile child policies.
	for _, cc := range pc.Children {
		child, err := compileChildPolicy(cc)
		if err != nil {
			return nil, fmt.Errorf("compile child policy %q: %w", cc.Name, err)
		}
		pp.Children = append(pp.Children, child)
	}

	return pp, nil
}

// compileChildPolicy compiles a child policy configuration.
func compileChildPolicy(cc ChildConfig) (*ChildPolicy, error) {
	matcher, err := NewProcessMatcher(cc.Match)
	if err != nil {
		return nil, fmt.Errorf("create matcher: %w", err)
	}

	cp := &ChildPolicy{
		Name:    cc.Name,
		Match:   cc.Match,
		Inherit: cc.Inherit,
		Matcher: matcher,
	}

	for i, rc := range cc.Rules {
		rule, err := CompileNetworkRule(rc)
		if err != nil {
			return nil, fmt.Errorf("compile rule %d: %w", i, err)
		}
		cp.Rules = append(cp.Rules, rule)
	}

	return cp, nil
}

// PolicyResult contains the result of policy evaluation.
type PolicyResult struct {
	// Decision is the policy decision.
	Decision Decision
	// ProcessName is the name of the matched process policy.
	ProcessName string
	// RuleIndex is the index of the matched rule, or -1 if default.
	RuleIndex int
	// IsInherited indicates if the decision came from an inherited rule.
	IsInherited bool
	// ChildName is the name of the matched child policy, if any.
	ChildName string
}

// Evaluate evaluates the policy for a network connection.
func (e *PolicyEngine) Evaluate(proc ProcessInfo, host string, ip net.IP, port int, protocol string) PolicyResult {
	// Find matching process policy.
	for _, pp := range e.ProcessPolicies {
		if !pp.Matcher.Matches(proc) {
			continue
		}

		// Check if this is a child process and if there's a child policy.
		childPolicy := e.findChildPolicy(pp, proc)
		if childPolicy != nil {
			return e.evaluateWithChild(pp, childPolicy, host, ip, port, protocol)
		}

		// Evaluate process rules.
		return e.evaluateProcessRules(pp, host, ip, port, protocol)
	}

	// No matching process policy; use global default.
	return PolicyResult{
		Decision:  e.GlobalDefault,
		RuleIndex: -1,
	}
}

// findChildPolicy finds a matching child policy for a process.
// Note: In a real implementation, this would check the process tree.
// For now, it matches based on the process info directly.
func (e *PolicyEngine) findChildPolicy(parent *ProcessPolicy, proc ProcessInfo) *ChildPolicy {
	for _, cp := range parent.Children {
		if cp.Matcher.Matches(proc) {
			return cp
		}
	}
	return nil
}

// evaluateWithChild evaluates rules for a child process.
func (e *PolicyEngine) evaluateWithChild(parent *ProcessPolicy, child *ChildPolicy, host string, ip net.IP, port int, protocol string) PolicyResult {
	// Check child-specific rules first (most specific wins).
	for i, rule := range child.Rules {
		if rule.Matches(host, ip, port, protocol) {
			return PolicyResult{
				Decision:    rule.Decision(),
				ProcessName: parent.Name,
				ChildName:   child.Name,
				RuleIndex:   i,
			}
		}
	}

	// If inheritance is enabled, check parent rules.
	if child.Inherit {
		for i, rule := range parent.Rules {
			if rule.Matches(host, ip, port, protocol) {
				return PolicyResult{
					Decision:    rule.Decision(),
					ProcessName: parent.Name,
					ChildName:   child.Name,
					RuleIndex:   i,
					IsInherited: true,
				}
			}
		}
	}

	// Use parent's default decision.
	return PolicyResult{
		Decision:    parent.Default,
		ProcessName: parent.Name,
		ChildName:   child.Name,
		RuleIndex:   -1,
		IsInherited: child.Inherit,
	}
}

// evaluateProcessRules evaluates rules for a process.
func (e *PolicyEngine) evaluateProcessRules(pp *ProcessPolicy, host string, ip net.IP, port int, protocol string) PolicyResult {
	for i, rule := range pp.Rules {
		if rule.Matches(host, ip, port, protocol) {
			return PolicyResult{
				Decision:    rule.Decision(),
				ProcessName: pp.Name,
				RuleIndex:   i,
			}
		}
	}

	// No rule matched; use process default.
	return PolicyResult{
		Decision:    pp.Default,
		ProcessName: pp.Name,
		RuleIndex:   -1,
	}
}

// EvaluateForParentChild evaluates policy considering parent-child relationship.
// parentProc is the parent process info, childProc is the current process being evaluated.
func (e *PolicyEngine) EvaluateForParentChild(parentProc, childProc ProcessInfo, host string, ip net.IP, port int, protocol string) PolicyResult {
	// First, find a policy matching the parent.
	for _, pp := range e.ProcessPolicies {
		if !pp.Matcher.Matches(parentProc) {
			continue
		}

		// Check if there's a child policy matching the child process.
		for _, cp := range pp.Children {
			if cp.Matcher.Matches(childProc) {
				return e.evaluateWithChild(pp, cp, host, ip, port, protocol)
			}
		}

		// If no child policy matches but child inherits, use parent rules.
		return e.evaluateProcessRules(pp, host, ip, port, protocol)
	}

	// Check if the child itself matches a process policy directly.
	return e.Evaluate(childProc, host, ip, port, protocol)
}
