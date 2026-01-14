// Package pnacl provides Process Network ACL (PNACL) functionality for
// per-process network access control policies.
package pnacl

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

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
	// DecisionUseDefault is a special value for timeout fallback that
	// indicates the policy engine's global or process default should be used.
	// This is only valid for ApprovalConfig.TimeoutFallback.
	DecisionUseDefault Decision = "use_default"
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

// ConnectionContext provides context for matching a network connection to a process policy.
// This type contains both process and connection information for policy evaluation.
type ConnectionContext struct {
	// Process contains information about the process making the connection.
	Process ProcessInfo
	// Host is the target hostname (may be empty if connecting by IP).
	Host string
	// Port is the target port number.
	Port int
	// Protocol is the connection protocol (e.g., "tcp", "udp").
	Protocol string
}

// ProcessACL represents the resolved ACL configuration for a matched process.
// It contains the policy details that should be applied to the process's connections.
type ProcessACL struct {
	// Name is the human-readable name for this process policy.
	Name string
	// Match contains the criteria that matched this process.
	Match ProcessMatchCriteria
	// Default is the default decision for this process's connections.
	Default Decision
	// Rules are the network rules for this process.
	Rules []NetworkTarget
	// Children are the child process configurations.
	Children []ChildConfig
	// Specificity indicates how specific this match is.
	Specificity MatchSpecificity
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
		Inherit: cc.InheritRules(), // Use method to get default-aware value
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

// EvaluationResult contains the result of policy evaluation for the PolicyEvaluator.
type EvaluationResult struct {
	// Decision is the policy decision.
	Decision Decision
	// MatchedRule is the rule that matched, or nil if default was used.
	MatchedRule *NetworkTarget
	// RuleIndex is the index of the matched rule, or -1 if default was used.
	RuleIndex int
	// ProcessACLName is the name of the matched process ACL.
	ProcessACLName string
	// IsInherited indicates if the decision came from an inherited parent rule.
	IsInherited bool
	// ChildACLName is the name of the matched child ACL, if any.
	ChildACLName string
}

// PolicyEvaluatorACL defines network ACL rules for a specific process.
// This is the runtime representation used by the PolicyEvaluator.
type PolicyEvaluatorACL struct {
	// Name is a human-readable name for this ACL.
	Name string
	// Match defines the process matching criteria.
	Match ProcessMatchCriteria
	// Default is the default decision when no rule matches.
	Default Decision
	// Rules are the network ACL rules evaluated in order.
	Rules []NetworkTarget
	// Children are ACLs for child processes.
	Children []*PolicyEvaluatorACL
	// Inherit indicates whether this ACL inherits rules from its parent.
	Inherit bool
}

// PolicyEvaluator evaluates network ACL rules for connection requests.
// It supports first-match-wins evaluation with parent-child inheritance.
// PolicyEvaluator is thread-safe for concurrent Evaluate calls.
type PolicyEvaluator struct {
	// GlobalDefault is the default decision when no process ACL matches.
	GlobalDefault Decision
	// ProcessACLs are the configured process-specific ACLs.
	ProcessACLs []*PolicyEvaluatorACL
	// compiledMatchers caches compiled process matchers by ACL name.
	compiledMatchers map[string]*singleProcessMatcher
	// compiledHostGlobs caches compiled host glob patterns.
	compiledHostGlobs map[string]glob.Glob
	// cacheMu protects compiledMatchers and compiledHostGlobs for concurrent access.
	cacheMu sync.RWMutex
}

// singleProcessMatcher is a simplified matcher for a single process criteria.
type singleProcessMatcher struct {
	criteria ProcessMatchCriteria
	pathGlob glob.Glob
}

// NewPolicyEvaluator creates a new PolicyEvaluator with default settings.
func NewPolicyEvaluator() *PolicyEvaluator {
	return &PolicyEvaluator{
		GlobalDefault:     DecisionDeny,
		ProcessACLs:       make([]*PolicyEvaluatorACL, 0),
		compiledMatchers:  make(map[string]*singleProcessMatcher),
		compiledHostGlobs: make(map[string]glob.Glob),
	}
}

// Evaluate evaluates the policy for a connection context against a process ACL.
// Rules are evaluated in order, and the first matching rule wins.
// If the process ACL has children (inheritance), child rules are evaluated first,
// then inherited parent rules if no child rule matches.
func (pe *PolicyEvaluator) Evaluate(ctx ConnectionContext, processACL *PolicyEvaluatorACL) EvaluationResult {
	if processACL == nil {
		return EvaluationResult{
			Decision:  pe.GlobalDefault,
			RuleIndex: -1,
		}
	}

	// Check if there's a matching child ACL for the current process.
	childACL := pe.findChildACL(processACL, ctx)
	if childACL != nil {
		return pe.evaluateWithInheritance(ctx, processACL, childACL)
	}

	// Evaluate rules directly on the process ACL.
	return pe.evaluateACLRules(ctx, processACL.Rules, processACL.Name, processACL.Default, false, "")
}

// evaluateWithInheritance evaluates rules with parent-child inheritance.
// Child rules are evaluated first, then parent rules if inheritance is enabled.
func (pe *PolicyEvaluator) evaluateWithInheritance(ctx ConnectionContext, parent, child *PolicyEvaluatorACL) EvaluationResult {
	// Evaluate child-specific rules first (most specific wins).
	for i := range child.Rules {
		rule := &child.Rules[i]
		if pe.evaluateNetworkTarget(*rule, ctx) {
			return EvaluationResult{
				Decision:       rule.Decision,
				MatchedRule:    rule,
				RuleIndex:      i,
				ProcessACLName: parent.Name,
				IsInherited:    false,
				ChildACLName:   child.Name,
			}
		}
	}

	// If inheritance is enabled, evaluate parent rules.
	if child.Inherit {
		for i := range parent.Rules {
			rule := &parent.Rules[i]
			if pe.evaluateNetworkTarget(*rule, ctx) {
				return EvaluationResult{
					Decision:       rule.Decision,
					MatchedRule:    rule,
					RuleIndex:      i,
					ProcessACLName: parent.Name,
					IsInherited:    true,
					ChildACLName:   child.Name,
				}
			}
		}
	}

	// No rule matched; use child's default if set, otherwise parent's default.
	defaultDecision := child.Default
	if defaultDecision == "" {
		defaultDecision = parent.Default
	}
	if defaultDecision == "" {
		defaultDecision = pe.GlobalDefault
	}

	return EvaluationResult{
		Decision:       defaultDecision,
		RuleIndex:      -1,
		ProcessACLName: parent.Name,
		IsInherited:    child.Inherit,
		ChildACLName:   child.Name,
	}
}

// evaluateACLRules evaluates a list of rules against a connection context.
func (pe *PolicyEvaluator) evaluateACLRules(ctx ConnectionContext, rules []NetworkTarget, aclName string, defaultDecision Decision, isInherited bool, childName string) EvaluationResult {
	for i := range rules {
		rule := &rules[i]
		if pe.evaluateNetworkTarget(*rule, ctx) {
			return EvaluationResult{
				Decision:       rule.Decision,
				MatchedRule:    rule,
				RuleIndex:      i,
				ProcessACLName: aclName,
				IsInherited:    isInherited,
				ChildACLName:   childName,
			}
		}
	}

	// No rule matched; use default decision.
	if defaultDecision == "" {
		defaultDecision = pe.GlobalDefault
	}

	return EvaluationResult{
		Decision:       defaultDecision,
		RuleIndex:      -1,
		ProcessACLName: aclName,
		IsInherited:    isInherited,
		ChildACLName:   childName,
	}
}

// evaluateNetworkTarget checks if a single rule matches the connection context.
// A rule matches if all specified criteria (host/IP/CIDR, port, protocol) match.
// For target matching, host OR IP OR CIDR must match (if specified).
func (pe *PolicyEvaluator) evaluateNetworkTarget(rule NetworkTarget, ctx ConnectionContext) bool {
	// Check protocol first (most selective).
	if !matchProtocol(rule.Protocol, ctx.Protocol) {
		return false
	}

	// Check port.
	if !matchPort(rule.Port, ctx.Port) {
		return false
	}

	// Check target (host OR IP OR CIDR).
	// At least one target specifier must be present and match.
	targetMatched := false
	hasTargetSpec := false

	// Check host pattern.
	if rule.Host != "" {
		hasTargetSpec = true
		if pe.matchHost(rule.Host, ctx.Host) {
			targetMatched = true
		}
	}

	// Check IP - ConnectionContext uses Host for IP as string.
	if rule.IP != "" {
		hasTargetSpec = true
		ip := net.ParseIP(ctx.Host)
		if matchIP(rule.IP, ip) {
			targetMatched = true
		}
	}

	// Check CIDR.
	if rule.CIDR != "" {
		hasTargetSpec = true
		ip := net.ParseIP(ctx.Host)
		if matchCIDR(rule.CIDR, ip) {
			targetMatched = true
		}
	}

	// If no target was specified, the rule matches any target.
	if !hasTargetSpec {
		return true
	}

	return targetMatched
}

// findChildACL finds a matching child ACL for the given connection context.
// Returns nil if no child ACL matches.
func (pe *PolicyEvaluator) findChildACL(parent *PolicyEvaluatorACL, ctx ConnectionContext) *PolicyEvaluatorACL {
	if len(parent.Children) == 0 {
		return nil
	}

	for _, child := range parent.Children {
		matcher, err := pe.getOrCreateMatcher(child.Name, child.Match)
		if err != nil {
			continue
		}

		if matcher.matches(ctx.Process) {
			return child
		}
	}

	return nil
}

// getOrCreateMatcher retrieves a cached matcher or creates a new one.
// Thread-safe via cacheMu.
func (pe *PolicyEvaluator) getOrCreateMatcher(name string, criteria ProcessMatchCriteria) (*singleProcessMatcher, error) {
	// Check cache with read lock first.
	pe.cacheMu.RLock()
	if matcher, ok := pe.compiledMatchers[name]; ok {
		pe.cacheMu.RUnlock()
		return matcher, nil
	}
	pe.cacheMu.RUnlock()

	// Create new matcher.
	matcher := &singleProcessMatcher{
		criteria: criteria,
	}

	// Compile path glob if specified.
	if criteria.Path != "" {
		g, err := glob.Compile(criteria.Path, '/')
		if err != nil {
			return nil, err
		}
		matcher.pathGlob = g
	}

	// Store in cache with write lock.
	pe.cacheMu.Lock()
	pe.compiledMatchers[name] = matcher
	pe.cacheMu.Unlock()

	return matcher, nil
}

// matches checks if a process info matches this matcher's criteria.
func (m *singleProcessMatcher) matches(info ProcessInfo) bool {
	if m.criteria.Strict {
		return m.matchStrict(info)
	}
	return m.matchFlexible(info)
}

// matchFlexible returns true if any specified criterion matches (OR semantics).
func (m *singleProcessMatcher) matchFlexible(info ProcessInfo) bool {
	if !hasCriteria(m.criteria) {
		return false
	}

	// Check process name.
	if m.criteria.ProcessName != "" {
		if strings.EqualFold(m.criteria.ProcessName, info.Name) {
			return true
		}
	}

	// Check path.
	if m.pathGlob != nil {
		if m.pathGlob.Match(info.Path) {
			return true
		}
	}

	// Check bundle ID (macOS).
	if m.criteria.BundleID != "" && info.BundleID != "" {
		if strings.EqualFold(m.criteria.BundleID, info.BundleID) {
			return true
		}
	}

	// Check package family name (Windows).
	if m.criteria.PackageFamilyName != "" && info.PackageFamilyName != "" {
		if strings.EqualFold(m.criteria.PackageFamilyName, info.PackageFamilyName) {
			return true
		}
	}

	return false
}

// matchStrict returns true only if all specified criteria match (AND semantics).
func (m *singleProcessMatcher) matchStrict(info ProcessInfo) bool {
	if !hasCriteria(m.criteria) {
		return false
	}

	// Check process name if specified.
	if m.criteria.ProcessName != "" {
		if !strings.EqualFold(m.criteria.ProcessName, info.Name) {
			return false
		}
	}

	// Check path if specified.
	if m.pathGlob != nil {
		if !m.pathGlob.Match(info.Path) {
			return false
		}
	}

	// Check bundle ID if specified.
	if m.criteria.BundleID != "" {
		if !strings.EqualFold(m.criteria.BundleID, info.BundleID) {
			return false
		}
	}

	// Check package family name if specified.
	if m.criteria.PackageFamilyName != "" {
		if !strings.EqualFold(m.criteria.PackageFamilyName, info.PackageFamilyName) {
			return false
		}
	}

	return true
}

// matchHost checks if a host matches a pattern.
// Supports glob patterns like "*.example.com", "api.*.anthropic.com".
func (pe *PolicyEvaluator) matchHost(pattern, host string) bool {
	if pattern == "" || host == "" {
		return false
	}

	// Normalize to lowercase.
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)

	// Exact match.
	if pattern == host {
		return true
	}

	// Wildcard match.
	if pattern == "*" {
		return true
	}

	// Check cache for compiled glob with read lock.
	pe.cacheMu.RLock()
	g, ok := pe.compiledHostGlobs[pattern]
	pe.cacheMu.RUnlock()

	if !ok {
		// Compile the glob.
		var err error
		g, err = glob.Compile(pattern, '.')
		if err != nil {
			return false
		}
		// Cache with write lock.
		pe.cacheMu.Lock()
		pe.compiledHostGlobs[pattern] = g
		pe.cacheMu.Unlock()
	}

	return g.Match(host)
}

// matchIP checks if an IP address matches a target IP string.
// Performs exact IP match.
func matchIP(target string, ip net.IP) bool {
	if target == "" || ip == nil {
		return false
	}

	// Parse the target IP.
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return false
	}

	return targetIP.Equal(ip)
}

// matchCIDR checks if an IP address is contained within a CIDR block.
// Uses net.ParseCIDR for proper CIDR containment check.
func matchCIDR(cidr string, ip net.IP) bool {
	if cidr == "" || ip == nil {
		return false
	}

	// Parse the CIDR.
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	return ipNet.Contains(ip)
}

// matchPort checks if a port matches a port specification.
// Supports:
//   - Single port: "443"
//   - Port range: "8000-9000"
//   - Wildcard: "*" or empty string (matches any port)
func matchPort(pattern string, port int) bool {
	pattern = strings.TrimSpace(pattern)

	// Empty or wildcard matches any port.
	if pattern == "" || pattern == "*" {
		return true
	}

	// Check for range.
	if strings.Contains(pattern, "-") {
		parts := strings.SplitN(pattern, "-", 2)
		if len(parts) != 2 {
			return false
		}

		min, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return false
		}

		max, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return false
		}

		return port >= min && port <= max
	}

	// Single port match.
	targetPort, err := strconv.Atoi(pattern)
	if err != nil {
		return false
	}

	return port == targetPort
}

// matchProtocol checks if a protocol matches a pattern.
// Supports "tcp", "udp", or "*" (matches any protocol).
func matchProtocol(pattern, protocol string) bool {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	protocol = strings.TrimSpace(strings.ToLower(protocol))

	// Empty or wildcard matches any protocol.
	if pattern == "" || pattern == "*" {
		return true
	}

	return pattern == protocol
}

// AddProcessACL adds a process ACL to the evaluator.
func (pe *PolicyEvaluator) AddProcessACL(acl *PolicyEvaluatorACL) {
	pe.ProcessACLs = append(pe.ProcessACLs, acl)
}

// FindProcessACL finds a process ACL that matches the given process info.
func (pe *PolicyEvaluator) FindProcessACL(info ProcessInfo) *PolicyEvaluatorACL {
	for _, acl := range pe.ProcessACLs {
		matcher, err := pe.getOrCreateMatcher(acl.Name, acl.Match)
		if err != nil {
			continue
		}

		if matcher.matches(info) {
			return acl
		}
	}
	return nil
}

// EvaluateConnection is a convenience method that finds the matching process ACL
// and evaluates the connection in one call.
func (pe *PolicyEvaluator) EvaluateConnection(ctx ConnectionContext) EvaluationResult {
	acl := pe.FindProcessACL(ctx.Process)
	return pe.Evaluate(ctx, acl)
}

// SetGlobalDefault sets the global default decision.
func (pe *PolicyEvaluator) SetGlobalDefault(decision Decision) {
	pe.GlobalDefault = decision
}

// ClearCache clears all cached matchers and compiled globs.
// Useful when ACLs are modified and need to be re-evaluated.
// Thread-safe via cacheMu.
func (pe *PolicyEvaluator) ClearCache() {
	pe.cacheMu.Lock()
	pe.compiledMatchers = make(map[string]*singleProcessMatcher)
	pe.compiledHostGlobs = make(map[string]glob.Glob)
	pe.cacheMu.Unlock()
}

// LoadFromConfig creates a PolicyEvaluator from a Config.
func LoadFromConfig(config *Config) *PolicyEvaluator {
	pe := NewPolicyEvaluator()
	if config.Default != "" {
		pe.GlobalDefault = Decision(config.Default)
	}

	// Convert ProcessConfig to PolicyEvaluatorACL.
	for _, pc := range config.Processes {
		acl := &PolicyEvaluatorACL{
			Name:    pc.Name,
			Match:   pc.Match,
			Default: Decision(pc.Default),
			Rules:   pc.Rules,
		}

		// Convert children.
		for _, cc := range pc.Children {
			childACL := &PolicyEvaluatorACL{
				Name:    cc.Name,
				Match:   cc.Match,
				Inherit: cc.InheritRules(),
				Rules:   cc.Rules,
			}
			acl.Children = append(acl.Children, childACL)
		}

		pe.ProcessACLs = append(pe.ProcessACLs, acl)
	}

	return pe
}
