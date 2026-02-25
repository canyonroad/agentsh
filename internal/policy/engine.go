package policy

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/gobwas/glob"
)

// ThreatCheckResult holds the outcome of a threat feed lookup.
type ThreatCheckResult struct {
	FeedName      string
	MatchedDomain string
}

// ThreatChecker is an optional interface for domain-level threat feed lookups.
// *threatfeed.Store satisfies this interface.
type ThreatChecker interface {
	Check(domain string) (ThreatCheckResult, bool)
}

type Engine struct {
	policy           *Policy
	enforceApprovals bool

	compiledFileRules     []compiledFileRule
	compiledNetworkRules  []compiledNetworkRule
	compiledCommandRules  []compiledCommandRule
	compiledUnixRules     []compiledUnixRule
	compiledRegistryRules []compiledRegistryRule

	// Compiled redirect rules for DNS and connect interception
	dnsRedirectRules     []compiledDnsRedirectRule
	connectRedirectRules []compiledConnectRedirectRule

	// Compiled env policy patterns for glob matching
	compiledEnvAllow []glob.Glob
	compiledEnvDeny  []glob.Glob

	// Signal policy engine
	signalEngine signalEngineType

	// Optional threat feed store for domain checking
	threatStore  ThreatChecker
	threatAction string
}

type Limits struct {
	CommandTimeout time.Duration
	SessionTimeout time.Duration
	IdleTimeout    time.Duration

	MaxMemoryMB     int
	CPUQuotaPercent int
	PidsMax         int
}

type compiledFileRule struct {
	rule         FileRule
	globs        []glob.Glob
	ops          map[string]struct{}
	redirectTo   string // Expanded redirect target
	preserveTree bool
}

type compiledNetworkRule struct {
	rule        NetworkRule
	domainGlobs []glob.Glob
	cidrs       []*net.IPNet
	ports       map[int]struct{}
}

type compiledCommandRule struct {
	rule          CommandRule
	basenames     map[string]struct{} // Commands without paths (e.g., "sh") - match by basename
	basenameGlobs []glob.Glob         // Glob patterns for basenames (e.g., "go*", "*")
	fullPaths     map[string]struct{} // Commands with paths (e.g., "/bin/sh") - match exact path
	pathGlobs     []glob.Glob         // Glob patterns for paths (e.g., "/usr/*/sh")
	argsRegexes   []*regexp.Regexp    // Regex patterns matched against joined args string
}

type compiledUnixRule struct {
	rule  UnixSocketRule
	paths []glob.Glob
	ops   map[string]struct{}
}

type compiledRegistryRule struct {
	rule     RegistryRule
	globs    []glob.Glob
	ops      map[string]struct{}
	priority int
}

type compiledDnsRedirectRule struct {
	rule    DnsRedirectRule
	pattern *regexp.Regexp
}

type compiledConnectRedirectRule struct {
	rule    ConnectRedirectRule
	pattern *regexp.Regexp
}

type Decision struct {
	PolicyDecision    types.Decision
	EffectiveDecision types.Decision
	Rule              string
	Message           string
	Approval          *types.ApprovalInfo
	Redirect          *types.RedirectInfo
	FileRedirect      *types.FileRedirectInfo
	EnvPolicy         ResolvedEnvPolicy
	ThreatFeed        string
	ThreatMatch       string
	ThreatAction      string // "deny" or "audit" — set when a threat feed matched
}

func NewEngine(p *Policy, enforceApprovals bool) (*Engine, error) {
	e := &Engine{
		policy:           p,
		enforceApprovals: enforceApprovals,
	}

	for _, r := range p.FileRules {
		cr := compiledFileRule{
			rule:         r,
			ops:          map[string]struct{}{},
			redirectTo:   r.RedirectTo,
			preserveTree: r.PreserveTree,
		}
		for _, op := range r.Operations {
			cr.ops[strings.ToLower(op)] = struct{}{}
		}
		for _, pat := range r.Paths {
			g, err := glob.Compile(pat, '/')
			if err != nil {
				return nil, fmt.Errorf("compile file rule %q glob %q: %w", r.Name, pat, err)
			}
			cr.globs = append(cr.globs, g)
		}
		e.compiledFileRules = append(e.compiledFileRules, cr)
	}

	for _, r := range p.NetworkRules {
		cr := compiledNetworkRule{
			rule:  r,
			ports: map[int]struct{}{},
		}
		for _, port := range r.Ports {
			cr.ports[port] = struct{}{}
		}
		for _, pat := range r.Domains {
			// Domain patterns in the sample policy include "*" which gobwas/glob can handle.
			g, err := glob.Compile(strings.ToLower(pat), '.')
			if err != nil {
				// Fall back to path-separator compilation.
				g, err = glob.Compile(strings.ToLower(pat))
				if err != nil {
					return nil, fmt.Errorf("compile network rule %q domain %q: %w", r.Name, pat, err)
				}
			}
			cr.domainGlobs = append(cr.domainGlobs, g)
		}
		for _, cidr := range r.CIDRs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("parse network rule %q cidr %q: %w", r.Name, cidr, err)
			}
			cr.cidrs = append(cr.cidrs, ipnet)
		}
		e.compiledNetworkRules = append(e.compiledNetworkRules, cr)
	}

	for _, r := range p.CommandRules {
		cr := compiledCommandRule{
			rule:      r,
			basenames: map[string]struct{}{},
			fullPaths: map[string]struct{}{},
		}
		for _, c := range r.Commands {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			// Check if command contains a path separator
			if strings.Contains(c, "/") {
				// Check if it's a glob pattern (contains * or ?)
				if strings.ContainsAny(c, "*?[") {
					// Use '/' separator so * matches single path component only
					g, err := glob.Compile(c, '/')
					if err != nil {
						// Failed to compile as glob (e.g., incomplete pattern like "[")
						// Fall back to exact match
						cr.fullPaths[strings.ToLower(c)] = struct{}{}
					} else {
						cr.pathGlobs = append(cr.pathGlobs, g)
					}
				} else {
					// Exact path match (case-sensitive on Unix, but we lowercase for consistency)
					cr.fullPaths[strings.ToLower(c)] = struct{}{}
				}
			} else {
				// Basename only - check if it's a glob pattern
				if strings.ContainsAny(c, "*?[") {
					g, err := glob.Compile(c)
					if err != nil {
						// Failed to compile as glob (e.g., incomplete pattern like "[")
						// Fall back to literal match
						cr.basenames[strings.ToLower(c)] = struct{}{}
					} else {
						cr.basenameGlobs = append(cr.basenameGlobs, g)
					}
				} else {
					// Literal basename match (case-insensitive)
					cr.basenames[strings.ToLower(c)] = struct{}{}
				}
			}
		}
		for _, pat := range r.ArgsPatterns {
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("compile command rule %q arg pattern %q: %w", r.Name, pat, err)
			}
			cr.argsRegexes = append(cr.argsRegexes, re)
		}
		e.compiledCommandRules = append(e.compiledCommandRules, cr)
	}

	for _, r := range p.UnixRules {
		cr := compiledUnixRule{rule: r, ops: map[string]struct{}{}}
		for _, op := range r.Operations {
			cr.ops[strings.ToLower(op)] = struct{}{}
		}
		for _, pat := range r.Paths {
			g, err := glob.Compile(pat, '/')
			if err != nil {
				g, err = glob.Compile(pat)
			}
			if err != nil {
				return nil, fmt.Errorf("compile unix rule %q glob %q: %w", r.Name, pat, err)
			}
			cr.paths = append(cr.paths, g)
		}
		e.compiledUnixRules = append(e.compiledUnixRules, cr)
	}

	// Compile registry rules
	for _, r := range p.RegistryRules {
		cr := compiledRegistryRule{
			rule:     r,
			ops:      map[string]struct{}{},
			priority: r.Priority,
		}
		for _, op := range r.Operations {
			cr.ops[strings.ToLower(op)] = struct{}{}
		}
		for _, pat := range r.Paths {
			// Escape backslashes for glob (backslash is the escape character in gobwas/glob)
			// Compile without separator so * matches across path segments
			escapedPat := strings.ReplaceAll(pat, `\`, `\\`)
			g, err := glob.Compile(escapedPat)
			if err != nil {
				return nil, fmt.Errorf("compile registry rule %q glob %q: %w", r.Name, pat, err)
			}
			cr.globs = append(cr.globs, g)
		}
		e.compiledRegistryRules = append(e.compiledRegistryRules, cr)
	}
	// Sort by priority (higher first)
	sort.Slice(e.compiledRegistryRules, func(i, j int) bool {
		return e.compiledRegistryRules[i].priority > e.compiledRegistryRules[j].priority
	})

	// Compile DNS redirect rules
	for _, r := range p.DnsRedirectRules {
		pattern, _ := regexp.Compile(r.Match) // Already validated
		e.dnsRedirectRules = append(e.dnsRedirectRules, compiledDnsRedirectRule{
			rule:    r,
			pattern: pattern,
		})
	}

	// Compile connect redirect rules
	for _, r := range p.ConnectRedirectRules {
		pattern, _ := regexp.Compile(r.Match) // Already validated
		e.connectRedirectRules = append(e.connectRedirectRules, compiledConnectRedirectRule{
			rule:    r,
			pattern: pattern,
		})
	}

	// Compile env policy patterns
	for _, pat := range p.EnvPolicy.Allow {
		g, err := glob.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("compile env allow pattern %q: %w", pat, err)
		}
		e.compiledEnvAllow = append(e.compiledEnvAllow, g)
	}
	for _, pat := range p.EnvPolicy.Deny {
		g, err := glob.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("compile env deny pattern %q: %w", pat, err)
		}
		e.compiledEnvDeny = append(e.compiledEnvDeny, g)
	}

	// Compile signal rules
	sigEngine, err := compileSignalRules(p.SignalRules)
	if err != nil {
		return nil, err
	}
	e.signalEngine = sigEngine

	return e, nil
}

// NewEngineWithVariables creates an engine with variable expansion.
// Variables in policy paths are expanded before glob compilation.
func NewEngineWithVariables(p *Policy, enforceApprovals bool, vars map[string]string) (*Engine, error) {
	// Deep copy and expand the policy
	expanded, err := expandPolicy(p, vars)
	if err != nil {
		return nil, fmt.Errorf("expand policy variables: %w", err)
	}
	return NewEngine(expanded, enforceApprovals)
}

// SetThreatStore configures an optional threat feed store for domain checking.
// action must be "deny" or "audit"; defaults to "deny" if invalid.
func (e *Engine) SetThreatStore(store ThreatChecker, action string) {
	e.threatStore = store
	switch action {
	case "deny", "audit":
		e.threatAction = action
	default:
		e.threatAction = "deny"
	}
}

// expandPolicy creates a copy of the policy with all variables expanded.
func expandPolicy(p *Policy, vars map[string]string) (*Policy, error) {
	// Create a shallow copy
	expanded := *p

	// Expand file rules
	expanded.FileRules = make([]FileRule, len(p.FileRules))
	for i, rule := range p.FileRules {
		expandedRule := rule
		expandedRule.Paths = make([]string, len(rule.Paths))
		for j, path := range rule.Paths {
			expandedPath, err := ExpandVariables(path, vars)
			if err != nil {
				return nil, fmt.Errorf("rule %q path %q: %w", rule.Name, path, err)
			}
			expandedRule.Paths[j] = expandedPath
		}
		expanded.FileRules[i] = expandedRule
	}

	// Expand network rules (domains might use variables)
	expanded.NetworkRules = make([]NetworkRule, len(p.NetworkRules))
	for i, rule := range p.NetworkRules {
		expandedRule := rule
		expandedRule.Domains = make([]string, len(rule.Domains))
		for j, domain := range rule.Domains {
			expandedDomain, err := ExpandVariables(domain, vars)
			if err != nil {
				return nil, fmt.Errorf("network rule %q domain %q: %w", rule.Name, domain, err)
			}
			expandedRule.Domains[j] = expandedDomain
		}
		expanded.NetworkRules[i] = expandedRule
	}

	// Copy other rules as-is (command rules unlikely to need variables)
	expanded.CommandRules = append([]CommandRule(nil), p.CommandRules...)
	expanded.RegistryRules = append([]RegistryRule(nil), p.RegistryRules...)
	expanded.UnixRules = append([]UnixSocketRule(nil), p.UnixRules...)

	return &expanded, nil
}

// NetworkRules returns the raw network rules for read-only inspection (e.g., ebpf allowlist).
func (e *Engine) NetworkRules() []NetworkRule {
	if e == nil || e.policy == nil {
		return nil
	}
	return e.policy.NetworkRules
}

// Policy returns the underlying policy for read-only inspection (e.g., Landlock path derivation).
func (e *Engine) Policy() *Policy {
	if e == nil {
		return nil
	}
	return e.policy
}

// SignalEngine returns the signal policy engine, or nil if no signal rules.
func (e *Engine) SignalEngine() signalEngineType {
	return e.signalEngine
}

func (e *Engine) Limits() Limits {
	if e == nil || e.policy == nil {
		return Limits{}
	}
	return Limits{
		CommandTimeout:  e.policy.ResourceLimits.CommandTimeout.Duration,
		SessionTimeout:  e.policy.ResourceLimits.SessionTimeout.Duration,
		IdleTimeout:     e.policy.ResourceLimits.IdleTimeout.Duration,
		MaxMemoryMB:     e.policy.ResourceLimits.MaxMemoryMB,
		CPUQuotaPercent: e.policy.ResourceLimits.CPUQuotaPercent,
		PidsMax:         e.policy.ResourceLimits.PidsMax,
	}
}

// CheckNetworkIP evaluates network_rules using a known destination IP (no DNS resolution).
// If domain is empty, only CIDR/port-based rules can match.
func (e *Engine) CheckNetworkIP(domain string, ip net.IP, port int) Decision {
	if e.policy == nil {
		return Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Threat feed pre-check.
	var threatResult *ThreatCheckResult
	if e.threatStore != nil && domain != "" {
		if result, matched := e.threatStore.Check(domain); matched {
			if e.threatAction == "deny" {
				dec := e.wrapDecision("deny", "threat-feed:"+result.FeedName,
					"domain matched threat feed: "+result.FeedName+" (matched: "+result.MatchedDomain+")", nil)
				dec.ThreatFeed = result.FeedName
				dec.ThreatMatch = result.MatchedDomain
				dec.ThreatAction = "deny"
				return dec
			}
			// Audit mode: record threat metadata, continue normal rule evaluation.
			threatResult = &result
		}
	}

	var ips []net.IP
	if ip != nil {
		ips = []net.IP{ip}
	} else if parsed := net.ParseIP(domain); parsed != nil {
		ips = []net.IP{parsed}
	}

	for _, r := range e.compiledNetworkRules {
		if len(r.ports) > 0 {
			if _, ok := r.ports[port]; !ok {
				continue
			}
		}

		if len(r.domainGlobs) > 0 {
			matched := false
			for _, g := range r.domainGlobs {
				if domain != "" && g.Match(domain) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		if len(r.cidrs) > 0 {
			matched := false
			for _, cand := range ips {
				for _, cidr := range r.cidrs {
					if cidr.Contains(cand) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				continue
			}
		}

		dec := e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, nil)
		if threatResult != nil {
			dec.ThreatFeed = threatResult.FeedName
			dec.ThreatMatch = threatResult.MatchedDomain
			dec.ThreatAction = "audit"
		}
		return dec
	}

	dec := e.wrapDecision(string(types.DecisionDeny), "default-deny-network", "", nil)
	if threatResult != nil {
		dec.ThreatFeed = threatResult.FeedName
		dec.ThreatMatch = threatResult.MatchedDomain
		dec.ThreatAction = "audit"
	}
	return dec
}

func (e *Engine) CheckCommand(command string, args []string) Decision {
	cmdLower := strings.ToLower(command)
	cmdBase := strings.ToLower(filepath.Base(command))

	for _, r := range e.compiledCommandRules {
		// Pre-check is always depth 0 (direct command from user)
		// Skip rules that don't apply to direct commands
		if !r.rule.Context.MatchesDepth(0) {
			continue
		}

		// Check if command matches any of the rule's patterns
		commandMatched := false

		// If no commands specified, rule applies to all commands
		if len(r.basenames) == 0 && len(r.basenameGlobs) == 0 && len(r.fullPaths) == 0 && len(r.pathGlobs) == 0 {
			commandMatched = true
		} else {
			// Check full path matches first (more specific)
			if _, ok := r.fullPaths[cmdLower]; ok {
				commandMatched = true
			}

			// Check path glob patterns
			if !commandMatched {
				for _, g := range r.pathGlobs {
					if g.Match(cmdLower) || g.Match(command) {
						commandMatched = true
						break
					}
				}
			}

			// Check basename matches (less specific, legacy behavior)
			if !commandMatched {
				if _, ok := r.basenames[cmdBase]; ok {
					commandMatched = true
				}
			}

			// Check basename glob patterns
			if !commandMatched {
				for _, g := range r.basenameGlobs {
					if g.Match(cmdBase) || g.Match(filepath.Base(command)) {
						commandMatched = true
						break
					}
				}
			}
		}

		if !commandMatched {
			continue
		}

		// Check argument patterns if specified (regex on joined args string)
		if len(r.argsRegexes) > 0 {
			argsJoined := strings.Join(args, " ")
			matched := false
			for _, re := range r.argsRegexes {
				if re.MatchString(argsJoined) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		dec := e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, r.rule.RedirectTo)
		dec.EnvPolicy = MergeEnvPolicy(e.policy.EnvPolicy, r.rule)
		return dec
	}
	// Default deny (consistent with file_rules, network_rules, and unix_socket_rules).
	dec := e.wrapDecision(string(types.DecisionDeny), "default-deny-commands", "", nil)
	dec.EnvPolicy = MergeEnvPolicy(e.policy.EnvPolicy, CommandRule{})
	return dec
}

func (e *Engine) CheckFile(p string, operation string) Decision {
	operation = strings.ToLower(operation)
	for _, r := range e.compiledFileRules {
		if !matchOp(r.ops, operation) {
			continue
		}
		for _, g := range r.globs {
			if g.Match(p) {
				dec := e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, nil)

				// Handle file redirect if configured
				if r.redirectTo != "" && dec.PolicyDecision == types.DecisionRedirect {
					dec.FileRedirect = computeFileRedirect(p, operation, r.redirectTo, r.preserveTree, r.rule.Message)
				}

				return dec
			}
		}
	}
	// Default deny (policy files typically include an explicit default deny, but we enforce it here too).
	return e.wrapDecision(string(types.DecisionDeny), "default-deny-files", "", nil)
}

// computeFileRedirect calculates the redirected path for a file operation.
func computeFileRedirect(originalPath, operation, targetBase string, preserveTree bool, msg string) *types.FileRedirectInfo {
	var newPath string
	if preserveTree {
		// /home/user/file.txt -> /workspace/.scratch/home/user/file.txt
		newPath = filepath.Join(targetBase, originalPath)
	} else {
		// /home/user/file.txt -> /workspace/.scratch/file.txt
		newPath = filepath.Join(targetBase, filepath.Base(originalPath))
	}

	return &types.FileRedirectInfo{
		OriginalPath: originalPath,
		RedirectPath: newPath,
		Operation:    operation,
		Reason:       msg,
	}
}

// CheckUnixSocket evaluates unix_socket_rules against a path and operation (connect|bind|listen|sendto).
// Paths for abstract sockets should be passed as "@name".
func (e *Engine) CheckUnixSocket(path string, operation string) Decision {
	operation = strings.ToLower(strings.TrimSpace(operation))
	for _, r := range e.compiledUnixRules {
		if !matchOp(r.ops, operation) {
			continue
		}
		for _, g := range r.paths {
			if g.Match(path) {
				return e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, nil)
			}
		}
	}
	return e.wrapDecision(string(types.DecisionDeny), "default-deny-unix", "", nil)
}

// CheckRegistry evaluates registry_rules against a path and operation.
func (e *Engine) CheckRegistry(path string, operation string) Decision {
	if e.policy == nil {
		return Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
	}
	operation = strings.ToLower(operation)
	pathUpper := strings.ToUpper(path)

	for _, r := range e.compiledRegistryRules {
		if !matchOp(r.ops, operation) {
			continue
		}
		for _, g := range r.globs {
			if g.Match(path) || g.Match(pathUpper) {
				return e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, nil)
			}
		}
	}
	return e.wrapDecision(string(types.DecisionDeny), "default-deny-registry", "", nil)
}

// EnvDecision represents the result of CheckEnv with additional metadata.
type EnvDecision struct {
	Allowed   bool
	MatchedBy string // "allow", "deny", "default-allow", "default-deny"
	Pattern   string // The pattern that matched, if any
}

// CheckEnv evaluates the env policy against an environment variable name.
// Returns whether the variable is allowed and what matched.
// Logic: deny patterns are checked first (deny wins), then allow patterns.
// If no allow patterns defined, default is allow (unless denied).
// If allow patterns defined, default is deny (unless allowed).
func (e *Engine) CheckEnv(name string) EnvDecision {
	if e == nil || e.policy == nil {
		return EnvDecision{Allowed: true, MatchedBy: "default-allow"}
	}

	// Check deny patterns first (deny always wins)
	for i, g := range e.compiledEnvDeny {
		if g.Match(name) {
			pattern := ""
			if i < len(e.policy.EnvPolicy.Deny) {
				pattern = e.policy.EnvPolicy.Deny[i]
			}
			return EnvDecision{Allowed: false, MatchedBy: "deny", Pattern: pattern}
		}
	}

	// Check defaultSecretDeny patterns when no allow patterns defined
	if len(e.compiledEnvAllow) == 0 {
		for _, secret := range defaultSecretDeny {
			if name == secret {
				return EnvDecision{Allowed: false, MatchedBy: "default-secret-deny", Pattern: secret}
			}
		}
		// No allow patterns and not denied = allow
		return EnvDecision{Allowed: true, MatchedBy: "default-allow"}
	}

	// Check allow patterns
	for i, g := range e.compiledEnvAllow {
		if g.Match(name) {
			pattern := ""
			if i < len(e.policy.EnvPolicy.Allow) {
				pattern = e.policy.EnvPolicy.Allow[i]
			}
			return EnvDecision{Allowed: true, MatchedBy: "allow", Pattern: pattern}
		}
	}

	// Allow patterns defined but none matched = deny
	return EnvDecision{Allowed: false, MatchedBy: "default-deny"}
}

// EnvPolicy returns the raw env policy for configuration inspection.
func (e *Engine) EnvPolicy() EnvPolicy {
	if e == nil || e.policy == nil {
		return EnvPolicy{}
	}
	return e.policy.EnvPolicy
}

// GetEnvInject returns the env_inject map from the policy.
// Returns an empty map if engine, policy, or EnvInject is nil.
func (e *Engine) GetEnvInject() map[string]string {
	if e == nil || e.policy == nil || e.policy.EnvInject == nil {
		return map[string]string{}
	}
	return e.policy.EnvInject
}

// CheckNetwork evaluates network_rules against a domain and port.
// Deprecated: Use CheckNetworkCtx for proper cancellation support.
func (e *Engine) CheckNetwork(domain string, port int) Decision {
	return e.CheckNetworkCtx(context.Background(), domain, port)
}

// CheckNetworkCtx evaluates network_rules against a domain and port with context support.
// If a rule requires CIDR matching and the domain is not an IP literal, DNS resolution
// will be performed using the provided context for cancellation.
func (e *Engine) CheckNetworkCtx(ctx context.Context, domain string, port int) Decision {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Threat feed pre-check.
	var threatResult *ThreatCheckResult
	if e.threatStore != nil {
		if entry, matched := e.threatStore.Check(domain); matched {
			if e.threatAction == "deny" {
				dec := e.wrapDecision("deny", "threat-feed:"+entry.FeedName,
					"domain matched threat feed: "+entry.FeedName+" (matched: "+entry.MatchedDomain+")", nil)
				dec.ThreatFeed = entry.FeedName
				dec.ThreatMatch = entry.MatchedDomain
				dec.ThreatAction = "deny"
				return dec
			}
			// Audit mode: record threat metadata, continue normal rule evaluation.
			threatResult = &entry
		}
	}

	var (
		ips      []net.IP
		resolved bool
	)
	if ip := net.ParseIP(domain); ip != nil {
		ips = []net.IP{ip}
		resolved = true
	}

	resolveIPs := func() {
		if resolved || domain == "" {
			return
		}
		resolved = true
		// Use caller's context with a reasonable upper bound timeout
		resolveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, domain)
		if err != nil {
			return
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}

	for _, r := range e.compiledNetworkRules {
		if len(r.ports) > 0 {
			if _, ok := r.ports[port]; !ok {
				continue
			}
		}

		// Match domains if present.
		if len(r.domainGlobs) > 0 {
			matched := false
			for _, g := range r.domainGlobs {
				if domain != "" && g.Match(domain) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Match CIDRs if present.
		if len(r.cidrs) > 0 {
			resolveIPs()
			matched := false
			for _, ip := range ips {
				for _, cidr := range r.cidrs {
					if cidr.Contains(ip) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				continue
			}
		}

		// If rule has no selectors, it matches (e.g., approve unknown https by port only).
		dec := e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, nil)
		if threatResult != nil {
			dec.ThreatFeed = threatResult.FeedName
			dec.ThreatMatch = threatResult.MatchedDomain
			dec.ThreatAction = "audit"
		}
		return dec
	}

	dec := e.wrapDecision(string(types.DecisionDeny), "default-deny-network", "", nil)
	if threatResult != nil {
		dec.ThreatFeed = threatResult.FeedName
		dec.ThreatMatch = threatResult.MatchedDomain
		dec.ThreatAction = "audit"
	}
	return dec
}

func matchOp(ops map[string]struct{}, op string) bool {
	if len(ops) == 0 {
		return true
	}
	if _, ok := ops["*"]; ok {
		return true
	}
	_, ok := ops[op]
	return ok
}

func (e *Engine) wrapDecision(decision string, rule string, msg string, redirect *CommandRedirect) Decision {
	pd := types.Decision(strings.ToLower(decision))
	switch pd {
	case types.DecisionAllow:
		return Decision{PolicyDecision: pd, EffectiveDecision: pd, Rule: rule, Message: msg}
	case types.DecisionDeny:
		return Decision{PolicyDecision: pd, EffectiveDecision: pd, Rule: rule, Message: msg}
	case types.DecisionApprove:
		if e.enforceApprovals {
			return Decision{
				PolicyDecision:    pd,
				EffectiveDecision: pd,
				Rule:              rule,
				Message:           msg,
				Approval:          &types.ApprovalInfo{Required: true, Mode: types.ApprovalModeEnforced},
			}
		}
		return Decision{
			PolicyDecision:    pd,
			EffectiveDecision: types.DecisionAllow,
			Rule:              rule,
			Message:           msg,
			Approval:          &types.ApprovalInfo{Required: true, Mode: types.ApprovalModeShadow},
		}
	case types.DecisionRedirect:
		return Decision{
			PolicyDecision:    pd,
			EffectiveDecision: types.DecisionAllow,
			Rule:              rule,
			Message:           msg,
			Redirect:          toRedirectInfo(redirect, msg),
		}
	case types.DecisionAudit:
		// Audit is allow + enhanced logging (caller should emit audit event)
		return Decision{
			PolicyDecision:    pd,
			EffectiveDecision: types.DecisionAllow,
			Rule:              rule,
			Message:           msg,
		}
	case types.DecisionSoftDelete:
		// Soft delete means redirect destructive operations to trash
		return Decision{
			PolicyDecision:    pd,
			EffectiveDecision: types.DecisionAllow,
			Rule:              rule,
			Message:           msg,
		}
	default:
		// Safe fallback.
		return Decision{PolicyDecision: types.DecisionDeny, EffectiveDecision: types.DecisionDeny, Rule: "invalid-policy-decision", Message: "invalid decision in policy"}
	}
}

func toRedirectInfo(r *CommandRedirect, msg string) *types.RedirectInfo {
	if r == nil || strings.TrimSpace(r.Command) == "" {
		return nil
	}
	return &types.RedirectInfo{
		Command:     r.Command,
		Args:        append([]string{}, r.Args...),
		ArgsAppend:  append([]string{}, r.ArgsAppend...),
		Environment: copyMap(r.Environment),
		Reason:      msg,
	}
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// DnsRedirectResult contains the result of DNS redirect evaluation
type DnsRedirectResult struct {
	Matched    bool
	Rule       string
	ResolveTo  string
	Visibility string
	OnFailure  string
}

// EvaluateDnsRedirect checks if a hostname should be redirected.
// The hostname is normalized (lowercased, trimmed, trailing dot removed)
// to ensure case-insensitive matching consistent with DNS semantics.
func (e *Engine) EvaluateDnsRedirect(hostname string) *DnsRedirectResult {
	hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	for _, r := range e.dnsRedirectRules {
		if r.pattern.MatchString(hostname) {
			visibility := r.rule.Visibility
			if visibility == "" {
				visibility = "audit_only"
			}
			onFailure := r.rule.OnFailure
			if onFailure == "" {
				onFailure = "fail_closed"
			}
			return &DnsRedirectResult{
				Matched:    true,
				Rule:       r.rule.Name,
				ResolveTo:  r.rule.ResolveTo,
				Visibility: visibility,
				OnFailure:  onFailure,
			}
		}
	}
	return &DnsRedirectResult{Matched: false}
}

// ConnectRedirectResult contains the result of connect redirect evaluation
type ConnectRedirectResult struct {
	Matched    bool
	Rule       string
	RedirectTo string
	TLSMode    string
	SNI        string
	Visibility string
	Message    string
	OnFailure  string
}

// EvaluateConnectRedirect checks if a connection should be redirected.
// The host portion of hostPort is normalized (lowercased, trailing dot removed)
// to ensure case-insensitive matching consistent with DNS semantics.
func (e *Engine) EvaluateConnectRedirect(hostPort string) *ConnectRedirectResult {
	hostPort = strings.TrimSpace(hostPort)
	if host, port, err := net.SplitHostPort(hostPort); err == nil {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		hostPort = net.JoinHostPort(host, port)
	} else {
		hostPort = strings.TrimSuffix(strings.ToLower(hostPort), ".")
	}
	for _, r := range e.connectRedirectRules {
		if r.pattern.MatchString(hostPort) {
			visibility := r.rule.Visibility
			if visibility == "" {
				visibility = "audit_only"
			}
			onFailure := r.rule.OnFailure
			if onFailure == "" {
				onFailure = "fail_closed"
			}
			tlsMode := "passthrough"
			sni := ""
			if r.rule.TLS != nil {
				if r.rule.TLS.Mode != "" {
					tlsMode = r.rule.TLS.Mode
				}
				sni = r.rule.TLS.SNI
			}
			return &ConnectRedirectResult{
				Matched:    true,
				Rule:       r.rule.Name,
				RedirectTo: r.rule.RedirectTo,
				TLSMode:    tlsMode,
				SNI:        sni,
				Visibility: visibility,
				Message:    r.rule.Message,
				OnFailure:  onFailure,
			}
		}
	}
	return &ConnectRedirectResult{Matched: false}
}

// CheckExecve evaluates an execve call against command rules with depth context support.
// Returns the decision from the first matching rule, or default deny if none match.
// The depth parameter represents the ancestry depth: 0 = direct (user-typed), 1+ = nested (script-spawned).
func (e *Engine) CheckExecve(filename string, argv []string, depth int) Decision {
	cmdLower := strings.ToLower(filename)
	cmdBase := strings.ToLower(filepath.Base(filename))

	for _, r := range e.compiledCommandRules {
		// Check depth/context constraint first
		if !r.rule.Context.MatchesDepth(depth) {
			continue
		}

		// Check if command matches any of the rule's patterns
		commandMatched := false

		// If no commands specified, rule applies to all commands
		if len(r.basenames) == 0 && len(r.basenameGlobs) == 0 && len(r.fullPaths) == 0 && len(r.pathGlobs) == 0 {
			commandMatched = true
		} else {
			// Check full path matches first (more specific)
			if _, ok := r.fullPaths[cmdLower]; ok {
				commandMatched = true
			}

			// Check path glob patterns
			if !commandMatched {
				for _, g := range r.pathGlobs {
					if g.Match(cmdLower) || g.Match(filename) {
						commandMatched = true
						break
					}
				}
			}

			// Check basename matches (less specific, legacy behavior)
			if !commandMatched {
				if _, ok := r.basenames[cmdBase]; ok {
					commandMatched = true
				}
			}

			// Check basename glob patterns
			if !commandMatched {
				for _, g := range r.basenameGlobs {
					if g.Match(cmdBase) || g.Match(filepath.Base(filename)) {
						commandMatched = true
						break
					}
				}
			}
		}

		if !commandMatched {
			continue
		}

		// Check argument patterns if specified (regex on joined args string)
		if len(r.argsRegexes) > 0 {
			argsJoined := strings.Join(argv, " ")
			matched := false
			for _, re := range r.argsRegexes {
				if re.MatchString(argsJoined) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		dec := e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, r.rule.RedirectTo)
		dec.EnvPolicy = MergeEnvPolicy(e.policy.EnvPolicy, r.rule)
		return dec
	}

	// Default deny (consistent with other Check* methods)
	dec := e.wrapDecision(string(types.DecisionDeny), "default-deny-execve", "", nil)
	dec.EnvPolicy = MergeEnvPolicy(e.policy.EnvPolicy, CommandRule{})
	return dec
}
