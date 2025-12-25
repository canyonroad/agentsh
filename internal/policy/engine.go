package policy

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/gobwas/glob"
)

type Engine struct {
	policy           *Policy
	enforceApprovals bool

	compiledFileRules    []compiledFileRule
	compiledNetworkRules []compiledNetworkRule
	compiledCommandRules []compiledCommandRule
	compiledUnixRules    []compiledUnixRule

	// Compiled env policy patterns for glob matching
	compiledEnvAllow []glob.Glob
	compiledEnvDeny  []glob.Glob
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
	rule      CommandRule
	commands  map[string]struct{}
	argsGlobs []glob.Glob
}

type compiledUnixRule struct {
	rule  UnixSocketRule
	paths []glob.Glob
	ops   map[string]struct{}
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
		cr := compiledCommandRule{rule: r, commands: map[string]struct{}{}}
		for _, c := range r.Commands {
			cr.commands[strings.ToLower(filepath.Base(c))] = struct{}{}
		}
		for _, pat := range r.ArgsPatterns {
			g, err := glob.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("compile command rule %q arg pattern %q: %w", r.Name, pat, err)
			}
			cr.argsGlobs = append(cr.argsGlobs, g)
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

	return e, nil
}

// NetworkRules returns the raw network rules for read-only inspection (e.g., ebpf allowlist).
func (e *Engine) NetworkRules() []NetworkRule {
	if e == nil || e.policy == nil {
		return nil
	}
	return e.policy.NetworkRules
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

		return e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, nil)
	}

	return e.wrapDecision(string(types.DecisionDeny), "default-deny-network", "", nil)
}

func (e *Engine) CheckCommand(command string, args []string) Decision {
	cmd := strings.ToLower(filepath.Base(command))
	for _, r := range e.compiledCommandRules {
		if len(r.commands) > 0 {
			if _, ok := r.commands[cmd]; !ok {
				continue
			}
		}
		if len(r.argsGlobs) > 0 && len(args) > 0 {
			matched := false
			for _, arg := range args {
				for _, g := range r.argsGlobs {
					if g.Match(arg) {
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
		dec := e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, r.rule.RedirectTo)
		dec.EnvPolicy = MergeEnvPolicy(e.policy.EnvPolicy, r.rule)
		return dec
	}
	dec := e.wrapDecision(string(types.DecisionAllow), "", "", nil)
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
		return e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, nil)
	}

	return e.wrapDecision(string(types.DecisionDeny), "default-deny-network", "", nil)
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
