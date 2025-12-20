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
	rule  FileRule
	globs []glob.Glob
	ops   map[string]struct{}
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

type Decision struct {
	PolicyDecision    types.Decision
	EffectiveDecision types.Decision
	Rule              string
	Message           string
	Approval          *types.ApprovalInfo
	Redirect          *types.RedirectInfo
}

func NewEngine(p *Policy, enforceApprovals bool) (*Engine, error) {
	e := &Engine{
		policy:           p,
		enforceApprovals: enforceApprovals,
	}

	for _, r := range p.FileRules {
		cr := compiledFileRule{rule: r, ops: map[string]struct{}{}}
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
		return e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, r.rule.RedirectTo)
	}
	return e.wrapDecision(string(types.DecisionAllow), "", "", nil)
}

func (e *Engine) CheckFile(p string, operation string) Decision {
	operation = strings.ToLower(operation)
	for _, r := range e.compiledFileRules {
		if !matchOp(r.ops, operation) {
			continue
		}
		for _, g := range r.globs {
			if g.Match(p) {
				return e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, nil)
			}
		}
	}
	// Default deny (policy files typically include an explicit default deny, but we enforce it here too).
	return e.wrapDecision(string(types.DecisionDeny), "default-deny-files", "", nil)
}

func (e *Engine) CheckNetwork(domain string, port int) Decision {
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
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
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
		Command: r.Command,
		Args:    append([]string{}, r.Args...),
		Reason:  msg,
	}
}
