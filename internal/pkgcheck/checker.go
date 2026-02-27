package pkgcheck

import (
	"context"
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/internal/policy"
)

// CheckerConfig holds all dependencies for the top-level package checker.
type CheckerConfig struct {
	Scope     string // "new_packages_only" | "all_installs"
	Resolvers []Resolver
	Providers map[string]ProviderEntry
	Rules     []policy.PackageRule
	Allowlist *Allowlist
}

// Checker is the single entry point for package install checks.
// It classifies the command, resolves the install plan, runs provider checks
// in parallel, evaluates findings via policy rules, and returns a verdict.
type Checker struct {
	cfg  CheckerConfig
	orch *Orchestrator
	eval *Evaluator
}

// NewChecker creates a new Checker wired to the given config.
func NewChecker(cfg CheckerConfig) *Checker {
	return &Checker{
		cfg: cfg,
		orch: NewOrchestrator(OrchestratorConfig{
			Providers: cfg.Providers,
		}),
		eval: NewEvaluator(cfg.Rules),
	}
}

// Check evaluates a command. Returns a nil verdict if the command is not a
// recognised package-install operation.
func (c *Checker) Check(ctx context.Context, command string, args []string, workDir string) (*Verdict, error) {
	// 1. Classify the command.
	intent := ClassifyInstallCommand(command, args, c.cfg.Scope)
	if intent == nil {
		return nil, nil
	}

	// 2. Find a resolver that can handle this tool.
	var resolver Resolver
	for _, r := range c.cfg.Resolvers {
		if r.CanResolve(intent.Tool, intent.OrigArgs) {
			resolver = r
			break
		}
	}
	if resolver == nil {
		return nil, fmt.Errorf("no resolver for tool %q", intent.Tool)
	}

	// 3. Resolve the install plan.
	fullArgs := append([]string{command}, args...)
	plan, err := resolver.Resolve(ctx, workDir, fullArgs)
	if err != nil {
		return nil, fmt.Errorf("resolve install plan: %w", err)
	}

	// 4. Run all providers in parallel.
	findings, providerErrs := c.orch.CheckAll(ctx, CheckRequest{
		Ecosystem: plan.Ecosystem,
		Packages:  plan.AllPackages(),
	})

	// 5. Handle provider errors.
	for _, pe := range providerErrs {
		if pe.OnFailure == "deny" {
			return &Verdict{
				Action:  VerdictBlock,
				Summary: fmt.Sprintf("provider %s failed and on_failure=deny: %v", pe.Provider, pe.Err),
			}, nil
		}
		// For "approve", "warn", or "allow" on failure — add a finding so evaluator can decide.
		if pe.OnFailure == "approve" || pe.OnFailure == "warn" {
			findings = append(findings, Finding{
				Type:     FindingReputation,
				Provider: pe.Provider,
				Severity: SeverityInfo,
				Title:    fmt.Sprintf("provider %s unavailable", pe.Provider),
				Detail:   pe.Err.Error(),
			})
		}
	}

	// 6. Evaluate findings against policy rules.
	verdict := c.eval.Evaluate(findings, plan.Ecosystem)

	// 7. Populate allowlist for allow/warn verdicts.
	if c.cfg.Allowlist != nil && (verdict.Action == VerdictAllow || verdict.Action == VerdictWarn) {
		registry := plan.Registry
		for _, pkg := range plan.AllPackages() {
			c.cfg.Allowlist.Add(registry, pkg.Name, pkg.Version)
		}
	}

	// 8. Enrich summary with package list.
	verdict.Summary = buildCheckerSummary(intent, plan, verdict)

	return verdict, nil
}

// buildCheckerSummary creates a human-readable summary for the verdict.
func buildCheckerSummary(intent *InstallIntent, plan *InstallPlan, verdict *Verdict) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s] ", intent.Tool))

	pkgNames := make([]string, 0, len(plan.Direct))
	for _, p := range plan.Direct {
		pkgNames = append(pkgNames, p.String())
	}
	if len(pkgNames) > 0 {
		sb.WriteString(strings.Join(pkgNames, ", "))
	} else {
		sb.WriteString("bulk install")
	}

	sb.WriteString(fmt.Sprintf(" -> %s", verdict.Action))
	if len(verdict.Findings) > 0 {
		sb.WriteString(fmt.Sprintf(" (%d finding(s))", len(verdict.Findings)))
	}
	return sb.String()
}
