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
	// Strip leading global flags so args[0] is the subcommand,
	// which is what resolvers' CanResolve expects.
	cleanArgs := stripGlobalFlags(intent.OrigArgs)
	var resolver Resolver
	for _, r := range c.cfg.Resolvers {
		if r.CanResolve(intent.Tool, cleanArgs) {
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

	// 5. Handle provider errors: collect all, then apply strictest action.
	// Process provider errors by strictness after seeing ALL of them.
	// Initialize to VerdictAllow (weight 0) so the first real action always wins.
	strictestFailAction := VerdictAllow
	var strictestFailSummary string
	hasFailAction := false
	for _, pe := range providerErrs {
		switch pe.OnFailure {
		case "deny":
			if VerdictBlock.weight() > strictestFailAction.weight() {
				strictestFailAction = VerdictBlock
				strictestFailSummary = fmt.Sprintf("Provider %s unavailable (on_failure=%s): %v", pe.Provider, pe.OnFailure, pe.Err)
				hasFailAction = true
			}
		case "approve":
			if VerdictApprove.weight() > strictestFailAction.weight() {
				strictestFailAction = VerdictApprove
				strictestFailSummary = fmt.Sprintf("Provider %s unavailable (on_failure=%s): %v", pe.Provider, pe.OnFailure, pe.Err)
				hasFailAction = true
			}
		case "warn":
			findings = append(findings, Finding{
				Type:     FindingReputation,
				Provider: pe.Provider,
				Severity: SeverityInfo,
				Title:    fmt.Sprintf("provider %s unavailable", pe.Provider),
				Detail:   pe.Err.Error(),
			})
		}
		// "allow" on failure: no finding injected, evaluator decides on existing findings.
	}

	// Apply strictest failure action.
	if hasFailAction && strictestFailAction == VerdictBlock {
		return &Verdict{
			Action:  VerdictBlock,
			Summary: strictestFailSummary,
		}, nil
	}

	// 6. Evaluate findings against policy rules.
	verdict := c.eval.Evaluate(findings, plan.Ecosystem)

	// If any provider needs approval and verdict is weaker, upgrade to approve.
	if hasFailAction && strictestFailAction == VerdictApprove && verdict.Action.weight() < VerdictApprove.weight() {
		verdict.Action = VerdictApprove
	}

	// 7. Populate allowlist for allow/warn verdicts.
	if c.cfg.Allowlist != nil && (verdict.Action == VerdictAllow || verdict.Action == VerdictWarn) {
		registry := plan.Registry
		for _, pkg := range plan.AllPackages() {
			c.cfg.Allowlist.Add(registry, pkg.Name, pkg.Version)
		}
	}

	// 8. Enrich summary with package list; append provider failure reason if present.
	verdict.Summary = buildCheckerSummary(intent, plan, verdict)
	if hasFailAction && strictestFailSummary != "" {
		verdict.Summary = verdict.Summary + "; " + strictestFailSummary
	}

	return verdict, nil
}

// stripGlobalFlags removes leading global flags from args so that args[0]
// is the subcommand. Resolvers' CanResolve expects args[0] to be the
// subcommand (e.g., "install", "add", "pip"), but raw command args may
// contain leading flags like "--prefix /tmp".
func stripGlobalFlags(args []string) []string {
	sub, remaining := skipGlobalFlags(args)
	if sub == "" {
		return args
	}
	return append([]string{sub}, remaining...)
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
