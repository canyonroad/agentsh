package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

// PoetryResolverConfig configures the poetry resolver.
type PoetryResolverConfig struct {
	// DryRunCommand is the path to the poetry binary; defaults to "poetry".
	// For additional args to prepend to the resolver-specific args, use DryRunArgs.
	DryRunCommand string
	// DryRunArgs contains args to prepend to the resolver-specific args.
	// Each element is a single token (no shell splitting is performed).
	DryRunArgs []string
	Timeout    time.Duration // timeout for dry-run execution
}

type poetryResolver struct {
	cfg        PoetryResolverConfig
	binary     string
	prefixArgs []string
}

// NewPoetryResolver creates a resolver for poetry add commands.
func NewPoetryResolver(cfg PoetryResolverConfig) pkgcheck.Resolver {
	if cfg.DryRunCommand == "" {
		cfg.DryRunCommand = "poetry"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	// DryRunCommand is the binary path only; DryRunArgs carries any prefix args.
	// No shell splitting is performed so paths with spaces are preserved verbatim.
	return &poetryResolver{cfg: cfg, binary: cfg.DryRunCommand, prefixArgs: cfg.DryRunArgs}
}

func (r *poetryResolver) Name() string { return "poetry" }

func (r *poetryResolver) CanResolve(command string, args []string) bool {
	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimSuffix(base, ".cmd")
	base = strings.TrimSuffix(base, ".bat")
	if base != "poetry" {
		return false
	}
	if len(args) == 0 {
		return false
	}
	// Only "add" is supported by Resolve (which runs poetry add --dry-run).
	return args[0] == "add"
}

func (r *poetryResolver) Resolve(ctx context.Context, workDir string, command []string) (*pkgcheck.InstallPlan, error) {
	var packages []string
	if len(command) > 1 {
		packages = extractPkgArgs(command[1:])
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	// poetry add --dry-run <packages>
	cmdArgs := []string{"add", "--dry-run"}
	cmdArgs = append(cmdArgs, packages...)
	allArgs := append(append([]string(nil), r.prefixArgs...), cmdArgs...)

	cmd := exec.CommandContext(ctx, r.binary, allArgs...)
	cmd.Dir = workDir

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("poetry dry-run failed: %w", err)
	}

	// TODO: poetry has no equivalent CLI registry override flag; the registry is
	// configured via [[tool.poetry.source]] in pyproject.toml. Reading that file
	// to detect a custom source URL is future work. For now the plan always carries
	// "pypi.org" regardless of the project's source configuration.
	return parsePoetryDryRunOutput(out, packages)
}

// poetryDryRunOutput represents poetry's JSON output structure.
type poetryDryRunOutput struct {
	Added []poetryDryRunPkg `json:"added"`
}

type poetryDryRunPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parsePoetryDryRunOutput parses poetry's output into an InstallPlan.
// TODO: The expected JSON format {"added":[...]} needs verification against actual
// poetry CLI output. `poetry add --dry-run` outputs text lines like
// "- Installing package (version)", not JSON.
func parsePoetryDryRunOutput(data []byte, requestedPkgs []string) (*pkgcheck.InstallPlan, error) {
	var output poetryDryRunOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse poetry JSON output: %w", err)
	}

	requested := make(map[string]bool, len(requestedPkgs))
	for _, p := range requestedPkgs {
		name := strings.ToLower(pkgBaseName(p))
		requested[name] = true
	}

	plan := &pkgcheck.InstallPlan{
		Tool:      "poetry",
		Ecosystem: pkgcheck.EcosystemPyPI,
		// Default to public PyPI. Poetry's [[tool.poetry.source]] blocks
		// in pyproject.toml can redirect to a private registry, but we
		// do not parse pyproject.toml. Operators using a private Poetry
		// source must:
		//   1. Add their private registry URL to ExternalScanRegistries
		//      so private packages reach external providers, OR
		//   2. Set external_scan_registries: [] to disable the privacy
		//      filter entirely if all their dependencies are private.
		// This matches pip/uv defaulting behavior.
		Registry:   "pypi.org",
		ResolvedAt: time.Now(),
	}

	for _, pkg := range output.Added {
		ref := pkgcheck.PackageRef{
			Name:    pkg.Name,
			Version: pkg.Version,
		}
		if requested[strings.ToLower(pkg.Name)] {
			ref.Direct = true
			plan.Direct = append(plan.Direct, ref)
		} else {
			plan.Transitive = append(plan.Transitive, ref)
		}
	}

	return plan, nil
}
