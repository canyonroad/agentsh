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

// YarnResolverConfig configures the yarn resolver.
type YarnResolverConfig struct {
	DryRunCommand string        // path to yarn binary; defaults to "yarn"
	Timeout       time.Duration // timeout for dry-run execution
}

type yarnResolver struct {
	cfg YarnResolverConfig
}

// NewYarnResolver creates a resolver for yarn add commands.
func NewYarnResolver(cfg YarnResolverConfig) pkgcheck.Resolver {
	if cfg.DryRunCommand == "" {
		cfg.DryRunCommand = "yarn"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &yarnResolver{cfg: cfg}
}

func (r *yarnResolver) Name() string { return "yarn" }

func (r *yarnResolver) CanResolve(command string, args []string) bool {
	base := filepath.Base(command)
	base = strings.TrimSuffix(base, ".exe")
	base = trimWindowsScriptExt(base)
	base = strings.ToLower(base)
	if base != "yarn" {
		return false
	}
	if len(args) == 0 {
		return false
	}
	// Only "add" is supported by Resolve (which runs yarn add --mode update-lockfile).
	return args[0] == "add"
}

func (r *yarnResolver) Resolve(ctx context.Context, workDir string, command []string) (*pkgcheck.InstallPlan, error) {
	var packages []string
	if len(command) > 1 {
		packages = extractPkgArgs(command[1:])
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	// yarn add --mode update-lockfile <packages>
	cmdArgs := []string{"add", "--mode", "update-lockfile"}
	cmdArgs = append(cmdArgs, packages...)

	cmd := exec.CommandContext(ctx, r.cfg.DryRunCommand, cmdArgs...)
	cmd.Dir = workDir

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("yarn dry-run failed: %w", err)
	}

	return parseYarnDryRunOutput(out, packages)
}

// yarnDryRunOutput represents yarn's JSON output structure.
type yarnDryRunOutput struct {
	Added []yarnDryRunPkg `json:"added"`
}

type yarnDryRunPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parseYarnDryRunOutput parses yarn's output into an InstallPlan.
// TODO: The expected JSON format {"added":[...]} needs verification against actual
// yarn CLI output. Yarn v1 --json outputs ndjson; v2+ may differ.
func parseYarnDryRunOutput(data []byte, requestedPkgs []string) (*pkgcheck.InstallPlan, error) {
	var output yarnDryRunOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse yarn JSON output: %w", err)
	}

	requested := make(map[string]bool, len(requestedPkgs))
	for _, p := range requestedPkgs {
		name := pkgBaseName(p)
		requested[name] = true
	}

	plan := &pkgcheck.InstallPlan{
		Tool:       "yarn",
		Ecosystem:  pkgcheck.EcosystemNPM,
		ResolvedAt: time.Now(),
	}

	for _, pkg := range output.Added {
		ref := pkgcheck.PackageRef{
			Name:    pkg.Name,
			Version: pkg.Version,
		}
		if requested[pkg.Name] {
			ref.Direct = true
			plan.Direct = append(plan.Direct, ref)
		} else {
			plan.Transitive = append(plan.Transitive, ref)
		}
	}

	return plan, nil
}
