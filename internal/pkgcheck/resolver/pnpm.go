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

// PNPMResolverConfig configures the pnpm resolver.
type PNPMResolverConfig struct {
	DryRunCommand string        // path to pnpm binary; defaults to "pnpm"
	Timeout       time.Duration // timeout for dry-run execution
}

type pnpmResolver struct {
	cfg PNPMResolverConfig
}

// NewPNPMResolver creates a resolver for pnpm add commands.
func NewPNPMResolver(cfg PNPMResolverConfig) pkgcheck.Resolver {
	if cfg.DryRunCommand == "" {
		cfg.DryRunCommand = "pnpm"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &pnpmResolver{cfg: cfg}
}

func (r *pnpmResolver) Name() string { return "pnpm" }

func (r *pnpmResolver) CanResolve(command string, args []string) bool {
	base := filepath.Base(command)
	base = strings.TrimSuffix(base, ".exe")
	base = trimWindowsScriptExt(base)
	if base != "pnpm" {
		return false
	}
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "add", "install", "i":
		return true
	default:
		return false
	}
}

func (r *pnpmResolver) Resolve(ctx context.Context, workDir string, command []string) (*pkgcheck.InstallPlan, error) {
	var packages []string
	if len(command) > 1 {
		packages = extractPkgArgs(command[1:])
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	// pnpm add --lockfile-only --ignore-scripts <packages>
	cmdArgs := []string{"add", "--lockfile-only", "--ignore-scripts"}
	cmdArgs = append(cmdArgs, packages...)

	cmd := exec.CommandContext(ctx, r.cfg.DryRunCommand, cmdArgs...)
	cmd.Dir = workDir

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("pnpm dry-run failed: %w", err)
	}

	return parsePNPMDryRunOutput(out, packages)
}

// pnpmDryRunOutput represents pnpm's JSON output structure.
type pnpmDryRunOutput struct {
	Added []pnpmDryRunPkg `json:"added"`
}

type pnpmDryRunPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parsePNPMDryRunOutput parses pnpm's output into an InstallPlan.
// TODO: The expected JSON format {"added":[...]} needs verification against actual
// pnpm CLI output. `pnpm add --dry-run` outputs text, not JSON.
func parsePNPMDryRunOutput(data []byte, requestedPkgs []string) (*pkgcheck.InstallPlan, error) {
	var output pnpmDryRunOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse pnpm JSON output: %w", err)
	}

	requested := make(map[string]bool, len(requestedPkgs))
	for _, p := range requestedPkgs {
		name := pkgBaseName(p)
		requested[name] = true
	}

	plan := &pkgcheck.InstallPlan{
		Tool:       "pnpm",
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
