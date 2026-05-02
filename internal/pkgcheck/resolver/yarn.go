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
	// DryRunCommand is the path to the yarn binary; defaults to "yarn".
	// For additional args to prepend to the resolver-specific args, use DryRunArgs.
	DryRunCommand string
	// DryRunArgs contains args to prepend to the resolver-specific args.
	// Each element is a single token (no shell splitting is performed).
	DryRunArgs []string
	Timeout    time.Duration // timeout for dry-run execution
}

type yarnResolver struct {
	cfg        YarnResolverConfig
	binary     string
	prefixArgs []string
}

// NewYarnResolver creates a resolver for yarn add commands.
func NewYarnResolver(cfg YarnResolverConfig) pkgcheck.Resolver {
	if cfg.DryRunCommand == "" {
		cfg.DryRunCommand = "yarn"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	// DryRunCommand is the binary path only; DryRunArgs carries any prefix args.
	// No shell splitting is performed so paths with spaces are preserved verbatim.
	return &yarnResolver{cfg: cfg, binary: cfg.DryRunCommand, prefixArgs: cfg.DryRunArgs}
}

func (r *yarnResolver) Name() string { return "yarn" }

func (r *yarnResolver) CanResolve(command string, args []string) bool {
	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimSuffix(base, ".cmd")
	base = strings.TrimSuffix(base, ".bat")
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
	var args []string
	if len(command) > 1 {
		args = command[1:]
		packages = extractPkgArgs(args)
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	// yarn add --mode update-lockfile <packages>
	cmdArgs := []string{"add", "--mode", "update-lockfile"}
	cmdArgs = append(cmdArgs, packages...)
	allArgs := append(append([]string(nil), r.prefixArgs...), cmdArgs...)

	cmd := exec.CommandContext(ctx, r.binary, allArgs...)
	cmd.Dir = workDir

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("yarn dry-run failed: %w", err)
	}

	plan, err := parseYarnDryRunOutput(out, packages)
	if err != nil {
		return nil, err
	}
	planRegistry := r.detectRegistry(args)
	plan.Registry = planRegistry
	explicitFlag := r.hasRegistryFlag(args)
	for i := range plan.Direct {
		if isScopedPackage(plan.Direct[i].Name) && !explicitFlag {
			plan.Direct[i].Registry = ""
		} else {
			plan.Direct[i].Registry = planRegistry
		}
	}
	for i := range plan.Transitive {
		if isScopedPackage(plan.Transitive[i].Name) && !explicitFlag {
			plan.Transitive[i].Registry = ""
		} else {
			plan.Transitive[i].Registry = planRegistry
		}
	}
	return plan, nil
}

// hasRegistryFlag reports whether the args slice contains an explicit
// --registry flag (with or without =).
func (r *yarnResolver) hasRegistryFlag(args []string) bool {
	for _, a := range args {
		if a == "--registry" || strings.HasPrefix(a, "--registry=") {
			return true
		}
	}
	return false
}

// detectRegistry scans the install command args for an explicit --registry
// flag and returns its value. Falls back to the public npm registry.
// yarn 1.x supports --registry; yarn 2+ uses different config but
// the CLI flag still works for overrides.
func (r *yarnResolver) detectRegistry(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--registry" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "--registry=") {
			return strings.TrimPrefix(a, "--registry=")
		}
	}
	return "registry.npmjs.org"
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
		Registry:   "registry.npmjs.org",
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
