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

// NPMResolverConfig configures the NPM resolver.
type NPMResolverConfig struct {
	DryRunCommand string        // path to npm binary; defaults to "npm"
	Timeout       time.Duration // timeout for dry-run execution
}

type npmResolver struct {
	cfg NPMResolverConfig
}

// NewNPMResolver creates a resolver for npm install commands.
func NewNPMResolver(cfg NPMResolverConfig) pkgcheck.Resolver {
	if cfg.DryRunCommand == "" {
		cfg.DryRunCommand = "npm"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &npmResolver{cfg: cfg}
}

func (r *npmResolver) Name() string { return "npm" }

func (r *npmResolver) CanResolve(command string, args []string) bool {
	base := filepath.Base(command)
	base = strings.TrimSuffix(base, ".exe")
	base = trimWindowsScriptExt(base)
	base = strings.ToLower(base)
	if base != "npm" {
		return false
	}
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "install", "i", "add":
		return true
	default:
		return false
	}
}

func (r *npmResolver) Resolve(ctx context.Context, workDir string, command []string) (*pkgcheck.InstallPlan, error) {
	// Extract package args (skip the subcommand, filter flags)
	var packages []string
	if len(command) > 1 {
		packages = extractPkgArgs(command[1:])
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	// npm install --package-lock-only --ignore-scripts --json <packages>
	cmdArgs := []string{"install", "--package-lock-only", "--ignore-scripts", "--json"}
	cmdArgs = append(cmdArgs, packages...)

	cmd := exec.CommandContext(ctx, r.cfg.DryRunCommand, cmdArgs...)
	cmd.Dir = workDir

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("npm dry-run failed: %w", err)
	}

	return parseNPMDryRunOutput(out, packages)
}

// npmDryRunOutput represents the JSON output from npm install --json.
type npmDryRunOutput struct {
	Added []npmDryRunPkg `json:"added"`
}

type npmDryRunPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parseNPMDryRunOutput parses npm's --json output into an InstallPlan.
func parseNPMDryRunOutput(data []byte, requestedPkgs []string) (*pkgcheck.InstallPlan, error) {
	var output npmDryRunOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse npm JSON output: %w", err)
	}

	// Build a set of requested package base names (without version specs)
	requested := make(map[string]bool, len(requestedPkgs))
	for _, p := range requestedPkgs {
		name := pkgBaseName(p)
		requested[name] = true
	}

	plan := &pkgcheck.InstallPlan{
		Tool:       "npm",
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

// extractPkgArgs filters command args to return only package names/specs,
// skipping the subcommand, flags and their values.
func extractPkgArgs(args []string) []string {
	var pkgs []string
	skipNext := false
	foundSub := false

	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}

		// Skip the subcommand (first non-flag arg like "install", "add")
		if !foundSub {
			if !strings.HasPrefix(arg, "-") {
				foundSub = true
				// This is the subcommand; for npm the caller already strips it
				// but for safety we check if it looks like a subcommand
				switch arg {
				case "install", "i", "add", "pip":
					continue
				}
				// Otherwise it's a package name
				pkgs = append(pkgs, arg)
				continue
			}
		}

		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "=") {
				continue
			}
			if flagsWithValues[arg] {
				skipNext = true
			}
			continue
		}

		pkgs = append(pkgs, arg)
	}

	return pkgs
}

// flagsWithValues lists flags that consume the next argument.
var flagsWithValues = map[string]bool{
	"--registry":        true,
	"--save-prefix":     true,
	"--tag":             true,
	"--cache":           true,
	"--prefix":          true,
	"--target":          true,
	"--index-url":       true,
	"--extra-index-url": true,
	"-i":                true,
	"-c":                true,
	"--constraint":      true,
	"--root":            true,
	"--python":          true,
	"--config-file":     true,
	"--group":           true,
	"-G":                true,
	"-r":                true,
	"--requirement":     true,
}

// pkgBaseName strips version specs from a package name.
// e.g., "express@4.18.0" -> "express", "requests>=2.28" -> "requests"
func pkgBaseName(spec string) string {
	// Handle scoped npm packages like @types/node@20.0.0
	if strings.HasPrefix(spec, "@") {
		// Find the second @ which separates scope/name from version
		idx := strings.Index(spec[1:], "@")
		if idx >= 0 {
			return spec[:idx+1]
		}
		// No version, check for other specifiers
		for _, sep := range []string{">=", "<=", "!=", "==", ">", "<", "~="} {
			if i := strings.Index(spec, sep); i > 0 {
				return spec[:i]
			}
		}
		return spec
	}

	// Regular packages
	if idx := strings.IndexByte(spec, '@'); idx > 0 {
		return spec[:idx]
	}
	for _, sep := range []string{">=", "<=", "!=", "==", ">", "<", "~="} {
		if i := strings.Index(spec, sep); i > 0 {
			return spec[:i]
		}
	}
	return spec
}

// trimWindowsScriptExt strips .cmd and .bat extensions (case-insensitive)
// from a command base name for Windows compatibility.
func trimWindowsScriptExt(base string) string {
	if len(base) < 5 {
		return base
	}
	ext := strings.ToLower(base[len(base)-4:])
	if ext == ".cmd" || ext == ".bat" {
		return base[:len(base)-4]
	}
	return base
}
