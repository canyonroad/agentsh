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
	// DryRunCommand is the path to the npm binary; defaults to "npm".
	// For additional args to prepend to the resolver-specific args, use DryRunArgs.
	DryRunCommand string
	// DryRunArgs contains args to prepend to the resolver-specific args.
	// Each element is a single token (no shell splitting is performed).
	DryRunArgs []string
	Timeout    time.Duration // timeout for dry-run execution
}

type npmResolver struct {
	cfg        NPMResolverConfig
	binary     string
	prefixArgs []string
}

// NewNPMResolver creates a resolver for npm install commands.
func NewNPMResolver(cfg NPMResolverConfig) pkgcheck.Resolver {
	if cfg.DryRunCommand == "" {
		cfg.DryRunCommand = "npm"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	// DryRunCommand is the binary path only; DryRunArgs carries any prefix args.
	// No shell splitting is performed so paths with spaces are preserved verbatim.
	return &npmResolver{cfg: cfg, binary: cfg.DryRunCommand, prefixArgs: cfg.DryRunArgs}
}

func (r *npmResolver) Name() string { return "npm" }

func (r *npmResolver) CanResolve(command string, args []string) bool {
	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimSuffix(base, ".cmd")
	base = strings.TrimSuffix(base, ".bat")
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
	var args []string
	if len(command) > 1 {
		args = command[1:]
		packages = extractPkgArgs(args)
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	// npm install --package-lock-only --ignore-scripts --json <packages>
	cmdArgs := []string{"install", "--package-lock-only", "--ignore-scripts", "--json"}
	cmdArgs = append(cmdArgs, packages...)
	allArgs := append(append([]string(nil), r.prefixArgs...), cmdArgs...)

	cmd := exec.CommandContext(ctx, r.binary, allArgs...)
	cmd.Dir = workDir

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("npm dry-run failed: %w", err)
	}

	plan, err := parseNPMDryRunOutput(out, packages)
	if err != nil {
		return nil, err
	}
	planRegistry := r.detectRegistry(args)
	plan.Registry = planRegistry
	explicitFlag := r.hasRegistryFlag(args)
	// Scoped packages may resolve from a private registry per .npmrc scope
	// directives. Without an explicit --registry CLI flag we cannot prove the
	// resolved origin, so leave Registry empty and let the privacy filter fail
	// closed (over-skip rather than risk leaking the package name externally).
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

// detectRegistry scans the install command args for an explicit --registry
// flag and returns its value. Falls back to the public npm registry.
func (r *npmResolver) detectRegistry(args []string) string {
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

// isScopedPackage reports whether name is a scoped npm package (e.g. @acme/foo).
// Scoped packages can be routed to a private registry via .npmrc
// "scope:registry" directives that we cannot read. Without an explicit
// --registry CLI flag we cannot prove the resolved origin, so callers
// leave Registry empty for scoped packages (fail closed).
func isScopedPackage(name string) bool {
	return strings.HasPrefix(name, "@") && strings.Contains(name, "/")
}

// hasRegistryFlag reports whether the args slice contains an explicit
// --registry flag (with or without =).
func (r *npmResolver) hasRegistryFlag(args []string) bool {
	for _, a := range args {
		if a == "--registry" || strings.HasPrefix(a, "--registry=") {
			return true
		}
	}
	return false
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
