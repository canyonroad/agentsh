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

// PipResolverConfig configures the pip resolver.
type PipResolverConfig struct {
	// DryRunCommand is the path to the pip binary; defaults to "pip".
	// For additional args to prepend to the resolver-specific args, use DryRunArgs.
	DryRunCommand string
	// DryRunArgs contains args to prepend to the resolver-specific args.
	// Each element is a single token (no shell splitting is performed).
	DryRunArgs []string
	Timeout    time.Duration // timeout for dry-run execution
}

type pipResolver struct {
	cfg        PipResolverConfig
	binary     string
	prefixArgs []string
}

// NewPipResolver creates a resolver for pip install commands.
func NewPipResolver(cfg PipResolverConfig) pkgcheck.Resolver {
	if cfg.DryRunCommand == "" {
		cfg.DryRunCommand = "pip"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	// DryRunCommand is the binary path only; DryRunArgs carries any prefix args.
	// No shell splitting is performed so paths with spaces are preserved verbatim.
	return &pipResolver{cfg: cfg, binary: cfg.DryRunCommand, prefixArgs: cfg.DryRunArgs}
}

func (r *pipResolver) Name() string { return "pip" }

func (r *pipResolver) CanResolve(command string, args []string) bool {
	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimSuffix(base, ".cmd")
	base = strings.TrimSuffix(base, ".bat")
	if base != "pip" && base != "pip3" {
		return false
	}
	if len(args) == 0 {
		return false
	}
	return args[0] == "install"
}

func (r *pipResolver) Resolve(ctx context.Context, workDir string, command []string) (*pkgcheck.InstallPlan, error) {
	var packages []string
	var args []string
	if len(command) > 1 {
		args = command[1:]
		packages = extractPkgArgs(args)
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	// pip install --dry-run --report - [--index-url <url>] [--extra-index-url <url>] <packages>
	// Forward any --index-url / -i / --extra-index-url flags from the original
	// command so the dry-run resolves against the same index the actual install
	// will use.
	cmdArgs := []string{"install", "--dry-run", "--report", "-"}
	cmdArgs = append(cmdArgs, r.extractIndexURLFlags(command)...)
	cmdArgs = append(cmdArgs, packages...)
	allArgs := append(append([]string(nil), r.prefixArgs...), cmdArgs...)

	cmd := exec.CommandContext(ctx, r.binary, allArgs...)
	cmd.Dir = workDir

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("pip dry-run failed: %w", err)
	}

	plan, err := parsePipDryRunOutput(out, packages)
	if err != nil {
		return nil, err
	}
	plan.Registry = r.detectRegistry(args)
	return plan, nil
}

// extractIndexURLFlags returns the subset of args that influence which
// index/registry packages resolve from (--index-url, -i, --extra-index-url).
// Pass these to the dry-run so the resolver hits the same source the actual
// install will use.
func (r *pipResolver) extractIndexURLFlags(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "--index-url" || a == "-i") && i+1 < len(args):
			out = append(out, a, args[i+1])
			i++
		case strings.HasPrefix(a, "--index-url="):
			out = append(out, a)
		case a == "--extra-index-url" && i+1 < len(args):
			out = append(out, a, args[i+1])
			i++
		case strings.HasPrefix(a, "--extra-index-url="):
			out = append(out, a)
		}
	}
	return out
}

// detectRegistry scans the pip install command args for registry override flags.
//
// --index-url / -i sets the primary registry; return it directly.
// --extra-index-url means "also use this registry", so the package may have
// come from EITHER the primary or the extra registry. We can't tell which, so
// we return "" (unknown) to let the privacy filter fail closed rather than
// accidentally claiming the package came from a known-public registry.
func (r *pipResolver) detectRegistry(args []string) string {
	hasExtra := false
	primary := "pypi.org"

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--index-url" && i+1 < len(args):
			primary = args[i+1]
			i++
		case strings.HasPrefix(a, "--index-url="):
			primary = strings.TrimPrefix(a, "--index-url=")
		case a == "-i" && i+1 < len(args):
			primary = args[i+1]
			i++
		case a == "--extra-index-url" && i+1 < len(args):
			hasExtra = true
			i++
		case strings.HasPrefix(a, "--extra-index-url="):
			hasExtra = true
		}
	}

	if hasExtra {
		// Package origin is ambiguous — return "" so privacy filter fails closed.
		return ""
	}
	return primary
}

// pipReport represents the JSON output from pip install --report.
type pipReport struct {
	Install []pipInstallItem `json:"install"`
}

type pipInstallItem struct {
	Metadata pipMetadata `json:"metadata"`
	Requested bool       `json:"requested"`
}

type pipMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parsePipDryRunOutput parses pip's --report JSON output into an InstallPlan.
func parsePipDryRunOutput(data []byte, requestedPkgs []string) (*pkgcheck.InstallPlan, error) {
	var report pipReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse pip report JSON: %w", err)
	}

	// Build a set of requested package base names (normalized to lowercase)
	requested := make(map[string]bool, len(requestedPkgs))
	for _, p := range requestedPkgs {
		name := strings.ToLower(pkgBaseName(p))
		requested[name] = true
	}

	plan := &pkgcheck.InstallPlan{
		Tool:       "pip",
		Ecosystem:  pkgcheck.EcosystemPyPI,
		Registry:   "pypi.org",
		ResolvedAt: time.Now(),
	}

	for _, item := range report.Install {
		ref := pkgcheck.PackageRef{
			Name:    item.Metadata.Name,
			Version: item.Metadata.Version,
		}

		// Use pip's "requested" field if available, fall back to name matching
		isDirect := item.Requested || requested[strings.ToLower(item.Metadata.Name)]
		if isDirect {
			ref.Direct = true
			plan.Direct = append(plan.Direct, ref)
		} else {
			plan.Transitive = append(plan.Transitive, ref)
		}
	}

	return plan, nil
}
