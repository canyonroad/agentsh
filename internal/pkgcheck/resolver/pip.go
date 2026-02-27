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
	DryRunCommand string        // path to pip binary; defaults to "pip"
	Timeout       time.Duration // timeout for dry-run execution
}

type pipResolver struct {
	cfg PipResolverConfig
}

// NewPipResolver creates a resolver for pip install commands.
func NewPipResolver(cfg PipResolverConfig) pkgcheck.Resolver {
	if cfg.DryRunCommand == "" {
		cfg.DryRunCommand = "pip"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &pipResolver{cfg: cfg}
}

func (r *pipResolver) Name() string { return "pip" }

func (r *pipResolver) CanResolve(command string, args []string) bool {
	base := filepath.Base(command)
	base = strings.TrimSuffix(base, ".exe")
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
	if len(command) > 1 {
		packages = extractPkgArgs(command[1:])
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	// pip install --dry-run --report - <packages>
	cmdArgs := []string{"install", "--dry-run", "--report", "-"}
	cmdArgs = append(cmdArgs, packages...)

	cmd := exec.CommandContext(ctx, r.cfg.DryRunCommand, cmdArgs...)
	cmd.Dir = workDir

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("pip dry-run failed: %w", err)
	}

	return parsePipDryRunOutput(out, packages)
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
