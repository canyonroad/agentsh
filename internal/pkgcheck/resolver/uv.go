package resolver

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

// UVResolverConfig configures the uv resolver.
type UVResolverConfig struct {
	DryRunCommand string        // path to uv binary; defaults to "uv"
	Timeout       time.Duration // timeout for dry-run execution
}

type uvResolver struct {
	cfg UVResolverConfig
}

// NewUVResolver creates a resolver for uv pip install and uv add commands.
func NewUVResolver(cfg UVResolverConfig) pkgcheck.Resolver {
	if cfg.DryRunCommand == "" {
		cfg.DryRunCommand = "uv"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &uvResolver{cfg: cfg}
}

func (r *uvResolver) Name() string { return "uv" }

func (r *uvResolver) CanResolve(command string, args []string) bool {
	base := filepath.Base(command)
	base = strings.TrimSuffix(base, ".exe")
	if base != "uv" {
		return false
	}
	if len(args) == 0 {
		return false
	}
	// "uv pip install ..."
	if args[0] == "pip" && len(args) > 1 && args[1] == "install" {
		return true
	}
	// "uv add ..."
	if args[0] == "add" {
		return true
	}
	return false
}

func (r *uvResolver) Resolve(ctx context.Context, workDir string, command []string) (*pkgcheck.InstallPlan, error) {
	var packages []string
	if len(command) > 1 {
		packages = extractPkgArgs(command[1:])
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	// uv pip install --dry-run <packages>
	cmdArgs := []string{"pip", "install", "--dry-run"}
	cmdArgs = append(cmdArgs, packages...)

	cmd := exec.CommandContext(ctx, r.cfg.DryRunCommand, cmdArgs...)
	cmd.Dir = workDir

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("uv dry-run failed: %w", err)
	}

	return parseUVDryRunOutput(out, packages)
}

// parseUVDryRunOutput parses uv's --dry-run text output into an InstallPlan.
// uv outputs lines like:
//
//	Would install flask-3.0.0 jinja2-3.1.2 markupsafe-2.1.3
//
// or one package per line:
//
//	Would install flask-3.0.0
//	                jinja2-3.1.2
func parseUVDryRunOutput(data []byte, requestedPkgs []string) (*pkgcheck.InstallPlan, error) {
	// Build a set of requested package base names (normalized to lowercase)
	requested := make(map[string]bool, len(requestedPkgs))
	for _, p := range requestedPkgs {
		name := strings.ToLower(pkgBaseName(p))
		requested[name] = true
	}

	plan := &pkgcheck.InstallPlan{
		Tool:       "uv",
		Ecosystem:  pkgcheck.EcosystemPyPI,
		ResolvedAt: time.Now(),
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Look for "Would install" lines
		if strings.HasPrefix(line, "Would install ") {
			line = strings.TrimPrefix(line, "Would install ")
		} else if strings.HasPrefix(line, "would install ") {
			line = strings.TrimPrefix(line, "would install ")
		} else if line == "" {
			continue
		} else {
			// Could be a continuation line with just package specs
			// Only process if it looks like package-version specs
			if !looksLikePackageSpec(line) {
				continue
			}
		}

		// Parse space-separated package-version specs
		parts := strings.Fields(line)
		for _, part := range parts {
			name, version := parseUVPackageSpec(part)
			if name == "" {
				continue
			}

			ref := pkgcheck.PackageRef{
				Name:    name,
				Version: version,
			}

			if requested[strings.ToLower(name)] {
				ref.Direct = true
				plan.Direct = append(plan.Direct, ref)
			} else {
				plan.Transitive = append(plan.Transitive, ref)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading uv output: %w", err)
	}

	return plan, nil
}

// parseUVPackageSpec parses a uv package spec like "flask-3.0.0" into name and version.
// The last hyphen-separated component that starts with a digit is treated as the version.
func parseUVPackageSpec(spec string) (name, version string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", ""
	}

	// Find the last hyphen followed by a digit (version separator)
	for i := len(spec) - 1; i > 0; i-- {
		if spec[i-1] == '-' && i < len(spec) && spec[i] >= '0' && spec[i] <= '9' {
			return spec[:i-1], spec[i:]
		}
	}

	// No version found
	return spec, ""
}

// looksLikePackageSpec checks if a line looks like it contains package-version specs.
func looksLikePackageSpec(line string) bool {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return false
	}
	// At least one part should contain a hyphen followed by a digit
	for _, p := range parts {
		for i := 1; i < len(p); i++ {
			if p[i-1] == '-' && p[i] >= '0' && p[i] <= '9' {
				return true
			}
		}
	}
	return false
}
