package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

const defaultExecTimeout = 30 * time.Second

// ExecProviderConfig configures an external command-based check provider.
type ExecProviderConfig struct {
	Command string
	Args    []string
	Timeout time.Duration
	Config  map[string]any
}

// execProvider runs an external command as a check provider.
// It marshals the CheckRequest to stdin as JSON and reads a CheckResponse
// from stdout as JSON.
type execProvider struct {
	name    string
	command string
	args    []string
	timeout time.Duration
	config  map[string]any
}

// NewExecProvider returns a CheckProvider that delegates checks to an external
// command via stdin/stdout JSON protocol.
//
// The subprocess receives a JSON-encoded check request on stdin and must produce
// a JSON-encoded check response on stdout.
//
// Exit codes:
//   - 0: success, parse stdout as CheckResponse
//   - 1: partial failure, parse stdout anyway (may contain partial results)
//   - 2+: total failure, return error
//
// For security, the subprocess does NOT inherit the parent process environment.
func NewExecProvider(name string, cfg ExecProviderConfig) pkgcheck.CheckProvider {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultExecTimeout
	}
	// Defensively copy Args to prevent concurrent mutation races.
	var args []string
	if len(cfg.Args) > 0 {
		args = make([]string, len(cfg.Args))
		copy(args, cfg.Args)
	}
	// Defensively deep-copy Config map.
	var config map[string]any
	if len(cfg.Config) > 0 {
		config = make(map[string]any, len(cfg.Config))
		for k, v := range cfg.Config {
			config[k] = v
		}
	}
	return &execProvider{
		name:    name,
		command: cfg.Command,
		args:    args,
		timeout: timeout,
		config:  config,
	}
}

func (p *execProvider) Name() string {
	return p.name
}

func (p *execProvider) Capabilities() []pkgcheck.FindingType {
	// Custom providers can return any finding type.
	return []pkgcheck.FindingType{
		pkgcheck.FindingVulnerability,
		pkgcheck.FindingLicense,
		pkgcheck.FindingProvenance,
		pkgcheck.FindingReputation,
		pkgcheck.FindingMalware,
	}
}

// execRequest is what we send to the subprocess on stdin.
type execRequest struct {
	Ecosystem string               `json:"ecosystem"`
	Packages  []pkgcheck.PackageRef `json:"packages"`
	Config    map[string]any        `json:"config,omitempty"`
}

func (p *execProvider) CheckBatch(ctx context.Context, req pkgcheck.CheckRequest) (*pkgcheck.CheckResponse, error) {
	start := time.Now()

	// Apply timeout.
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	// Build the subprocess request.
	execReq := execRequest{
		Ecosystem: string(req.Ecosystem),
		Packages:  req.Packages,
		Config:    p.config,
	}

	input, err := json.Marshal(execReq)
	if err != nil {
		return nil, fmt.Errorf("exec(%s): marshal input: %w", p.name, err)
	}

	// Create the command.
	cmd := exec.CommandContext(ctx, p.command, p.args...)

	// SECURITY: Do not inherit parent process environment variables.
	// This prevents leaking API keys and other sensitive data.
	cmd.Env = []string{}

	cmd.Stdin = bytes.NewReader(input)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	// Check for context cancellation/timeout first, regardless of exit code.
	if ctx.Err() != nil {
		return nil, fmt.Errorf("exec(%s): %w", p.name, ctx.Err())
	}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("exec(%s): run command: %w", p.name, err)
		}
	}

	// Exit code 2+ is a total failure.
	if exitCode >= 2 {
		return nil, fmt.Errorf("exec(%s): command failed with exit code %d: %s", p.name, exitCode, stderr.String())
	}

	// For exit code 0, require non-empty stdout.
	if exitCode == 0 && stdout.Len() == 0 {
		return nil, fmt.Errorf("exec(%s): exec provider returned empty response", p.name)
	}

	// Parse stdout as CheckResponse for exit code 0 (success) or 1 (partial).
	var response pkgcheck.CheckResponse
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
			return nil, fmt.Errorf("exec(%s): decode output: %w", p.name, err)
		}
	}

	response.Provider = p.name
	response.Metadata.Duration = time.Since(start)

	if exitCode == 1 {
		response.Metadata.Partial = true
		if stderr.Len() > 0 {
			response.Metadata.Error = stderr.String()
		}
	}

	return &response, nil
}
