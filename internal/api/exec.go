package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/signal"
	"github.com/agentsh/agentsh/pkg/types"
)

const (
	defaultCommandTimeout = 5 * time.Minute
	defaultMaxOutputBytes = 1 * 1024 * 1024 // 1MB per stream in response + sqlite
)

type extraProcConfig struct {
	extraFiles       []*os.File
	env              map[string]string
	notifyParentSock *os.File       // Parent socket to receive seccomp notify fd (Linux only)
	notifySessionID  string         // Session ID for notify handler
	notifyStore      eventStore     // Event store for notify handler
	notifyBroker     eventBroker    // Event broker for notify handler
	notifyPolicy     *policy.Engine // Policy engine for notify handler
	execveHandler    any            // Execve handler (*unixmon.ExecveHandler on Linux, nil otherwise)

	// Signal filter fields
	signalParentSock *os.File            // Parent socket to receive signal filter fd
	signalEngine     *signal.Engine      // Signal policy engine
	signalRegistry   *signal.PIDRegistry // Process registry for signal classification
	signalCommandID  func() string       // Function to get current command ID

	// Original command name (before wrapping) for signal registry
	origCommand string
}

// eventStore is the interface for storing events.
type eventStore interface {
	AppendEvent(ctx context.Context, ev types.Event) error
}

// eventBroker is the interface for publishing events.
type eventBroker interface {
	Publish(ev types.Event)
}

type postStartHook func(pid int) (cleanup func() error, err error)

// emitSeccompBlockedIfSIGSYS checks if the error indicates a SIGSYS (seccomp kill)
// and emits a seccomp_blocked event if so.
func emitSeccompBlockedIfSIGSYS(ctx context.Context, store eventStore, broker eventBroker, sessionID, cmdID string, err error) {
	info := checkSIGSYS(err)
	if info == nil {
		return
	}
	ev := types.Event{
		ID:        "seccomp-" + cmdID,
		Timestamp: time.Now().UTC(),
		Type:      "seccomp_blocked",
		SessionID: sessionID,
		CommandID: cmdID,
		PID:       info.PID,
		Fields: map[string]any{
			"comm":   info.Comm,
			"reason": "blocked_by_policy",
			"action": "killed",
		},
	}
	if store != nil {
		_ = store.AppendEvent(ctx, ev)
	}
	if broker != nil {
		broker.Publish(ev)
	}
}

func chooseCommandTimeout(req types.ExecRequest, policyLimit time.Duration) time.Duration {
	timeout := defaultCommandTimeout
	if policyLimit > 0 {
		timeout = policyLimit
	}
	if req.Timeout == "" {
		return timeout
	}
	d, err := time.ParseDuration(req.Timeout)
	if err != nil || d <= 0 {
		return timeout
	}
	if policyLimit > 0 && d > policyLimit {
		return policyLimit
	}
	return d
}

func runCommandWithResources(ctx context.Context, s *session.Session, cmdID string, req types.ExecRequest, cfg *config.Config, envPol policy.ResolvedEnvPolicy, policyLimit time.Duration, hook postStartHook, extra *extraProcConfig) (exitCode int, stdout []byte, stderr []byte, stdoutTotal int64, stderrTotal int64, stdoutTrunc bool, stderrTrunc bool, resources types.ExecResources, err error) {
	timeout := chooseCommandTimeout(req, policyLimit)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if handled, code, out, errOut := s.Builtin(req); handled {
		return code, out, errOut, int64(len(out)), int64(len(errOut)), false, false, types.ExecResources{}, nil
	}

	s.RecordHistory(strings.TrimSpace(req.Command + " " + strings.Join(req.Args, " ")))

	workdir, err := resolveWorkingDir(s, req.WorkingDir)
	if err != nil {
		msg := []byte(err.Error() + "\n")
		return 2, []byte{}, msg, 0, int64(len(msg)), false, false, types.ExecResources{}, nil
	}

	cmd := exec.CommandContext(ctx, req.Command, req.Args...)
	slog.Debug("exec command created", "command", req.Command, "args", req.Args, "session_id", s.ID)
	if ns := s.NetNSName(); ns != "" {
		// Run inside the session network namespace (Linux only; requires iproute2).
		allArgs := append([]string{"netns", "exec", ns, req.Command}, req.Args...)
		cmd = exec.CommandContext(ctx, "ip", allArgs...)
	} else if strings.TrimSpace(req.Argv0) != "" && len(cmd.Args) > 0 {
		cmd.Args[0] = req.Argv0
	}
	cmd.Dir = workdir

	// If we have a post-start hook (e.g., eBPF/cgroup), start the process in a
	// stopped state using ptrace. This closes the race condition window where
	// the process could make network connections before eBPF is attached.
	startStopped := hook != nil
	if startStopped {
		cmd.SysProcAttr = getSysProcAttrStopped()
	} else {
		cmd.SysProcAttr = getSysProcAttr()
	}

	env, err := buildPolicyEnv(envPol, os.Environ(), s, req.Env)
	if err != nil {
		msg := []byte(err.Error() + "\n")
		return 2, []byte{}, msg, 0, int64(len(msg)), false, false, types.ExecResources{}, nil
	}
	// Debug: log whether AGENTSH_IN_SESSION is in the environment
	hasInSession := false
	for _, e := range env {
		if strings.HasPrefix(e, "AGENTSH_IN_SESSION=") {
			hasInSession = true
			break
		}
	}
	slog.Debug("exec env built", "command", req.Command, "has_AGENTSH_IN_SESSION", hasInSession, "env_count", len(env))
	if envPol.BlockIteration {
		env = maybeAddShimEnv(env, envPol, cfg)
	}
	if extra != nil && len(extra.env) > 0 {
		for k, v := range extra.env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd.Env = env
	if extra != nil && len(extra.extraFiles) > 0 {
		cmd.ExtraFiles = append(cmd.ExtraFiles, extra.extraFiles...)
	}

	if req.Stdin != "" {
		cmd.Stdin = strings.NewReader(req.Stdin)
	}

	stdoutW := newCaptureWriter(defaultMaxOutputBytes, nil)
	stderrW := newCaptureWriter(defaultMaxOutputBytes, nil)
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	if err := cmd.Start(); err != nil {
		slog.Debug("exec command start failed", "command", req.Command, "error", err)
		return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("start: %w", err)
	}
	slog.Debug("exec command started", "command", req.Command, "pid", cmd.Process.Pid)

	pgid := 0
	if cmd.Process != nil {
		s.SetCurrentProcessPID(cmd.Process.Pid)
		pgid = getProcessGroupID(cmd.Process.Pid)

		// If we started with ptrace (stopped), run the hook BEFORE resuming.
		// This ensures eBPF/cgroups are attached before the process executes.
		if startStopped && hook != nil {
			if cleanup, hookErr := hook(cmd.Process.Pid); hookErr == nil && cleanup != nil {
				defer func() { _ = cleanup() }()
			}
			// Resume the traced process - it was stopped at first instruction
			if resumeErr := resumeTracedProcess(cmd.Process.Pid); resumeErr != nil {
				// Failed to resume - kill the process and return error
				_ = killProcess(cmd.Process.Pid)
				return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("resume traced process: %w", resumeErr)
			}
		} else if hook != nil {
			// Non-stopped mode (fallback) - just run the hook
			if cleanup, hookErr := hook(cmd.Process.Pid); hookErr == nil && cleanup != nil {
				defer func() { _ = cleanup() }()
			}
		}

		// Start unix socket notify handler if configured (Linux only).
		// The handler receives the notify fd from the wrapper and runs until ctx is cancelled.
		if extra != nil && extra.notifyParentSock != nil {
			startNotifyHandler(ctx, extra.notifyParentSock, extra.notifySessionID, extra.notifyPolicy, extra.notifyStore, extra.notifyBroker, extra.execveHandler)
		}

		// Start signal filter handler if configured (Linux only).
		// The handler receives the signal filter fd from the wrapper and runs until ctx is cancelled.
		if extra != nil && extra.signalParentSock != nil && extra.signalEngine != nil {
			// Register the spawned process in the signal registry
			if extra.signalRegistry != nil {
				extra.signalRegistry.Register(cmd.Process.Pid, pgid, extra.origCommand)
			}
			startSignalHandler(ctx, extra.signalParentSock, extra.notifySessionID, cmd.Process.Pid,
				extra.signalEngine, extra.signalRegistry,
				extra.notifyStore, extra.notifyBroker, extra.signalCommandID)
		}
	}

	waitStart := time.Now()
	slog.Debug("exec waiting for command", "command", req.Command, "pid", cmd.Process.Pid)
	waitErr := cmd.Wait()
	waitDuration := time.Since(waitStart)
	slog.Debug("exec command finished", "command", req.Command, "pid", cmd.Process.Pid, "wait_error", waitErr, "ctx_err", ctx.Err(), "wait_duration_ms", waitDuration.Milliseconds())
	stdout, stderr = stdoutW.Bytes(), stderrW.Bytes()
	stdoutTotal, stderrTotal = stdoutW.total, stderrW.total
	stdoutTrunc, stderrTrunc = stdoutW.truncated, stderrW.truncated

	resources = resourcesFromProcessState(cmd.ProcessState)

	if ctx.Err() != nil {
		_ = killProcessGroup(pgid)
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return 124, stdout, append(stderr, []byte("command timed out\n")...), stdoutTotal, stderrTotal + int64(len("command timed out\n")), true, true, resources, ctx.Err()
	}
	if waitErr == nil {
		return 0, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, err
	}
	if ee := (*exec.ExitError)(nil); errors.As(waitErr, &ee) {
		return ee.ExitCode(), stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, err
	}
	return 127, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, waitErr
}

func resolveWorkingDir(s *session.Session, reqWorkingDir string) (string, error) {
	cwd, _, _ := s.GetCwdEnvHistory()
	virtual := cwd
	if reqWorkingDir != "" {
		if strings.HasPrefix(reqWorkingDir, "/") {
			virtual = reqWorkingDir
		} else {
			virtual = filepath.ToSlash(filepath.Join(cwd, reqWorkingDir))
		}
	}

	if !strings.HasPrefix(virtual, "/workspace") {
		return "", fmt.Errorf("working_dir must be under /workspace")
	}
	rel := strings.TrimPrefix(virtual, "/workspace")
	rel = strings.TrimPrefix(rel, "/")

	// Security: Ensure rel is not an absolute path (could escape on Windows)
	relPath := filepath.FromSlash(rel)
	if filepath.IsAbs(relPath) {
		return "", fmt.Errorf("working_dir contains absolute path component")
	}

	root := s.WorkspaceMountPath()
	real := filepath.Join(root, relPath)
	real = filepath.Clean(real)

	rootClean := filepath.Clean(root)
	if real != rootClean && !strings.HasPrefix(real, rootClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("working_dir escapes workspace mount")
	}
	return real, nil
}

func buildPolicyEnv(pol policy.ResolvedEnvPolicy, hostEnv []string, s *session.Session, overrides map[string]string) ([]string, error) {
	minimal := map[string]string{}
	hostMap := map[string]string{}
	for _, kv := range hostEnv {
		if k, v, ok := strings.Cut(kv, "="); ok {
			hostMap[k] = v
		}
	}
	copyKeys := []string{"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "HOME"}
	for _, k := range copyKeys {
		if v, ok := hostMap[k]; ok && v != "" {
			minimal[k] = v
		}
	}
	if _, ok := minimal["PATH"]; !ok {
		minimal["PATH"] = "/usr/bin:/bin"
	}

	// Session proxies
	if proxy := s.ProxyURL(); proxy != "" {
		minimal["HTTP_PROXY"] = proxy
		minimal["HTTPS_PROXY"] = proxy
		minimal["ALL_PROXY"] = proxy
		minimal["http_proxy"] = proxy
		minimal["https_proxy"] = proxy
		minimal["all_proxy"] = proxy
		noProxy := minimal["NO_PROXY"]
		if noProxy == "" {
			noProxy = minimal["no_proxy"]
		}
		if !strings.Contains(noProxy, "localhost") {
			if noProxy != "" && !strings.HasSuffix(noProxy, ",") {
				noProxy += ","
			}
			noProxy += "localhost,127.0.0.1"
		}
		minimal["NO_PROXY"] = noProxy
		minimal["no_proxy"] = noProxy
	}

	// LLM proxy base URLs (for SDK clients like Anthropic, OpenAI)
	if llmEnv := s.LLMProxyEnvVars(); llmEnv != nil {
		for k, v := range llmEnv {
			minimal[k] = v
		}
	}

	add := map[string]string{}
	_, sessEnv, _ := s.GetCwdEnvHistory()
	for k, v := range sessEnv {
		add[k] = v
	}
	for k, v := range overrides {
		add[k] = v
	}

	add["AGENTSH_IN_SESSION"] = "1"

	baseSlice := mapToEnvSlice(minimal)
	return policy.BuildEnv(pol, baseSlice, add)
}

func mapToEnvSlice(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, fmt.Sprintf("%s=%s", k, v))
	}
	return out
}

// maybeAddShimEnv injects the env-iteration blocking shim (LD_PRELOAD) and flag
// when block_iteration is enabled. It tolerates missing/invalid shim path to
// avoid breaking command execution, but emits a warning.
func maybeAddShimEnv(env []string, pol policy.ResolvedEnvPolicy, cfg *config.Config) []string {
	_ = pol
	out := append([]string{}, env...)
	out = append(out, "AGENTSH_ENV_BLOCK_ITERATION=1")

	shim := strings.TrimSpace(cfg.Policies.EnvShimPath)
	if shim == "" {
		slog.Warn("block_iteration enabled but policies.env_shim_path is not set")
		return out
	}
	info, err := os.Stat(shim)
	if err != nil || info.IsDir() {
		slog.Warn("block_iteration enabled but env shim missing", "path", shim, "err", err)
		return out
	}

	const ldPreload = "LD_PRELOAD"
	found := -1
	for i, kv := range out {
		if strings.HasPrefix(kv, ldPreload+"=") {
			found = i
			break
		}
	}
	if found >= 0 {
		existing := strings.TrimPrefix(out[found], ldPreload+"=")
		if existing == "" {
			out[found] = fmt.Sprintf("%s=%s", ldPreload, shim)
		} else {
			out[found] = fmt.Sprintf("%s=%s:%s", ldPreload, shim, existing)
		}
	} else {
		out = append(out, fmt.Sprintf("%s=%s", ldPreload, shim))
	}

	return out
}

func mergeEnv(base []string, s *session.Session, overrides map[string]string) []string {
	env, err := buildPolicyEnv(policy.ResolvedEnvPolicy{}, base, s, overrides)
	if err != nil {
		return []string{}
	}
	return env
}

// mergeEnvInject merges env_inject from global config and policy.
// Policy values take precedence over config values for the same key.
// These variables bypass policy env filtering (operator-trusted).
func mergeEnvInject(cfg *config.Config, pol *policy.Engine) map[string]string {
	result := make(map[string]string)

	// 1. Start with global config
	if cfg != nil {
		for k, v := range cfg.Sandbox.EnvInject {
			result[k] = v
		}
	}

	// 2. Layer policy on top (policy wins conflicts)
	if pol != nil {
		for k, v := range pol.GetEnvInject() {
			result[k] = v
		}
	}

	return result
}
