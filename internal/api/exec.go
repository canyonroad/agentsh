package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
	envInject        map[string]string // Operator-trusted env vars that bypass policy filtering
	notifyParentSock *os.File       // Parent socket to receive seccomp notify fd (Linux only)
	notifySessionID  string         // Session ID for notify handler
	notifyStore      eventStore     // Event store for notify handler
	notifyBroker     eventBroker    // Event broker for notify handler
	notifyPolicy     *policy.Engine // Policy engine for notify handler
	execveHandler    any            // Execve handler (*unixmon.ExecveHandler on Linux, nil otherwise)

	// File monitor config
	fileMonitorCfg  config.SandboxSeccompFileMonitorConfig
	landlockEnabled bool // Whether Landlock enforcement is configured

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

func runCommandWithResources(ctx context.Context, s *session.Session, cmdID string, req types.ExecRequest, cfg *config.Config, envPol policy.ResolvedEnvPolicy, policyLimit time.Duration, hook postStartHook, extra *extraProcConfig, tracer any, sessionID string) (exitCode int, stdout []byte, stderr []byte, stdoutTotal int64, stderrTotal int64, stdoutTrunc bool, stderrTrunc bool, resources types.ExecResources, err error) {
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

	// When ptrace is active, use exec.Command (not CommandContext) because we
	// skip cmd.Wait() — CommandContext starts an internal goroutine that needs
	// Wait() for cleanup. We handle timeout/cancellation via killProcessGroup.
	var cmd *exec.Cmd
	if tracer != nil {
		cmd = exec.Command(req.Command, req.Args...)
	} else {
		cmd = exec.CommandContext(ctx, req.Command, req.Args...)
	}
	slog.Debug("exec command created", "command", req.Command, "args", req.Args, "session_id", s.ID)
	if ns := s.NetNSName(); ns != "" {
		// Run inside the session network namespace (Linux only; requires iproute2).
		allArgs := append([]string{"netns", "exec", ns, req.Command}, req.Args...)
		if tracer != nil {
			cmd = exec.Command("ip", allArgs...)
		} else {
			cmd = exec.CommandContext(ctx, "ip", allArgs...)
		}
	} else if strings.TrimSpace(req.Argv0) != "" && len(cmd.Args) > 0 {
		cmd.Args[0] = req.Argv0
	}
	cmd.Dir = workdir

	// Determine process start mode:
	// - ptrace tracer active: start normally, tracer attaches via PTRACE_SEIZE
	// - cgroup hook without tracer: start stopped via PTRACE_TRACEME
	// - no interception: start normally
	if tracer != nil {
		cmd.SysProcAttr = getSysProcAttr()
	} else if hook != nil {
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
	// Add env_inject (operator-trusted, bypasses policy filtering)
	// On POSIX, the first matching key wins, so we must remove existing keys
	// before appending injected values to ensure they take effect.
	if extra != nil && len(extra.envInject) > 0 {
		// Build set of keys to inject (case-sensitive on POSIX)
		injectKeys := make(map[string]bool)
		for k := range extra.envInject {
			injectKeys[k] = true
		}
		// Filter out existing entries that will be overridden
		filtered := env[:0]
		for _, e := range env {
			if k, _, ok := strings.Cut(e, "="); ok && injectKeys[k] {
				continue // Skip - will be replaced by injected value
			}
			filtered = append(filtered, e)
		}
		env = filtered
		// Now append injected values
		for k, v := range extra.envInject {
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

	// For ptrace mode, use explicit pipes so we can drain them independently
	// of cmd.Wait() (which we skip to avoid the Wait4 race). For non-ptrace,
	// set writers directly and let cmd.Wait() handle pipe synchronization.
	var stdoutPipeR, stderrPipeR, stdoutPipeW, stderrPipeW *os.File
	var pipeWG sync.WaitGroup
	if tracer != nil {
		var pipeErr error
		stdoutPipeR, stdoutPipeW, pipeErr = os.Pipe()
		if pipeErr != nil {
			return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("stdout pipe: %w", pipeErr)
		}
		stderrPipeR, stderrPipeW, pipeErr = os.Pipe()
		if pipeErr != nil {
			stdoutPipeR.Close()
			stdoutPipeW.Close()
			return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("stderr pipe: %w", pipeErr)
		}
		cmd.Stdout = stdoutPipeW
		cmd.Stderr = stderrPipeW
	} else {
		cmd.Stdout = stdoutW
		cmd.Stderr = stderrW
	}

	// Fail fast if context is already cancelled (ptrace mode doesn't use CommandContext)
	if tracer != nil && ctx.Err() != nil {
		if stdoutPipeR != nil { stdoutPipeR.Close() }
		if stderrPipeR != nil { stderrPipeR.Close() }
		if stdoutPipeW != nil { stdoutPipeW.Close() }
		if stderrPipeW != nil { stderrPipeW.Close() }
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return 124, nil, nil, 0, 0, false, false, types.ExecResources{}, ctx.Err()
		}
		return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, ctx.Err()
	}

	if err := cmd.Start(); err != nil {
		slog.Debug("exec command start failed", "command", req.Command, "error", err)
		if stdoutPipeR != nil { stdoutPipeR.Close() }
		if stderrPipeR != nil { stderrPipeR.Close() }
		if stdoutPipeW != nil { stdoutPipeW.Close() }
		if stderrPipeW != nil { stderrPipeW.Close() }
		return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("start: %w", err)
	}
	slog.Debug("exec command started", "command", req.Command, "pid", cmd.Process.Pid)

	// For ptrace mode: close write ends (now owned by child) and start draining
	if tracer != nil && stdoutPipeW != nil {
		stdoutPipeW.Close()
		stderrPipeW.Close()
		pipeWG.Add(2)
		go func() { defer pipeWG.Done(); if _, err := io.Copy(stdoutW, stdoutPipeR); err != nil { slog.Debug("ptrace stdout drain error", "error", err) }; stdoutPipeR.Close() }()
		go func() { defer pipeWG.Done(); if _, err := io.Copy(stderrW, stderrPipeR); err != nil { slog.Debug("ptrace stderr drain error", "error", err) }; stderrPipeR.Close() }()
	}

	pgid := 0
	if cmd.Process != nil {
		s.SetCurrentProcessPID(cmd.Process.Pid)
		pgid = getProcessGroupID(cmd.Process.Pid)

		// If we started with ptrace (stopped), run the hook BEFORE resuming.
		// This ensures eBPF/cgroups are attached before the process executes.
		if tracer != nil && extra != nil && extra.notifyParentSock != nil {
			// HYBRID MODE: ptrace for execve interception + seccomp wrapper for sockets/files/Landlock.
			ptraceDone := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					_ = killProcessGroup(pgid)
					_ = killProcess(cmd.Process.Pid)
				case <-ptraceDone:
				}
			}()

			// 1. Attach ptrace (prefilter injected at first syscall exit)
			waitExit, resume, attachErr := ptraceExecAttach(tracer, cmd.Process.Pid, sessionID, cmdID, hook != nil)
			if attachErr != nil {
				close(ptraceDone)
				slog.Warn("hybrid mode: ptrace attach failed, falling back to wrapper-only",
					"error", attachErr, "pid", cmd.Process.Pid)
				// Fall through: startWrapperHandlers below will start wrapper-only mode.
				// Process will use cmd.Wait() path at bottom of function.
			} else {
				// 2. Start wrapper handlers (receives FD, sends ACK)
				startWrapperHandlers(ctx, extra, cmd.Process.Pid, pgid)

				// 3. Run hook while process stopped (cgroup/eBPF setup)
				if hook != nil {
					if cleanup, hookErr := hook(cmd.Process.Pid); hookErr == nil && cleanup != nil {
						defer func() { _ = cleanup() }()
					}
				}
				if resume != nil {
					if resumeErr := resume(); resumeErr != nil {
						close(ptraceDone)
						_ = killProcess(cmd.Process.Pid)
						_ = killProcessGroup(pgid)
						pipeWG.Wait()
						cmd.Process.Release()
						return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("ptrace resume: %w", resumeErr)
					}
				}

				// 4. Wait for exit via ptrace exit channel
				waitStart := time.Now()
				slog.Debug("exec waiting for command (hybrid)", "command", req.Command, "pid", cmd.Process.Pid)
				result := waitExit()
				close(ptraceDone)
				if result.err != nil {
					_ = killProcess(cmd.Process.Pid)
					_ = killProcessGroup(pgid)
				}
				waitDuration := time.Since(waitStart)
				slog.Debug("exec command finished (hybrid)", "command", req.Command, "pid", cmd.Process.Pid, "exit_code", result.exitCode, "wait_duration_ms", waitDuration.Milliseconds())
				pipeWG.Wait()
				stdout, stderr = stdoutW.Bytes(), stderrW.Bytes()
				stdoutTotal, stderrTotal = stdoutW.total, stderrW.total
				stdoutTrunc, stderrTrunc = stdoutW.truncated, stderrW.truncated
				resources = result.resources
				cmd.Process.Release()

				if ctx.Err() != nil {
					_ = killProcessGroup(pgid)
				}
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return 124, stdout, append(stderr, []byte("command timed out\n")...), stdoutTotal, stderrTotal + int64(len("command timed out\n")), true, true, resources, ctx.Err()
				}
				if errors.Is(ctx.Err(), context.Canceled) {
					return 127, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, ctx.Err()
				}
				return result.exitCode, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, result.err
			}
		} else if tracer != nil {
			// FULL PTRACE MODE: ptrace handles everything (no seccomp wrapper).
			// Context cancellation watcher: start BEFORE attach so timeout
			// is enforced even if WaitAttached stalls.
			ptraceDone := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					_ = killProcessGroup(pgid)
					_ = killProcess(cmd.Process.Pid)
				case <-ptraceDone:
				}
			}()

			// Ptrace tracer active: attach via PTRACE_SEIZE, run hook while stopped, resume
			waitExit, resume, attachErr := ptraceExecAttach(tracer, cmd.Process.Pid, sessionID, cmdID, hook != nil)
			if attachErr != nil {
				close(ptraceDone)
				_ = killProcess(cmd.Process.Pid)
				_ = killProcessGroup(pgid)
				pipeWG.Wait()
				cmd.Process.Release()
				return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("ptrace attach: %w", attachErr)
			}
			if hook != nil {
				if cleanup, hookErr := hook(cmd.Process.Pid); hookErr == nil && cleanup != nil {
					defer func() { _ = cleanup() }()
				}
			}
			if resume != nil {
				if resumeErr := resume(); resumeErr != nil {
					close(ptraceDone)
					_ = killProcess(cmd.Process.Pid)
					_ = killProcessGroup(pgid)
					pipeWG.Wait()
					cmd.Process.Release()
					return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("ptrace resume: %w", resumeErr)
				}
			}

			// Tracer-managed wait: block on exit channel instead of cmd.Wait()
			// to avoid Wait4(-1) race between tracer and Go runtime.
			waitStart := time.Now()
			slog.Debug("exec waiting for command (ptrace)", "command", req.Command, "pid", cmd.Process.Pid)
			result := waitExit()
			close(ptraceDone) // stop context watcher immediately after exit
			// On tracer shutdown, force-kill child before draining pipes
			if result.err != nil {
				_ = killProcess(cmd.Process.Pid)
				_ = killProcessGroup(pgid)
			}
			waitDuration := time.Since(waitStart)
			slog.Debug("exec command finished (ptrace)", "command", req.Command, "pid", cmd.Process.Pid, "exit_code", result.exitCode, "wait_duration_ms", waitDuration.Milliseconds())
			pipeWG.Wait() // drain pipes before reading capture writers
			stdout, stderr = stdoutW.Bytes(), stderrW.Bytes()
			stdoutTotal, stderrTotal = stdoutW.total, stderrW.total
			stdoutTrunc, stderrTrunc = stdoutW.truncated, stderrW.truncated
			resources = result.resources
			cmd.Process.Release()

			if ctx.Err() != nil {
				_ = killProcessGroup(pgid)
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return 124, stdout, append(stderr, []byte("command timed out\n")...), stdoutTotal, stderrTotal + int64(len("command timed out\n")), true, true, resources, ctx.Err()
			}
			if errors.Is(ctx.Err(), context.Canceled) {
				return 127, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, ctx.Err()
			}
			return result.exitCode, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, result.err
		} else if hook != nil {
			// Seccomp stopped-start: process started with PTRACE_TRACEME
			if cleanup, hookErr := hook(cmd.Process.Pid); hookErr == nil && cleanup != nil {
				defer func() { _ = cleanup() }()
			}
			// Resume the traced process - it was stopped at first instruction
			if resumeErr := resumeTracedProcess(cmd.Process.Pid); resumeErr != nil {
				// Failed to resume - kill the process and return error
				_ = killProcess(cmd.Process.Pid)
				return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("resume traced process: %w", resumeErr)
			}
		}

		// Start wrapper handlers (wrapper-only path + hybrid fallback).
		startWrapperHandlers(ctx, extra, cmd.Process.Pid, pgid)
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
		// Virtual paths always use "/" prefix; on Windows filepath.IsAbs("/workspace")
		// returns false, so also check for leading slash.
		if strings.HasPrefix(reqWorkingDir, "/") || filepath.IsAbs(reqWorkingDir) {
			virtual = filepath.ToSlash(reqWorkingDir)
		} else {
			virtual = filepath.ToSlash(filepath.Join(cwd, reqWorkingDir))
		}
	}
	// Normalize to resolve ".." before root boundary check, so paths like
	// /home/u/proj/../tmp are correctly classified as outside-workspace.
	virtual = filepath.ToSlash(filepath.Clean(filepath.FromSlash(virtual)))

	vroot := s.VirtualRoot
	if vroot == "" {
		vroot = "/workspace" // fail closed for uninitialized sessions
	}
	if !session.IsUnderRoot(virtual, vroot) {
		if vroot == "/workspace" {
			// Default mode: reject outside-workspace paths (preserves pre-real-paths behavior)
			return "", fmt.Errorf("working_dir must be under /workspace")
		}
		// Real-paths mode: pass through as-is for policy/seccomp enforcement
		return virtual, nil
	}
	rel := session.TrimRootPrefix(virtual, vroot)
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
	if !session.IsRealPathUnder(real, rootClean) {
		return "", fmt.Errorf("working_dir escapes workspace mount")
	}

	// Resolve root symlinks for consistent comparison (macOS /var -> /private/var).
	// Since workspace paths are canonicalized at session creation, this should
	// rarely change the path. On FUSE mounts (E2B/Daytona/Cloudflare), the mount
	// root is owned by root and EvalSymlinks fails with EACCES — fall back to
	// rootClean, which is safe because FUSE mount paths have no symlinks at the root.
	rootResolved, err := filepath.EvalSymlinks(rootClean)
	if err != nil {
		if !os.IsPermission(err) {
			return "", fmt.Errorf("resolve workspace mount %q: %w", rootClean, err)
		}
		rootResolved = rootClean
	}

	// Resolve symlinks to prevent symlink escape (e.g., /workspace/link -> /etc).
	// If the target doesn't exist yet, evaluate the parent directory instead.
	resolved, resolveErr := filepath.EvalSymlinks(real)
	if resolveErr != nil {
		// Path doesn't exist — evaluate parent to catch symlink escapes in ancestors
		parent := filepath.Dir(real)
		resolvedParent, parentErr := filepath.EvalSymlinks(parent)
		if parentErr != nil {
			// Parent also doesn't exist — use lexical path (already checked above)
			return real, nil
		}
		resolvedParent = filepath.Clean(resolvedParent)
		if !session.IsRealPathUnder(resolvedParent, rootResolved) {
			return "", fmt.Errorf("working_dir symlink escapes workspace mount")
		}
		return filepath.Clean(filepath.Join(resolvedParent, filepath.Base(real))), nil
	}
	resolved = filepath.Clean(resolved)
	if !session.IsRealPathUnder(resolved, rootResolved) {
		return "", fmt.Errorf("working_dir symlink escapes workspace mount")
	}
	return resolved, nil
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

// startWrapperHandlers starts the seccomp notify handler and signal filter handler
// if configured. Used by both regular exec and hybrid ptrace+wrapper mode.
func startWrapperHandlers(ctx context.Context, extra *extraProcConfig, pid, pgid int) {
	if extra == nil {
		return
	}
	if extra.notifyParentSock != nil {
		startNotifyHandler(ctx, extra.notifyParentSock, extra.notifySessionID, extra.notifyPolicy, extra.notifyStore, extra.notifyBroker, extra.execveHandler, extra.fileMonitorCfg, extra.landlockEnabled)
	}
	if extra.signalParentSock != nil && extra.signalEngine != nil {
		if extra.signalRegistry != nil {
			extra.signalRegistry.Register(pid, pgid, extra.origCommand)
		}
		startSignalHandler(ctx, extra.signalParentSock, extra.notifySessionID, pid,
			extra.signalEngine, extra.signalRegistry,
			extra.notifyStore, extra.notifyBroker, extra.signalCommandID)
	}
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
