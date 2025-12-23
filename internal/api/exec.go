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
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

const (
	defaultCommandTimeout = 5 * time.Minute
	defaultMaxOutputBytes = 1 * 1024 * 1024 // 1MB per stream in response + sqlite
)

type extraProcConfig struct {
	extraFiles []*os.File
	env        map[string]string
}

type postStartHook func(pid int) (cleanup func() error, err error)

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
	if ns := s.NetNSName(); ns != "" {
		// Run inside the session network namespace (Linux only; requires iproute2).
		allArgs := append([]string{"netns", "exec", ns, req.Command}, req.Args...)
		cmd = exec.CommandContext(ctx, "ip", allArgs...)
	} else if strings.TrimSpace(req.Argv0) != "" && len(cmd.Args) > 0 {
		cmd.Args[0] = req.Argv0
	}
	cmd.Dir = workdir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	env, err := buildPolicyEnv(envPol, os.Environ(), s, req.Env)
	if err != nil {
		msg := []byte(err.Error() + "\n")
		return 2, []byte{}, msg, 0, int64(len(msg)), false, false, types.ExecResources{}, nil
	}
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
		return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("start: %w", err)
	}

	pgid := 0
	if cmd.Process != nil {
		s.SetCurrentProcessPID(cmd.Process.Pid)
		if gp, gpErr := syscall.Getpgid(cmd.Process.Pid); gpErr == nil {
			pgid = gp
		}
		if hook != nil {
			if cleanup, hookErr := hook(cmd.Process.Pid); hookErr == nil && cleanup != nil {
				defer func() { _ = cleanup() }()
			}
		}
	}

	waitErr := cmd.Wait()
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

func resourcesFromProcessState(ps *os.ProcessState) types.ExecResources {
	if ps == nil {
		return types.ExecResources{}
	}
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return types.ExecResources{}
	}
	return types.ExecResources{
		CPUUserMs:    int64(ru.Utime.Sec)*1000 + int64(ru.Utime.Usec)/1000,
		CPUSystemMs:  int64(ru.Stime.Sec)*1000 + int64(ru.Stime.Usec)/1000,
		MemoryPeakKB: int64(ru.Maxrss),
	}
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

func killProcessGroup(pgid int) error {
	if pgid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
		fmt.Fprintf(os.Stderr, "exec: failed to kill process group %d: %v\n", pgid, err)
		return err
	}
	return nil
}

func mergeEnv(base []string, s *session.Session, overrides map[string]string) []string {
	env, err := buildPolicyEnv(policy.ResolvedEnvPolicy{}, base, s, overrides)
	if err != nil {
		return []string{}
	}
	return env
}
