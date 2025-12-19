package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

const (
	defaultCommandTimeout = 5 * time.Minute
	defaultMaxOutputBytes = 1 * 1024 * 1024 // 1MB per stream in response + sqlite
)

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

func runCommandWithResources(ctx context.Context, s *session.Session, cmdID string, req types.ExecRequest, cfg *config.Config, policyLimit time.Duration, hook postStartHook) (exitCode int, stdout []byte, stderr []byte, stdoutTotal int64, stderrTotal int64, stdoutTrunc bool, stderrTrunc bool, resources types.ExecResources, err error) {
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

	env := mergeEnv(os.Environ(), s, req.Env)
	cmd.Env = env

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

func runCommand(ctx context.Context, s *session.Session, cmdID string, req types.ExecRequest, cfg *config.Config, policyLimit time.Duration) (exitCode int, stdout []byte, stderr []byte, stdoutTotal int64, stderrTotal int64, stdoutTrunc bool, stderrTrunc bool, err error) {
	exitCode, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, _, err = runCommandWithResources(ctx, s, cmdID, req, cfg, policyLimit, nil)
	return
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
	root := s.WorkspaceMountPath()
	real := filepath.Join(root, filepath.FromSlash(rel))
	real = filepath.Clean(real)

	rootClean := filepath.Clean(root)
	if real != rootClean && !strings.HasPrefix(real, rootClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("working_dir escapes workspace mount")
	}
	return real, nil
}

func mergeEnv(base []string, s *session.Session, overrides map[string]string) []string {
	envMap := map[string]string{}

	baseMap := map[string]string{}
	for _, kv := range base {
		if k, v, ok := strings.Cut(kv, "="); ok {
			baseMap[k] = v
		}
	}

	// Keep only a minimal, non-secret subset from the host.
	allow := []string{"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "HOME"}
	for _, k := range allow {
		if v, ok := baseMap[k]; ok {
			envMap[k] = v
		}
	}
	if _, ok := envMap["PATH"]; !ok {
		envMap["PATH"] = "/usr/bin:/bin"
	}

	if proxy := s.ProxyURL(); proxy != "" {
		envMap["HTTP_PROXY"] = proxy
		envMap["HTTPS_PROXY"] = proxy
		envMap["ALL_PROXY"] = proxy
		envMap["http_proxy"] = proxy
		envMap["https_proxy"] = proxy
		envMap["all_proxy"] = proxy

		noProxy := envMap["NO_PROXY"]
		if noProxy == "" {
			noProxy = envMap["no_proxy"]
		}
		if !strings.Contains(noProxy, "localhost") {
			if noProxy != "" && !strings.HasSuffix(noProxy, ",") {
				noProxy += ","
			}
			noProxy += "localhost,127.0.0.1"
		}
		envMap["NO_PROXY"] = noProxy
		envMap["no_proxy"] = noProxy
	}

	_, sessEnv, _ := s.GetCwdEnvHistory()
	for k, v := range sessEnv {
		envMap[k] = v
	}
	for k, v := range overrides {
		envMap[k] = v
	}

	// Mark processes executed by agentsh so sh/bash shims can avoid recursively re-entering agentsh.
	envMap["AGENTSH_IN_SESSION"] = "1"

	// Strip secrets that may have leaked in via overrides or session env.
	for k := range envMap {
		if isSensitiveEnvKey(k) {
			delete(envMap, k)
		}
	}

	out := make([]string, 0, len(envMap))
	for k, v := range envMap {
		out = append(out, k+"="+v)
	}
	return out
}

func killProcessGroup(pgid int) error {
	if pgid <= 0 {
		return nil
	}
	// Negative pid targets the process group.
	return syscall.Kill(-pgid, syscall.SIGKILL)
}

func isSensitiveEnvKey(k string) bool {
	l := strings.ToLower(strings.TrimSpace(k))
	switch l {
	case "aws_secret_access_key", "aws_access_key_id", "aws_session_token", "aws_profile", "aws_shared_credentials_file",
		"google_application_credentials", "gcp_service_account",
		"azure_client_secret", "azure_client_id", "azure_tenant_id", "azure_subscription_id",
		"ssh_auth_sock", "ssh_agent_pid",
		"docker_host", "docker_tls_verify",
		"kubeconfig", "gcloud_project",
		"github_token", "gh_token":
		return true
	}
	if strings.HasSuffix(l, "_secret") || strings.HasSuffix(l, "_token") || strings.HasSuffix(l, "_password") || strings.HasSuffix(l, "_key") {
		return true
	}
	return false
}
