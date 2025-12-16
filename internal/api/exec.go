package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

const (
	defaultCommandTimeout = 5 * time.Minute
	defaultMaxOutputBytes = 1 * 1024 * 1024 // 1MB per stream in response + sqlite
)

func runCommand(ctx context.Context, s *session.Session, cmdID string, req types.ExecRequest, cfg *config.Config) (exitCode int, stdout []byte, stderr []byte, stdoutTotal int64, stderrTotal int64, stdoutTrunc bool, stderrTrunc bool, err error) {
	timeout := defaultCommandTimeout
	if req.Timeout != "" {
		if d, e := time.ParseDuration(req.Timeout); e == nil && d > 0 {
			timeout = d
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if handled, code, out, errOut := s.Builtin(req); handled {
		return code, out, errOut, int64(len(out)), int64(len(errOut)), false, false, nil
	}

	s.RecordHistory(strings.TrimSpace(req.Command + " " + strings.Join(req.Args, " ")))

	workdir, err := resolveWorkingDir(s, req.WorkingDir)
	if err != nil {
		msg := []byte(err.Error() + "\n")
		return 2, []byte{}, msg, 0, int64(len(msg)), false, false, nil
	}

	cmd := exec.CommandContext(ctx, req.Command, req.Args...)
	cmd.Dir = workdir

	env := mergeEnv(os.Environ(), s, req.Env)
	cmd.Env = env

	if req.Stdin != "" {
		cmd.Stdin = strings.NewReader(req.Stdin)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return 127, nil, nil, 0, 0, false, false, fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return 127, nil, nil, 0, 0, false, false, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 127, nil, nil, 0, 0, false, false, fmt.Errorf("start: %w", err)
	}

	type capRes struct {
		b    []byte
		n    int64
		tr   bool
		err  error
	}
	outCh := make(chan capRes, 1)
	errCh := make(chan capRes, 1)
	go func() {
		b, n, tr, e := captureLimited(stdoutPipe, defaultMaxOutputBytes)
		outCh <- capRes{b: b, n: n, tr: tr, err: e}
	}()
	go func() {
		b, n, tr, e := captureLimited(stderrPipe, defaultMaxOutputBytes)
		errCh <- capRes{b: b, n: n, tr: tr, err: e}
	}()

	waitErr := cmd.Wait()
	outRes := <-outCh
	errRes := <-errCh

	stdout, stderr = outRes.b, errRes.b
	stdoutTotal, stderrTotal = outRes.n, errRes.n
	stdoutTrunc, stderrTrunc = outRes.tr, errRes.tr
	if outRes.err != nil {
		err = fmt.Errorf("read stdout: %w", outRes.err)
	}
	if errRes.err != nil && err == nil {
		err = fmt.Errorf("read stderr: %w", errRes.err)
	}

	if waitErr == nil {
		return 0, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, err
	}
	if ee := (*exec.ExitError)(nil); errors.As(waitErr, &ee) {
		return ee.ExitCode(), stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, err
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return 124, stdout, append(stderr, []byte("command timed out\n")...), stdoutTotal, stderrTotal + int64(len("command timed out\n")), true, true, ctx.Err()
	}
	return 127, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, waitErr
}

func captureLimited(r io.Reader, max int64) ([]byte, int64, bool, error) {
	var total int64
	truncated := false
	var buf bytes.Buffer
	tmp := make([]byte, 32*1024)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			total += int64(n)
			if int64(buf.Len()) < max {
				remain := max - int64(buf.Len())
				if int64(n) <= remain {
					_, _ = buf.Write(tmp[:n])
				} else {
					_, _ = buf.Write(tmp[:remain])
					truncated = true
				}
			} else {
				truncated = true
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return buf.Bytes(), total, truncated, err
		}
	}
	return buf.Bytes(), total, truncated, nil
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
	real := filepath.Join(s.Workspace, filepath.FromSlash(rel))
	real = filepath.Clean(real)

	workspaceClean := filepath.Clean(s.Workspace)
	if real != workspaceClean && !strings.HasPrefix(real, workspaceClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("working_dir escapes workspace")
	}
	return real, nil
}

func mergeEnv(base []string, s *session.Session, overrides map[string]string) []string {
	envMap := map[string]string{}
	for _, kv := range base {
		if k, v, ok := strings.Cut(kv, "="); ok {
			envMap[k] = v
		}
	}

	_, sessEnv, _ := s.GetCwdEnvHistory()
	for k, v := range sessEnv {
		envMap[k] = v
	}
	for k, v := range overrides {
		envMap[k] = v
	}

	out := make([]string, 0, len(envMap))
	for k, v := range envMap {
		out = append(out, k+"="+v)
	}
	return out
}
