package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (a *App) execInSessionStream(w http.ResponseWriter, r *http.Request) {
	if a.ptraceFailed.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "ptrace tracer exited unexpectedly; refusing to execute commands without enforcement"})
		return
	}
	id := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	var req types.ExecRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	if req.Command == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "command is required"})
		return
	}

	cmdID := "cmd-" + uuid.NewString()
	start := time.Now().UTC()
	unlock := s.LockExec()
	defer unlock()
	s.SetCurrentCommandID(cmdID)

	// Propagate W3C trace context for distributed tracing correlation
	if tp := r.Header.Get("Traceparent"); tp != "" {
		if traceID, spanID, traceFlags, ok := parseTraceparent(tp); ok {
			s.SetCurrentTraceContext(traceID, spanID, traceFlags)
		}
	}

	pre := a.policy.CheckCommand(req.Command, req.Args)
	redirected, originalCmd, originalArgs := applyCommandRedirect(&req.Command, &req.Args, pre)
	approvalErr := error(nil)
	if pre.PolicyDecision == types.DecisionApprove && pre.EffectiveDecision == types.DecisionApprove && a.approvals != nil {
		apr := approvals.Request{
			ID:        "approval-" + uuid.NewString(),
			SessionID: id,
			CommandID: cmdID,
			Kind:      "command",
			Target:    req.Command,
			Rule:      pre.Rule,
			Message:   pre.Message,
			Fields: map[string]any{
				"command": req.Command,
				"args":    req.Args,
			},
		}
		res, err := a.approvals.RequestApproval(r.Context(), apr)
		approvalErr = err
		if pre.Approval != nil {
			pre.Approval.ID = apr.ID
		}
		if err != nil || !res.Approved {
			pre.EffectiveDecision = types.DecisionDeny
		} else {
			pre.EffectiveDecision = types.DecisionAllow
		}
	}
	preEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: start,
		Type:      "command_policy",
		SessionID: id,
		CommandID: cmdID,
		Operation: "command_precheck",
		Policy: &types.PolicyInfo{
			Decision:          pre.PolicyDecision,
			EffectiveDecision: pre.EffectiveDecision,
			Rule:              pre.Rule,
			Message:           pre.Message,
			Approval:          pre.Approval,
			Redirect:          pre.Redirect,
		},
		Fields: map[string]any{
			"command": originalCmd,
			"args":    originalArgs,
		},
	}
	s.InjectTraceContext(preEv.Fields)
	_ = a.store.AppendEvent(r.Context(), preEv)
	a.broker.Publish(preEv)

	if redirected && pre.Redirect != nil {
		redirEv := types.Event{
			ID:        uuid.NewString(),
			Timestamp: start,
			Type:      "command_redirected",
			SessionID: id,
			CommandID: cmdID,
			Policy: &types.PolicyInfo{
				Decision:          types.DecisionRedirect,
				EffectiveDecision: types.DecisionAllow,
				Rule:              pre.Rule,
				Message:           pre.Message,
				Redirect:          pre.Redirect,
			},
			Fields: map[string]any{
				"from_command": originalCmd,
				"from_args":    originalArgs,
				"to_command":   req.Command,
				"to_args":      req.Args,
			},
		}
		s.InjectTraceContext(redirEv.Fields)
		_ = a.store.AppendEvent(r.Context(), redirEv)
		a.broker.Publish(redirEv)
	}

	if pre.EffectiveDecision == types.DecisionDeny {
		code := "E_POLICY_DENIED"
		if pre.PolicyDecision == types.DecisionApprove {
			code = "E_APPROVAL_DENIED"
			if approvalErr != nil && strings.Contains(strings.ToLower(approvalErr.Error()), "timeout") {
				code = "E_APPROVAL_TIMEOUT"
			}
		}
		resp := types.ExecResponse{
			CommandID: cmdID,
			SessionID: id,
			Timestamp: start,
			Request:   req,
			Result: types.ExecResult{
				ExitCode:   126,
				DurationMs: int64(time.Since(start).Milliseconds()),
				Error: &types.ExecError{
					Code:       code,
					Message:    "command denied by policy",
					PolicyRule: pre.Rule,
				},
			},
			Events: types.ExecEvents{
				FileOperations:    []types.Event{},
				NetworkOperations: []types.Event{},
				BlockedOperations: []types.Event{preEv},
			},
		}
		writeJSON(w, http.StatusForbidden, resp)
		return
	}

	startEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: start,
		Type:      "command_started",
		SessionID: id,
		CommandID: cmdID,
		Fields: map[string]any{
			"command": req.Command,
			"args":    req.Args,
		},
	}
	s.InjectTraceContext(startEv.Fields)
	_ = a.store.AppendEvent(r.Context(), startEv)
	a.broker.Publish(startEv)

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming not supported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Set up seccomp wrapper (Linux) for syscall enforcement
	wrapperResult := a.setupSeccompWrapper(req, id, s)
	wrappedReq := wrapperResult.wrappedReq
	extraCfg := wrapperResult.extraCfg

	limits := a.policy.Limits()
	emit := func(event string, payload map[string]any) error {
		return writeSSE(w, flusher, event, payload)
	}
	exitCode, stdoutB, stderrB, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, execErr := runCommandWithResourcesStreamingEmit(r.Context(), s, cmdID, wrappedReq, a.cfg, limits.CommandTimeout, emit, a.cgroupHook(id, cmdID, limits), extraCfg, a.ptraceTracer, id)
	_ = a.store.SaveOutput(r.Context(), id, cmdID, stdoutB, stderrB, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc)

	// Check if process was killed by seccomp (SIGSYS) and emit event
	emitSeccompBlockedIfSIGSYS(r.Context(), a.store, a.broker, id, cmdID, execErr)

	end := time.Now().UTC()
	endEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: end,
		Type:      "command_finished",
		SessionID: id,
		CommandID: cmdID,
		Fields: map[string]any{
			"exit_code":      exitCode,
			"duration_ms":    int64(end.Sub(start).Milliseconds()),
			"cpu_user_ms":    resources.CPUUserMs,
			"cpu_system_ms":  resources.CPUSystemMs,
			"memory_peak_kb": resources.MemoryPeakKB,
		},
	}
	if execErr != nil {
		endEv.Fields["error"] = execErr.Error()
	}
	s.InjectTraceContext(endEv.Fields)
	_ = a.store.AppendEvent(r.Context(), endEv)
	a.broker.Publish(endEv)

	// Final event for the client.
	_ = writeSSE(w, flusher, "done", map[string]any{
		"command_id":       cmdID,
		"exit_code":        exitCode,
		"duration_ms":      int64(end.Sub(start).Milliseconds()),
		"stdout_truncated": stdoutTrunc,
		"stderr_truncated": stderrTrunc,
	})
}

type emitFunc func(event string, payload map[string]any) error

func runCommandWithResourcesStreamingEmit(ctx context.Context, s *session.Session, cmdID string, req types.ExecRequest, cfg *config.Config, policyLimit time.Duration, emit emitFunc, hook postStartHook, extra *extraProcConfig, tracer any, sessionID string) (exitCode int, stdout []byte, stderr []byte, stdoutTotal int64, stderrTotal int64, stdoutTrunc bool, stderrTrunc bool, resources types.ExecResources, err error) {
	timeout := chooseCommandTimeout(req, policyLimit)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if handled, code, out, errOut := s.Builtin(req); handled {
		if len(out) > 0 {
			_ = emit("stdout", map[string]any{"command_id": cmdID, "stream": "stdout", "data": string(out)})
		}
		if len(errOut) > 0 {
			_ = emit("stderr", map[string]any{"command_id": cmdID, "stream": "stderr", "data": string(errOut)})
		}
		return code, out, errOut, int64(len(out)), int64(len(errOut)), false, false, types.ExecResources{}, nil
	}

	s.RecordHistory(strings.TrimSpace(req.Command + " " + strings.Join(req.Args, " ")))

	workdir, err := resolveWorkingDir(s, req.WorkingDir)
	if err != nil {
		msg := []byte(err.Error() + "\n")
		_ = emit("stderr", map[string]any{"command_id": cmdID, "stream": "stderr", "data": string(msg)})
		return 2, []byte{}, msg, 0, int64(len(msg)), false, false, types.ExecResources{}, nil
	}

	var cmd *exec.Cmd
	if tracer != nil {
		cmd = exec.Command(req.Command, req.Args...)
	} else {
		cmd = exec.CommandContext(ctx, req.Command, req.Args...)
	}
	if ns := s.NetNSName(); ns != "" {
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

	// Determine process start mode (same as non-streaming path)
	if tracer != nil {
		cmd.SysProcAttr = getSysProcAttr()
	} else if hook != nil {
		cmd.SysProcAttr = getSysProcAttrStopped()
	} else {
		cmd.SysProcAttr = getSysProcAttr()
	}

	env, _ := buildPolicyEnv(policy.ResolvedEnvPolicy{}, os.Environ(), s, req.Env)
	// Add extra environment variables from seccomp wrapper config
	if extra != nil && len(extra.env) > 0 {
		for k, v := range extra.env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd.Env = env

	// Add extra files (socket fds for seccomp notify/signal)
	if extra != nil && len(extra.extraFiles) > 0 {
		cmd.ExtraFiles = append(cmd.ExtraFiles, extra.extraFiles...)
	}

	if req.Stdin != "" {
		cmd.Stdin = strings.NewReader(req.Stdin)
	}

	var writeMu sync.Mutex
	stdoutW := newCaptureWriter(defaultMaxOutputBytes, func(chunk []byte) error {
		if emit == nil || len(chunk) == 0 {
			return nil
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		return emit("stdout", map[string]any{"command_id": cmdID, "stream": "stdout", "data": string(chunk)})
	})
	stderrW := newCaptureWriter(defaultMaxOutputBytes, func(chunk []byte) error {
		if emit == nil || len(chunk) == 0 {
			return nil
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		return emit("stderr", map[string]any{"command_id": cmdID, "stream": "stderr", "data": string(chunk)})
	})
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	// For ptrace mode, use explicit pipes for drain synchronization
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
	}

	if err := cmd.Start(); err != nil {
		if stdoutPipeR != nil { stdoutPipeR.Close() }
		if stderrPipeR != nil { stderrPipeR.Close() }
		if stdoutPipeW != nil { stdoutPipeW.Close() }
		if stderrPipeW != nil { stderrPipeW.Close() }
		return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("start: %w", err)
	}

	// For ptrace mode: close write ends and start draining
	if tracer != nil && stdoutPipeW != nil {
		stdoutPipeW.Close()
		stderrPipeW.Close()
		pipeWG.Add(2)
		go func() { defer pipeWG.Done(); io.Copy(stdoutW, stdoutPipeR); stdoutPipeR.Close() }()
		go func() { defer pipeWG.Done(); io.Copy(stderrW, stderrPipeR); stderrPipeR.Close() }()
	}

	pgid := 0
	if cmd.Process != nil {
		s.SetCurrentProcessPID(cmd.Process.Pid)
		pgid = getProcessGroupID(cmd.Process.Pid)

		if tracer != nil {
			// Ptrace tracer active: attach via PTRACE_SEIZE, run hook while stopped, resume
			waitExit, resume, attachErr := ptraceExecAttach(tracer, cmd.Process.Pid, sessionID, cmdID, hook != nil)
			if attachErr != nil {
				_ = killProcess(cmd.Process.Pid)
				return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("ptrace attach: %w", attachErr)
			}
			if hook != nil {
				if cleanup, hookErr := hook(cmd.Process.Pid); hookErr == nil && cleanup != nil {
					defer func() { _ = cleanup() }()
				}
			}
			if resume != nil {
				if resumeErr := resume(); resumeErr != nil {
					_ = killProcess(cmd.Process.Pid)
					return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("ptrace resume: %w", resumeErr)
				}
			}

			// Context cancellation watcher
			ptraceDone := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					_ = killProcessGroup(pgid)
					_ = killProcess(cmd.Process.Pid)
				case <-ptraceDone:
				}
			}()

			// Tracer-managed wait: block on exit channel instead of cmd.Wait()
			waitStart := time.Now()
			slog.Debug("exec_stream waiting for command (ptrace)", "command", req.Command, "pid", cmd.Process.Pid)
			result := waitExit()
			waitDuration := time.Since(waitStart)
			slog.Debug("exec_stream command finished (ptrace)", "command", req.Command, "pid", cmd.Process.Pid, "exit_code", result.exitCode, "wait_duration_ms", waitDuration.Milliseconds())
			pipeWG.Wait() // drain pipes before reading capture writers
			stdout, stderr = stdoutW.Bytes(), stderrW.Bytes()
			stdoutTotal, stderrTotal = stdoutW.total, stderrW.total
			stdoutTrunc, stderrTrunc = stdoutW.truncated, stderrW.truncated
			resources = result.resources
			cmd.Process.Release()
			close(ptraceDone)

			if ctx.Err() != nil {
				_ = killProcessGroup(pgid)
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return 124, stdout, append(stderr, []byte("command timed out\n")...), stdoutTotal, stderrTotal + int64(len("command timed out\n")), true, true, resources, ctx.Err()
			}
			return result.exitCode, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, result.err
		} else if hook != nil {
			// Seccomp stopped-start: process started with PTRACE_TRACEME
			if cleanup, hookErr := hook(cmd.Process.Pid); hookErr == nil && cleanup != nil {
				defer func() { _ = cleanup() }()
			}
			if resumeErr := resumeTracedProcess(cmd.Process.Pid); resumeErr != nil {
				_ = killProcess(cmd.Process.Pid)
				return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("resume traced process: %w", resumeErr)
			}
		}

		// Start unix socket notify handler if configured (Linux only).
		// The handler receives the notify fd from the wrapper and runs until ctx is cancelled.
		if extra != nil && extra.notifyParentSock != nil {
			startNotifyHandler(ctx, extra.notifyParentSock, extra.notifySessionID, extra.notifyPolicy, extra.notifyStore, extra.notifyBroker, extra.execveHandler, extra.fileMonitorCfg)
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
	waitErr := cmd.Wait()
	waitDuration := time.Since(waitStart)
	slog.Debug("exec_stream command finished", "command", req.Command, "pid", cmd.Process.Pid, "wait_error", waitErr, "ctx_err", ctx.Err(), "wait_duration_ms", waitDuration.Milliseconds())
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

func writeSSE(w io.Writer, flusher http.Flusher, event string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if event != "" {
		if _, err := fmt.Fprintf(w, "event: %s\n", event); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", strings.TrimSpace(string(b))); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}
