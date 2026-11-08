package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/agentsh/agentsh/internal/policy"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/pty"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type ptyStartParams struct {
	Command    string
	Args       []string
	Argv0      string
	WorkingDir string
	Env        map[string]string
	Rows       uint16
	Cols       uint16
}

type ptyRun struct {
	sessionID string
	unlock    func()

	cmdID   string
	started time.Time

	req ptyStartParams
	ps  *pty.Session
}

func (a *App) startPTY(ctx context.Context, sessionID string, req ptyStartParams) (*ptyRun, int, error) {
	if a == nil {
		return nil, http.StatusServiceUnavailable, errors.New("server not initialized")
	}
	if a.ptraceFailed.Load() {
		return nil, http.StatusServiceUnavailable, errors.New("ptrace tracer exited unexpectedly; refusing to execute commands without enforcement")
	}
	sess, ok := a.sessions.Get(sessionID)
	if !ok {
		return nil, http.StatusNotFound, errors.New("session not found")
	}
	if strings.TrimSpace(req.Command) == "" {
		return nil, http.StatusBadRequest, errors.New("command is required")
	}

	cmdID := "cmd-" + uuid.NewString()
	start := time.Now().UTC()
	unlock := sess.LockExec()
	sess.SetCurrentCommandID(cmdID)

	pre := a.policyEngineFor(sess).CheckCommandWithExecve(req.Command, req.Args, a.execveEnforcementActive(), a.shellCOpaqueMode())
	redirected, originalCmd, originalArgs := applyCommandRedirect(&req.Command, &req.Args, pre)
	approvalErr := error(nil)
	if pre.PolicyDecision == types.DecisionApprove && pre.EffectiveDecision == types.DecisionApprove && a.approvals != nil {
		apr := approvals.Request{
			ID:        "approval-" + uuid.NewString(),
			SessionID: sessionID,
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
		res, err := a.approvals.RequestApproval(ctx, apr)
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
		SessionID: sessionID,
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
	_ = a.store.AppendEvent(ctx, preEv)
	a.broker.Publish(preEv)

	if redirected && pre.Redirect != nil {
		redirEv := types.Event{
			ID:        uuid.NewString(),
			Timestamp: start,
			Type:      "command_redirected",
			SessionID: sessionID,
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
		_ = a.store.AppendEvent(ctx, redirEv)
		a.broker.Publish(redirEv)
	}

	if pre.EffectiveDecision == types.DecisionDeny {
		a.emitCommandDBBypassAttempt(ctx, sess, sessionID, cmdID, pre)
		defer unlock()
		msg := "command denied by policy"
		if pre.PolicyDecision == types.DecisionApprove {
			msg = "command denied (approval required)"
			if approvalErr != nil && strings.Contains(strings.ToLower(approvalErr.Error()), "timeout") {
				msg = "command denied (approval timed out)"
			}
		}
		return nil, http.StatusForbidden, fmt.Errorf("%s", msg)
	}

	// Record history like non-PTY exec (only for allowed commands).
	sess.RecordHistory(strings.TrimSpace(originalCmd + " " + strings.Join(originalArgs, " ")))

	workdir, err := resolveWorkingDir(sess, strings.TrimSpace(req.WorkingDir))
	if err != nil {
		defer unlock()
		return nil, http.StatusBadRequest, err
	}
	env, _ := buildPolicyEnv(policy.ResolvedEnvPolicy{}, os.Environ(), sess, req.Env)
	// Add service env vars (fake credentials, bypass policy filtering).
	if svcEnv := sess.ServiceEnvVars(); len(svcEnv) > 0 {
		svcKeys := make(map[string]bool, len(svcEnv))
		for k := range svcEnv {
			svcKeys[k] = true
		}
		filtered := env[:0]
		for _, e := range env {
			if k, _, ok := strings.Cut(e, "="); ok && svcKeys[k] {
				continue
			}
			filtered = append(filtered, e)
		}
		env = filtered
		for k, v := range svcEnv {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	rows := req.Rows
	cols := req.Cols
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}

	// PTY sessions must get the same kernel enforcement as a plain exec:
	// route the command through agentsh-unixwrap (seccomp file/net/execve,
	// Landlock) and attach the ptrace tracer when that mode is active.
	// Previously the PTY path ran the raw command with only FUSE in front.
	wrap := a.setupSeccompWrapper(types.ExecRequest{
		Command: req.Command,
		Args:    req.Args,
		Env:     req.Env,
	}, sessionID, sess)

	var extra *extraProcConfig
	if wrap != nil {
		extra = wrap.extraCfg
	}
	startReq := pty.StartRequest{
		Command: req.Command,
		Args:    req.Args,
		Argv0:   strings.TrimSpace(req.Argv0),
		Dir:     workdir,
		Env:     env,
		InitialSize: pty.Winsize{
			Rows: rows,
			Cols: cols,
		},
	}
	argv0 := startReq.Argv0
	if wrap != nil {
		startReq.Command = wrap.wrappedReq.Command
		startReq.Args = wrap.wrappedReq.Args
		// The wrapper launches the target, so the requested argv0 travels via
		// its env rather than as the wrapper's own argv[0].
		if argv0 != "" {
			startReq.Argv0 = ""
		}
	}
	startReq.ExternalWait = a.ptraceTracer != nil
	if extra != nil {
		// extra.env carries the wrapper's own plumbing (notify socket fd, seccomp
		// config, signal fd, wrapper log fd); without it agentsh-unixwrap exits.
		envSet := func(env []string, k, v string) []string {
			filtered := env[:0]
			for _, e := range env {
				if ek, _, ok := strings.Cut(e, "="); ok && ek == k {
					continue
				}
				filtered = append(filtered, e)
			}
			return append(filtered, k+"="+v)
		}
		for k, v := range extra.env {
			startReq.Env = envSet(startReq.Env, k, v)
		}
		for k, v := range extra.envInject {
			startReq.Env = envSet(startReq.Env, k, v)
		}
		if argv0 != "" {
			startReq.Env = envSet(startReq.Env, "AGENTSH_UNIXWRAP_ARGV0", argv0)
		}
		startReq.ExtraFiles = extra.extraFiles
	}

	ps, err := pty.New().Start(ctx, startReq)
	if err != nil {
		if extra != nil {
			for _, f := range extra.extraFiles {
				_ = f.Close()
			}
		}
		defer unlock()
		return nil, http.StatusInternalServerError, err
	}
	sess.SetCurrentProcessPID(ps.PID())
	pgid := getProcessGroupID(ps.PID())

	// Hand the wrapper's fds to its handlers, then attach the tracer, mirroring
	// the exec path: in hybrid mode (execve-only ptrace + wrapper) the wrapper
	// runs seccomp setup, signals READY, waits for the tracer, then for GO.
	failStart := func(what string, cause error) (*ptyRun, int, error) {
		_ = killProcess(ps.PID())
		_ = killProcessGroup(pgid)
		_, _ = ps.Wait()
		defer unlock()
		return nil, http.StatusInternalServerError, fmt.Errorf("%s: %w", what, cause)
	}
	var waitExit func() ptraceExecResult
	if extra != nil && extra.ptraceSync && a.ptraceTracer != nil {
		handlerCtx, handlerCancel := context.WithCancel(ctx)
		defer handlerCancel()
		ptraceReady := make(chan error, 1)
		startWrapperHandlers(handlerCtx, extra, ps.PID(), pgid, ptraceReady)

		var readyErr error
		select {
		case readyErr = <-ptraceReady:
		case <-ctx.Done():
			readyErr = ctx.Err()
		}
		if readyErr != nil {
			return failStart("PTY wrapper ready (hybrid)", readyErr)
		}
		attachWait, resume, attachErr := ptraceExecAttach(a.ptraceTracer, ps.PID(), sessionID, cmdID, false)
		if attachErr != nil {
			return failStart("ptrace attach (PTY, hybrid)", attachErr)
		}
		if resume != nil {
			if resumeErr := resume(); resumeErr != nil {
				return failStart("ptrace resume (PTY, hybrid)", resumeErr)
			}
		}
		if extra.notifyParentSock != nil {
			if _, goErr := extra.notifyParentSock.Write([]byte{'G'}); goErr != nil {
				return failStart("hybrid GO byte (PTY)", goErr)
			}
		}
		waitExit = attachWait
	} else {
		startWrapperHandlers(ctx, extra, ps.PID(), pgid, nil)
		if a.ptraceTracer != nil {
			attachWait, _, attachErr := ptraceExecAttach(a.ptraceTracer, ps.PID(), sessionID, cmdID, false)
			if attachErr != nil {
				return failStart("ptrace attach (PTY)", attachErr)
			}
			waitExit = attachWait
		}
	}
	if waitExit != nil {
		// The tracer reaps the child, so cmd.Wait would report ECHILD.
		ps.SetWaitOverride(func() (int, error) {
			res := waitExit()
			return res.exitCode, res.err
		})
	}

	startEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: start,
		Type:      "command_started",
		SessionID: sessionID,
		CommandID: cmdID,
		Fields: map[string]any{
			"command": req.Command,
			"args":    req.Args,
		},
	}
	_ = a.store.AppendEvent(ctx, startEv)
	a.broker.Publish(startEv)

	return &ptyRun{
		sessionID: sessionID,
		unlock:    unlock,
		cmdID:     cmdID,
		started:   start,
		req:       req,
		ps:        ps,
	}, http.StatusOK, nil
}

func (a *App) finishPTY(ctx context.Context, run *ptyRun, exitCode int, started time.Time, err error, out []byte, outTotal int64, outTrunc bool) {
	if a == nil || run == nil {
		return
	}
	end := time.Now().UTC()
	endEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: end,
		Type:      "command_finished",
		SessionID: run.sessionID,
		CommandID: run.cmdID,
		Fields: map[string]any{
			"exit_code":   exitCode,
			"duration_ms": int64(end.Sub(started).Milliseconds()),
		},
	}
	if err != nil {
		endEv.Fields["error"] = err.Error()
	}
	_ = a.store.AppendEvent(ctx, endEv)
	a.broker.Publish(endEv)

	// Best-effort store of PTY output as stdout.
	_ = a.store.SaveOutput(ctx, run.sessionID, run.cmdID, out, []byte{}, outTotal, 0, outTrunc, false)
}
