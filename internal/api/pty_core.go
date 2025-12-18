package api

import (
	"context"
	"errors"
	"fmt"
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

	// Record history like non-PTY exec.
	sess.RecordHistory(strings.TrimSpace(req.Command + " " + strings.Join(req.Args, " ")))

	pre := a.policy.CheckCommand(req.Command, req.Args)
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
		},
		Fields: map[string]any{
			"command": req.Command,
			"args":    req.Args,
		},
	}
	_ = a.store.AppendEvent(ctx, preEv)
	a.broker.Publish(preEv)

	if pre.EffectiveDecision == types.DecisionDeny {
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

	workdir, err := resolveWorkingDir(sess, strings.TrimSpace(req.WorkingDir))
	if err != nil {
		defer unlock()
		return nil, http.StatusBadRequest, err
	}
	env := mergeEnv(os.Environ(), sess, req.Env)

	ps, err := pty.New().Start(ctx, pty.StartRequest{
		Command: req.Command,
		Args:    req.Args,
		Argv0:   strings.TrimSpace(req.Argv0),
		Dir:     workdir,
		Env:     env,
		InitialSize: pty.Winsize{
			Rows: req.Rows,
			Cols: req.Cols,
		},
	})
	if err != nil {
		defer unlock()
		return nil, http.StatusInternalServerError, err
	}
	sess.SetCurrentProcessPID(ps.PID())

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
