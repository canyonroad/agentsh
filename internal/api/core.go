package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/fsmonitor"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func (a *App) createSessionCore(ctx context.Context, req types.CreateSessionRequest) (types.Session, int, error) {
	if req.Policy == "" {
		req.Policy = a.cfg.Policies.Default
	}

	var s *session.Session
	var err error
	if req.ID != "" {
		s, err = a.sessions.CreateWithID(req.ID, req.Workspace, req.Policy)
	} else {
		s, err = a.sessions.Create(req.Workspace, req.Policy)
	}
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, session.ErrSessionExists) {
			code = http.StatusConflict
		}
		return types.Session{}, code, err
	}

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "session_created",
		SessionID: s.ID,
		Fields: map[string]any{
			"workspace": s.Workspace,
			"policy":    s.Policy,
		},
	}
	_ = a.store.AppendEvent(ctx, ev)
	a.broker.Publish(ev)

	// Optional: mount FUSE loopback so we can monitor file operations.
	if a.cfg.Sandbox.FUSE.Enabled {
		mountBase := a.cfg.Sandbox.FUSE.MountBaseDir
		if mountBase == "" {
			mountBase = a.cfg.Sessions.BaseDir
		}
		mountPoint := filepath.Join(mountBase, s.ID, "workspace-mnt")
		em := storeEmitter{store: a.store, broker: a.broker}
		hashLimit, _ := config.ParseByteSize(a.cfg.Sandbox.FUSE.Audit.HashSmallFilesUnder)
		auditHooks := &fsmonitor.FUSEAuditHooks{
			Config:         a.cfg.Sandbox.FUSE.Audit,
			HashLimitBytes: hashLimit,
			NotifySoftDelete: func(path, token string) {
				ev := types.Event{
					ID:        uuid.NewString(),
					Timestamp: time.Now().UTC(),
					Type:      "file_soft_deleted",
					SessionID: s.ID,
					CommandID: s.CurrentCommandID(),
					Path:      path,
					Fields: map[string]any{
						"trash_token":  token,
						"restore_hint": fmt.Sprintf("agentsh trash restore %s", token),
					},
				}
				_ = a.store.AppendEvent(ctx, ev)
				a.broker.Publish(ev)
			},
		}
		m, err := fsmonitor.MountWorkspace(s.Workspace, mountPoint, &fsmonitor.Hooks{
			SessionID: s.ID,
			Session:   s,
			Policy:    a.policy,
			Approvals: a.approvals,
			Emit:      em,
			FUSEAudit: auditHooks,
		})
		if err != nil {
			fail := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "fuse_mount_failed",
				SessionID: s.ID,
				Fields: map[string]any{
					"mount_point": mountPoint,
					"error":       err.Error(),
				},
			}
			_ = a.store.AppendEvent(ctx, fail)
			a.broker.Publish(fail)
		} else {
			s.SetWorkspaceMount(mountPoint)
			s.SetWorkspaceUnmount(m.Unmount)
			okEv := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "fuse_mounted",
				SessionID: s.ID,
				Fields: map[string]any{
					"mount_point": mountPoint,
				},
			}
			_ = a.store.AppendEvent(ctx, okEv)
			a.broker.Publish(okEv)
		}
	}

	// Optional: start transparent network interception; fall back to explicit proxy on failure.
	if a.cfg.Sandbox.Network.Transparent.Enabled {
		if err := a.tryStartTransparentNetwork(ctx, s); err != nil {
			fail := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "transparent_net_failed",
				SessionID: s.ID,
				Fields: map[string]any{
					"error": err.Error(),
				},
			}
			_ = a.store.AppendEvent(ctx, fail)
			a.broker.Publish(fail)
			// Fall back to explicit proxy if configured.
			if a.cfg.Sandbox.Network.Enabled {
				a.startExplicitProxy(ctx, s)
			}
		} else {
			okEv := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "transparent_net_ready",
				SessionID: s.ID,
			}
			_ = a.store.AppendEvent(ctx, okEv)
			a.broker.Publish(okEv)
		}
	} else if a.cfg.Sandbox.Network.Enabled {
		a.startExplicitProxy(ctx, s)
	}

	return s.Snapshot(), http.StatusCreated, nil
}

func (a *App) execInSessionCore(ctx context.Context, id string, req types.ExecRequest) (*types.ExecResponse, int, error) {
	s, ok := a.sessions.Get(id)
	if !ok {
		return nil, http.StatusNotFound, errors.New("session not found")
	}
	if strings.TrimSpace(req.Command) == "" {
		return nil, http.StatusBadRequest, errors.New("command is required")
	}

	cmdID := "cmd-" + uuid.NewString()
	start := time.Now().UTC()
	unlock := s.LockExec()
	defer unlock()
	s.SetCurrentCommandID(cmdID)

	includeEvents := strings.ToLower(strings.TrimSpace(req.IncludeEvents))
	if includeEvents == "" {
		includeEvents = "all"
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
	_ = a.store.AppendEvent(ctx, preEv)
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
		_ = a.store.AppendEvent(ctx, redirEv)
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
		g := guidanceForPolicyDenied(req, pre, preEv, approvalErr)
		resp := &types.ExecResponse{
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
					Suggestions: func() []types.Suggestion {
						if g == nil {
							return nil
						}
						return g.Suggestions
					}(),
				},
			},
			Events: types.ExecEvents{
				FileOperations:         []types.Event{},
				NetworkOperations:      []types.Event{},
				BlockedOperations:      []types.Event{preEv},
				FileOperationsCount:    0,
				NetworkOperationsCount: 0,
				BlockedOperationsCount: 1,
				OtherCount:             0,
			},
			Guidance: g,
		}
		applyIncludeEvents(resp, includeEvents)
		return resp, http.StatusForbidden, nil
	}

	origCommand := req.Command
	origArgs := append([]string{}, req.Args...)

	wrappedReq := req
	unixEnabled := a.cfg.Sandbox.UnixSockets.Enabled
	wrapperBin := strings.TrimSpace(a.cfg.Sandbox.UnixSockets.WrapperBin)
	var extraCfg *extraProcConfig
	if unixEnabled {
		if wrapperBin == "" {
			wrapperBin = "agentsh-unixwrap"
		}
		sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
		if err == nil {
			parent := os.NewFile(uintptr(sp[0]), "notify-parent")
			child := os.NewFile(uintptr(sp[1]), "notify-child")
			if wrappedReq.Env == nil {
				wrappedReq.Env = map[string]string{}
			}
			envFD := 3 // first ExtraFile
			wrappedReq.Env["AGENTSH_NOTIFY_SOCK_FD"] = strconv.Itoa(envFD)
			wrappedReq.Command = wrapperBin
			wrappedReq.Args = append([]string{"--", origCommand}, origArgs...)
			extraCfg = &extraProcConfig{
				extraFiles: []*os.File{child},
				env:        map[string]string{"AGENTSH_NOTIFY_SOCK_FD": strconv.Itoa(envFD)},
			}
			// TODO: receive notify fd from parent (notify-parent) and start ServeNotify; monitor-only for now.
			// Currently we close the parent side and ignore notifications until enforcement is wired.
			_ = parent.Close()
		}
	}

	startEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: start,
		Type:      "command_started",
		SessionID: id,
		CommandID: cmdID,
		Fields: map[string]any{
			"command": origCommand,
			"args":    origArgs,
		},
	}
	_ = a.store.AppendEvent(ctx, startEv)
	a.broker.Publish(startEv)

	limits := a.policy.Limits()
	cmdDecision := a.policy.CheckCommand(wrappedReq.Command, wrappedReq.Args)
	exitCode, stdoutB, stderrB, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, execErr := runCommandWithResources(ctx, s, cmdID, wrappedReq, a.cfg, cmdDecision.EnvPolicy, limits.CommandTimeout, a.cgroupHook(id, cmdID, limits), extraCfg)

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
	_ = a.store.AppendEvent(ctx, endEv)
	a.broker.Publish(endEv)

	collected, _ := a.store.QueryEvents(ctx, types.EventQuery{
		CommandID: cmdID,
		Limit:     5000,
		Asc:       true,
	})
	var fileOps, netOps, blockedOps, otherOps []types.Event
	for _, ev := range collected {
		isBlocked := false
		if ev.Policy != nil && ev.Policy.EffectiveDecision == types.DecisionDeny {
			isBlocked = true
		}
		if b, ok := ev.Fields["blocked"].(bool); ok && b {
			isBlocked = true
		}
		if isBlocked {
			blockedOps = append(blockedOps, ev)
		}

		switch {
		case strings.HasPrefix(ev.Type, "file_") || strings.HasPrefix(ev.Type, "dir_") || strings.HasPrefix(ev.Type, "symlink_"):
			fileOps = append(fileOps, ev)
		case strings.HasPrefix(ev.Type, "net_") || ev.Type == "dns_query":
			netOps = append(netOps, ev)
		default:
			otherOps = append(otherOps, ev)
		}
	}
	if fileOps == nil {
		fileOps = []types.Event{}
	}
	if netOps == nil {
		netOps = []types.Event{}
	}
	if blockedOps == nil {
		blockedOps = []types.Event{}
	}
	if otherOps == nil {
		otherOps = []types.Event{}
	}

	stderrB, stderrTotal, softSuggestions := addSoftDeleteHints(fileOps, stderrB, stderrTotal)

	res := types.ExecResult{
		ExitCode:         exitCode,
		Stdout:           string(stdoutB),
		Stderr:           string(stderrB),
		StdoutTruncated:  stdoutTrunc,
		StderrTruncated:  stderrTrunc,
		StdoutTotalBytes: stdoutTotal,
		StderrTotalBytes: stderrTotal,
		DurationMs:       int64(end.Sub(start).Milliseconds()),
	}
	if execErr != nil {
		res.Error = &types.ExecError{
			Code:    "E_COMMAND_FAILED",
			Message: execErr.Error(),
		}
	}
	if stdoutTrunc && stdoutTotal > int64(len(stdoutB)) {
		res.Pagination = &types.Pagination{
			CurrentOffset: 0,
			CurrentLimit:  int64(len(stdoutB)),
			HasMore:       true,
			NextCommand:   fmt.Sprintf("agentsh output %s %s --stream stdout --offset %d --limit %d", id, cmdID, len(stdoutB), len(stdoutB)),
		}
	}

	resp := &types.ExecResponse{
		CommandID: cmdID,
		SessionID: id,
		Timestamp: start,
		Request:   req,
		Result:    res,
		Events: types.ExecEvents{
			FileOperations:         fileOps,
			NetworkOperations:      netOps,
			BlockedOperations:      blockedOps,
			Other:                  otherOps,
			FileOperationsCount:    len(fileOps),
			NetworkOperationsCount: len(netOps),
			BlockedOperationsCount: len(blockedOps),
			OtherCount:             len(otherOps),
		},
		Resources: &resources,
		Guidance:  guidanceForResponse(req, res, blockedOps),
	}
	addRedirectGuidance(resp, pre, originalCmd, originalArgs)
	if len(softSuggestions) > 0 {
		if resp.Guidance == nil {
			resp.Guidance = &types.ExecGuidance{Status: "ok"}
		}
		resp.Guidance.Suggestions = append(resp.Guidance.Suggestions, softSuggestions...)
	}
	_ = a.store.SaveOutput(ctx, id, cmdID, stdoutB, stderrB, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc)
	applyIncludeEvents(resp, includeEvents)
	return resp, http.StatusOK, nil
}
