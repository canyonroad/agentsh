package api

import (
	"context"
	"encoding/json"
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
	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

// seccompWrapperConfig is passed to the agentsh-unixwrap wrapper via
// AGENTSH_SECCOMP_CONFIG environment variable to configure seccomp-bpf filtering.
type seccompWrapperConfig struct {
	UnixSocketEnabled bool     `json:"unix_socket_enabled"`
	BlockedSyscalls   []string `json:"blocked_syscalls"`
}

// resolveProfile looks up a mount profile and validates it.
func (a *App) resolveProfile(profileName string) (*config.MountProfile, error) {
	if a.cfg.MountProfiles == nil {
		return nil, fmt.Errorf("no mount profiles configured")
	}
	profile, ok := a.cfg.MountProfiles[profileName]
	if !ok {
		return nil, fmt.Errorf("profile %q not found", profileName)
	}
	if len(profile.Mounts) == 0 {
		return nil, fmt.Errorf("profile %q has no mounts", profileName)
	}
	return &profile, nil
}

// setupProfileMounts creates FUSE mounts for all paths in a profile.
func (a *App) setupProfileMounts(ctx context.Context, s *session.Session, profile *config.MountProfile) ([]session.ResolvedMount, error) {
	var mounts []session.ResolvedMount

	mountBase := a.cfg.Sandbox.FUSE.MountBaseDir
	if mountBase == "" {
		mountBase = a.cfg.Sessions.BaseDir
	}

	for i, spec := range profile.Mounts {
		// Validate path exists
		if _, err := os.Stat(spec.Path); err != nil {
			// Cleanup already-created mounts
			for _, m := range mounts {
				if m.Unmount != nil {
					_ = m.Unmount()
				}
			}
			return nil, fmt.Errorf("mount path %q: %w", spec.Path, err)
		}

		// Load per-mount policy if specified
		var policyEngine *policy.Engine
		if spec.Policy != "" && a.policyLoader != nil {
			var err error
			policyEngine, err = a.policyLoader.Load(spec.Policy)
			if err != nil {
				// Cleanup already-created mounts
				for _, m := range mounts {
					if m.Unmount != nil {
						_ = m.Unmount()
					}
				}
				return nil, fmt.Errorf("load policy %q for mount %q: %w", spec.Policy, spec.Path, err)
			}
		} else {
			// Fall back to global policy if no per-mount policy specified
			policyEngine = a.policy
		}

		// Create mount point path
		mountPoint := filepath.Join(mountBase, s.ID, fmt.Sprintf("mount-%d", i))

		// Create FUSE mount if enabled
		if a.cfg.Sandbox.FUSE.Enabled && a.platform != nil {
			fs := a.platform.Filesystem()
			if fs != nil && fs.Available() {
				eventChan := make(chan platform.IOEvent, 1000)
				go a.processIOEvents(ctx, eventChan)

				fsCfg := platform.FSConfig{
					SourcePath: spec.Path,
					MountPoint: mountPoint,
					SessionID:  s.ID,
					CommandIDFunc: func() string {
						return s.CurrentCommandID()
					},
					PolicyEngine: platform.NewPolicyAdapter(policyEngine),
					EventChannel: eventChan,
				}

				m, err := fs.Mount(fsCfg)
				if err != nil {
					close(eventChan)
					// Log but continue - mount failure shouldn't block session
					a.logMountFailure(ctx, s.ID, spec.Path, mountPoint, err)
					continue
				}

				mounts = append(mounts, session.ResolvedMount{
					Path:         spec.Path,
					Policy:       spec.Policy,
					MountPoint:   mountPoint,
					PolicyEngine: policyEngine,
					Unmount: func() error {
						close(eventChan)
						return m.Close()
					},
				})
			}
		} else {
			// No FUSE, just track the mount without actual mounting
			mounts = append(mounts, session.ResolvedMount{
				Path:         spec.Path,
				Policy:       spec.Policy,
				MountPoint:   spec.Path, // Direct path when not using FUSE
				PolicyEngine: policyEngine,
			})
		}
	}

	return mounts, nil
}

func (a *App) logMountFailure(ctx context.Context, sessionID, path, mountPoint string, err error) {
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "fuse_mount_failed",
		SessionID: sessionID,
		Fields: map[string]any{
			"mount_point": mountPoint,
			"source_path": path,
			"error":       err.Error(),
		},
	}
	_ = a.store.AppendEvent(ctx, ev)
	a.broker.Publish(ev)
}

// createSessionWithProfile creates a session using a mount profile.
func (a *App) createSessionWithProfile(ctx context.Context, req types.CreateSessionRequest) (types.Session, int, error) {
	profile, err := a.resolveProfile(req.Profile)
	if err != nil {
		return types.Session{}, http.StatusBadRequest, err
	}

	basePolicy := profile.BasePolicy
	if basePolicy == "" {
		basePolicy = a.cfg.Policies.Default
	}

	// Build initial mounts from profile specs (without FUSE yet)
	var initialMounts []session.ResolvedMount
	for _, spec := range profile.Mounts {
		// Validate path exists
		if _, err := os.Stat(spec.Path); err != nil {
			return types.Session{}, http.StatusBadRequest, fmt.Errorf("mount path %q: %w", spec.Path, err)
		}
		initialMounts = append(initialMounts, session.ResolvedMount{
			Path:       spec.Path,
			Policy:     spec.Policy,
			MountPoint: spec.Path,
		})
	}

	// Create session with profile
	var s *session.Session
	if req.ID != "" {
		s, err = a.sessions.CreateWithProfile(req.ID, req.Profile, basePolicy, initialMounts)
	} else {
		s, err = a.sessions.CreateWithProfile("", req.Profile, basePolicy, initialMounts)
	}
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, session.ErrSessionExists) {
			code = http.StatusConflict
		}
		return types.Session{}, code, err
	}

	// Emit session_created event
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "session_created",
		SessionID: s.ID,
		Fields: map[string]any{
			"profile":     req.Profile,
			"base_policy": basePolicy,
			"mounts":      len(profile.Mounts),
		},
	}
	_ = a.store.AppendEvent(ctx, ev)
	a.broker.Publish(ev)

	// Setup FUSE mounts if enabled
	if a.cfg.Sandbox.FUSE.Enabled && a.platform != nil {
		mounts, err := a.setupProfileMounts(ctx, s, profile)
		if err != nil {
			// Cleanup session on mount failure
			_ = a.sessions.Destroy(s.ID)
			return types.Session{}, http.StatusInternalServerError, err
		}
		// Update session with resolved mounts
		s.Mounts = mounts
	}

	return s.Snapshot(), http.StatusCreated, nil
}

func (a *App) createSessionCore(ctx context.Context, req types.CreateSessionRequest) (types.Session, int, error) {
	// Handle profile-based session creation
	if req.Profile != "" {
		return a.createSessionWithProfile(ctx, req)
	}

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
	if a.cfg.Sandbox.FUSE.Enabled && a.platform != nil {
		fs := a.platform.Filesystem()
		if fs != nil && fs.Available() {
			mountBase := a.cfg.Sandbox.FUSE.MountBaseDir
			if mountBase == "" {
				mountBase = a.cfg.Sessions.BaseDir
			}
			mountPoint := filepath.Join(mountBase, s.ID, "workspace-mnt")
			hashLimit, _ := config.ParseByteSize(a.cfg.Sandbox.FUSE.Audit.HashSmallFilesUnder)

			// Create event channel for filesystem events
			eventChan := make(chan platform.IOEvent, 1000)

			// Start goroutine to process events from the channel
			go a.processIOEvents(ctx, eventChan)

			// Build platform FSConfig
			fsCfg := platform.FSConfig{
				SourcePath: s.Workspace,
				MountPoint: mountPoint,
				SessionID:  s.ID,
				CommandIDFunc: func() string {
					return s.CurrentCommandID()
				},
				PolicyEngine: platform.NewPolicyAdapter(a.policy),
				EventChannel: eventChan,
			}

			// Configure soft-delete/trash if enabled
			if a.cfg.Sandbox.FUSE.Audit.Mode == "soft_delete" {
				fsCfg.TrashConfig = &platform.TrashConfig{
					Enabled:        true,
					HashLimitBytes: hashLimit,
				}
				fsCfg.NotifySoftDelete = func(path, token string) {
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
				}
			}

			m, err := fs.Mount(fsCfg)
			if err != nil {
				fail := types.Event{
					ID:        uuid.NewString(),
					Timestamp: time.Now().UTC(),
					Type:      "fuse_mount_failed",
					SessionID: s.ID,
					Fields: map[string]any{
						"mount_point":    mountPoint,
						"error":          err.Error(),
						"implementation": fs.Implementation(),
					},
				}
				_ = a.store.AppendEvent(ctx, fail)
				a.broker.Publish(fail)
			} else {
				s.SetWorkspaceMount(mountPoint)
				// Wrap unmount to also close the event channel
				s.SetWorkspaceUnmount(func() error {
					close(eventChan)
					return m.Close()
				})
				okEv := types.Event{
					ID:        uuid.NewString(),
					Timestamp: time.Now().UTC(),
					Type:      "fuse_mounted",
					SessionID: s.ID,
					Fields: map[string]any{
						"mount_point":    mountPoint,
						"implementation": fs.Implementation(),
					},
				}
				_ = a.store.AppendEvent(ctx, okEv)
				a.broker.Publish(okEv)
			}
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

	// Start embedded LLM proxy if configured
	if a.cfg.Proxy.Mode == "embedded" {
		a.startLLMProxy(ctx, s)
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
		sp := createUnixSocketPair()
		if sp != nil {
			if wrappedReq.Env == nil {
				wrappedReq.Env = map[string]string{}
			}
			envFD := 3 // first ExtraFile
			wrappedReq.Env["AGENTSH_NOTIFY_SOCK_FD"] = strconv.Itoa(envFD)

			// Pass seccomp configuration to the wrapper
			seccompCfg := seccompWrapperConfig{
				UnixSocketEnabled: a.cfg.Sandbox.Seccomp.UnixSocket.Enabled,
				BlockedSyscalls:   a.cfg.Sandbox.Seccomp.Syscalls.Block,
			}
			if cfgJSON, err := json.Marshal(seccompCfg); err == nil {
				wrappedReq.Env["AGENTSH_SECCOMP_CONFIG"] = string(cfgJSON)
			}

			wrappedReq.Command = wrapperBin
			wrappedReq.Args = append([]string{"--", origCommand}, origArgs...)
			extraEnv := map[string]string{"AGENTSH_NOTIFY_SOCK_FD": strconv.Itoa(envFD)}
			if seccompJSON, ok := wrappedReq.Env["AGENTSH_SECCOMP_CONFIG"]; ok {
				extraEnv["AGENTSH_SECCOMP_CONFIG"] = seccompJSON
			}
			extraCfg = &extraProcConfig{
				extraFiles:       []*os.File{sp.child},
				env:              extraEnv,
				notifyParentSock: sp.parent,
				notifySessionID:  id,
				notifyPolicy:     a.policy,
				notifyStore:      a.store,
				notifyBroker:     a.broker,
			}
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

// processIOEvents reads events from the platform event channel and forwards
// them to the event store and broker. It runs until the channel is closed.
func (a *App) processIOEvents(ctx context.Context, eventChan <-chan platform.IOEvent) {
	for ioEvent := range eventChan {
		// Convert platform.IOEvent to types.Event
		ev := ioEvent.ToEvent()
		ev.ID = uuid.NewString()

		// Store and publish the event
		_ = a.store.AppendEvent(ctx, ev)
		a.broker.Publish(ev)
	}
}
