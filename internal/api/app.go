package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/auth"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/fsmonitor"
	"github.com/agentsh/agentsh/internal/netmonitor"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type App struct {
	cfg      *config.Config
	sessions *session.Manager
	store    *composite.Store
	policy   *policy.Engine
	broker   *events.Broker

	apiKeyAuth *auth.APIKeyAuth

	approvals *approvals.Manager
}

func NewApp(cfg *config.Config, sessions *session.Manager, store *composite.Store, engine *policy.Engine, broker *events.Broker, apiKeyAuth *auth.APIKeyAuth, approvalsMgr *approvals.Manager) *App {
	return &App{cfg: cfg, sessions: sessions, store: store, policy: engine, broker: broker, apiKeyAuth: apiKeyAuth, approvals: approvalsMgr}
}

func (a *App) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(a.authMiddleware)

	r.Get(a.cfg.Health.Path, func(w http.ResponseWriter, r *http.Request) { writeText(w, http.StatusOK, "ok\n") })
	r.Get(a.cfg.Health.ReadinessPath, func(w http.ResponseWriter, r *http.Request) { writeText(w, http.StatusOK, "ready\n") })

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/sessions", a.createSession)
		r.Get("/sessions", a.listSessions)
		r.Get("/sessions/{id}", a.getSession)
		r.Delete("/sessions/{id}", a.destroySession)

		r.Post("/sessions/{id}/exec", a.execInSession)
		r.Get("/sessions/{id}/events", a.streamEvents)
		r.Get("/sessions/{id}/history", a.sessionHistory)
		r.Get("/sessions/{id}/output/{cmdID}", a.getOutputChunk)

		r.Get("/events/search", a.searchEvents)

		r.Get("/approvals", a.listApprovals)
		r.Post("/approvals/{id}", a.resolveApproval)
	})

	return r
}

func (a *App) authMiddleware(next http.Handler) http.Handler {
	if a.cfg.Development.DisableAuth || strings.EqualFold(a.cfg.Auth.Type, "none") {
		return next
	}
	if strings.EqualFold(a.cfg.Auth.Type, "api_key") {
		if a.apiKeyAuth == nil {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{
					"error": "api key auth enabled but keys not loaded",
				})
			})
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get(a.apiKeyAuth.HeaderName())
			if key == "" || !a.apiKeyAuth.IsAllowed(key) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unsupported auth type"})
	})
}

func (a *App) createSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Workspace string `json:"workspace"`
		Policy    string `json:"policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	if req.Policy == "" {
		req.Policy = a.cfg.Policies.Default
	}
	s, err := a.sessions.Create(req.Workspace, req.Policy)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
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
	_ = a.store.AppendEvent(r.Context(), ev)
	a.broker.Publish(ev)

	// Optional: mount FUSE loopback so we can monitor file operations.
	if a.cfg.Sandbox.FUSE.Enabled {
		mountBase := a.cfg.Sandbox.FUSE.MountBaseDir
		if mountBase == "" {
			mountBase = a.cfg.Sessions.BaseDir
		}
		mountPoint := filepath.Join(mountBase, s.ID, "workspace-mnt")
		em := storeEmitter{store: a.store, broker: a.broker}
		m, err := fsmonitor.MountWorkspace(s.Workspace, mountPoint, &fsmonitor.Hooks{
			SessionID: s.ID,
			Session:   s,
			Policy:    a.policy,
			Approvals: a.approvals,
			Emit:      em,
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
			_ = a.store.AppendEvent(r.Context(), fail)
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
			_ = a.store.AppendEvent(r.Context(), okEv)
			a.broker.Publish(okEv)
		}
	}

	// Optional: start transparent network interception; fall back to explicit proxy on failure.
	if a.cfg.Sandbox.Network.Transparent.Enabled {
		if err := a.tryStartTransparentNetwork(r.Context(), s); err != nil {
			fail := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "transparent_net_failed",
				SessionID: s.ID,
				Fields: map[string]any{
					"error": err.Error(),
				},
			}
			_ = a.store.AppendEvent(r.Context(), fail)
			a.broker.Publish(fail)
			// Fall back to explicit proxy if configured.
			if a.cfg.Sandbox.Network.Enabled {
				a.startExplicitProxy(r.Context(), s)
			}
		} else {
			okEv := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "transparent_net_ready",
				SessionID: s.ID,
			}
			_ = a.store.AppendEvent(r.Context(), okEv)
			a.broker.Publish(okEv)
		}
	} else if a.cfg.Sandbox.Network.Enabled {
		a.startExplicitProxy(r.Context(), s)
	}

	writeJSON(w, http.StatusCreated, s.Snapshot())
}

func (a *App) startExplicitProxy(ctx context.Context, s *session.Session) {
	em := storeEmitter{store: a.store, broker: a.broker}
	pr, proxyURL, err := netmonitor.StartProxy(a.cfg.Sandbox.Network.ProxyListenAddr, s.ID, s, a.policy, a.approvals, em)
	if err != nil {
		fail := types.Event{
			ID:        uuid.NewString(),
			Timestamp: time.Now().UTC(),
			Type:      "net_proxy_failed",
			SessionID: s.ID,
			Fields: map[string]any{
				"error": err.Error(),
			},
		}
		_ = a.store.AppendEvent(ctx, fail)
		a.broker.Publish(fail)
		return
	}

	s.SetProxy(proxyURL, pr.Close)
	okEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "net_proxy_started",
		SessionID: s.ID,
		Fields: map[string]any{
			"proxy_url": proxyURL,
		},
	}
	_ = a.store.AppendEvent(ctx, okEv)
	a.broker.Publish(okEv)
}

func (a *App) tryStartTransparentNetwork(ctx context.Context, s *session.Session) error {
	// Implementation uses root-only Linux network namespaces. If it fails, we leave the session in proxy-env mode.
	em := storeEmitter{store: a.store, broker: a.broker}

	// Start interceptors on host; netns will DNAT to host veth IP.
	tcp, tcpPort, err := netmonitor.StartTransparentTCP("0.0.0.0:0", s.ID, s, a.policy, a.approvals, em)
	if err != nil {
		return err
	}
	dns, dnsPort, err := netmonitor.StartDNS("0.0.0.0:0", "8.8.8.8:53", s.ID, s, a.policy, a.approvals, em)
	if err != nil {
		_ = tcp.Close()
		return err
	}

	nsName := "agentsh-" + strings.TrimPrefix(s.ID, "session-")
	subnetCIDR, hostIPCIDR, nsIPCIDR, hostIf, nsIf := netmonitor.AllocateSubnet(a.cfg.Sandbox.Network.Transparent.SubnetBase, nsName)
	ns, err := netmonitor.SetupNetNS(ctx, nsName, subnetCIDR, hostIf, nsIf, hostIPCIDR, nsIPCIDR, tcpPort, dnsPort)
	if err != nil {
		_ = tcp.Close()
		_ = dns.Close()
		return err
	}

	s.SetNetNS(nsName, func() error {
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ns.Close(cctx)
		_ = tcp.Close()
		_ = dns.Close()
		return nil
	})

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "transparent_net_setup",
		SessionID: s.ID,
		Fields: map[string]any{
			"netns":      ns.Name,
			"subnet":     ns.SubnetCIDR,
			"host_ip":    ns.HostIP,
			"ns_ip":      ns.NSIP,
			"proxy_port": tcpPort,
			"dns_port":   dnsPort,
		},
	}
	_ = a.store.AppendEvent(ctx, ev)
	a.broker.Publish(ev)
	return nil
}

func (a *App) listSessions(w http.ResponseWriter, r *http.Request) {
	all := a.sessions.List()
	out := make([]types.Session, 0, len(all))
	for _, s := range all {
		out = append(out, s.Snapshot())
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) getSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}
	writeJSON(w, http.StatusOK, s.Snapshot())
}

func (a *App) destroySession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}
	_ = s.CloseNetNS()
	_ = s.CloseProxy()
	_ = s.UnmountWorkspace()
	_ = a.sessions.Destroy(id)

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "session_destroyed",
		SessionID: id,
	}
	_ = a.store.AppendEvent(r.Context(), ev)
	a.broker.Publish(ev)

	w.WriteHeader(http.StatusNoContent)
}

type storeEmitter struct {
	store  *composite.Store
	broker *events.Broker
}

func (e storeEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	return e.store.AppendEvent(ctx, ev)
}
func (e storeEmitter) Publish(ev types.Event) { e.broker.Publish(ev) }

func (a *App) execInSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	var req types.ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
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

	pre := a.policy.CheckCommand(req.Command, req.Args)
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
		},
		Fields: map[string]any{
			"command": req.Command,
			"args":    req.Args,
		},
	}
	_ = a.store.AppendEvent(r.Context(), preEv)
	a.broker.Publish(preEv)

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
	_ = a.store.AppendEvent(r.Context(), startEv)
	a.broker.Publish(startEv)

	limits := a.policy.Limits()
	exitCode, stdoutB, stderrB, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, execErr := runCommand(r.Context(), s, cmdID, req, a.cfg, limits.CommandTimeout)

	_ = a.store.SaveOutput(r.Context(), id, cmdID, stdoutB, stderrB, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc)

	end := time.Now().UTC()
	endEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: end,
		Type:      "command_finished",
		SessionID: id,
		CommandID: cmdID,
		Fields: map[string]any{
			"exit_code":   exitCode,
			"duration_ms": int64(end.Sub(start).Milliseconds()),
		},
	}
	if execErr != nil {
		endEv.Fields["error"] = execErr.Error()
	}
	_ = a.store.AppendEvent(r.Context(), endEv)
	a.broker.Publish(endEv)

	// Collect events for this command (including file events emitted by FUSE).
	collected, _ := a.store.QueryEvents(r.Context(), types.EventQuery{
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

	resp := types.ExecResponse{
		CommandID: cmdID,
		SessionID: id,
		Timestamp: start,
		Request:   req,
		Result:    res,
		Events: types.ExecEvents{
			FileOperations:    fileOps,
			NetworkOperations: netOps,
			BlockedOperations: blockedOps,
			Other:             otherOps,
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) streamEvents(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, ok := a.sessions.Get(id); !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "stream unsupported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := a.broker.Subscribe(id, 200)
	defer a.broker.Unsubscribe(id, ch)

	_, _ = w.Write([]byte("event: ready\ndata: {}\n\n"))
	flusher.Flush()

	enc := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			_, _ = w.Write([]byte("data: "))
			if err := enc.Encode(ev); err != nil {
				return
			}
			_, _ = w.Write([]byte("\n"))
			flusher.Flush()
		}
	}
}

func (a *App) sessionHistory(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, ok := a.sessions.Get(id); !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}
	q, err := parseEventQuery(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	q.SessionID = id
	evs, err := a.store.QueryEvents(r.Context(), q)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, evs)
}

func (a *App) searchEvents(w http.ResponseWriter, r *http.Request) {
	q, err := parseEventQuery(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if sid := r.URL.Query().Get("session_id"); sid != "" {
		q.SessionID = sid
	}
	evs, err := a.store.QueryEvents(r.Context(), q)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, evs)
}

func (a *App) getOutputChunk(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if _, ok := a.sessions.Get(sessionID); !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	cmdID := chi.URLParam(r, "cmdID")
	stream := r.URL.Query().Get("stream")
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	limit, _ := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 64)

	chunk, total, truncated, err := a.store.ReadOutputChunk(r.Context(), cmdID, stream, offset, limit)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"command_id":  cmdID,
		"stream":      stream,
		"offset":      offset,
		"limit":       limit,
		"total_bytes": total,
		"truncated":   truncated,
		"data":        string(chunk),
		"has_more":    offset+int64(len(chunk)) < total,
	})
}

func (a *App) listApprovals(w http.ResponseWriter, r *http.Request) {
	if a.approvals == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, a.approvals.ListPending())
}

func (a *App) resolveApproval(w http.ResponseWriter, r *http.Request) {
	if a.approvals == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "approvals not enabled"})
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		Decision string `json:"decision"` // "approve" or "deny"
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	approved := strings.EqualFold(req.Decision, "approve") || strings.EqualFold(req.Decision, "allow")
	if ok := a.approvals.Resolve(id, approved, req.Reason); !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "approval not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func parseEventQuery(r *http.Request) (types.EventQuery, error) {
	v := r.URL.Query()
	var q types.EventQuery
	q.CommandID = v.Get("command_id")
	if t := v.Get("type"); t != "" {
		q.Types = strings.Split(t, ",")
	}
	if decision := v.Get("decision"); decision != "" {
		d := types.Decision(decision)
		q.Decision = &d
	}
	q.PathLike = v.Get("path_like")
	q.DomainLike = v.Get("domain_like")
	q.TextLike = v.Get("text_like")
	q.Limit, _ = strconv.Atoi(v.Get("limit"))
	q.Offset, _ = strconv.Atoi(v.Get("offset"))
	q.Asc = v.Get("order") == "asc"

	if since := v.Get("since"); since != "" {
		t, err := parseTimeOrAgo(since)
		if err != nil {
			return q, fmt.Errorf("since: %w", err)
		}
		q.Since = &t
	}
	if until := v.Get("until"); until != "" {
		t, err := parseTimeOrAgo(until)
		if err != nil {
			return q, fmt.Errorf("until: %w", err)
		}
		q.Until = &t
	}
	return q, nil
}

func parseTimeOrAgo(s string) (time.Time, error) {
	if strings.ContainsAny(s, "smhdw") && !strings.Contains(s, "T") {
		d, err := time.ParseDuration(s)
		if err != nil {
			return time.Time{}, err
		}
		return time.Now().UTC().Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeText(w http.ResponseWriter, status int, s string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(s))
}
