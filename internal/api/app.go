package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/auth"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/netmonitor"
	ebpftrace "github.com/agentsh/agentsh/internal/netmonitor/ebpf"
	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/internal/trash"
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

	metrics *metrics.Collector

	// platform provides cross-platform filesystem, network, and sandbox abstractions
	platform platform.Platform
}

func NewApp(cfg *config.Config, sessions *session.Manager, store *composite.Store, engine *policy.Engine, broker *events.Broker, apiKeyAuth *auth.APIKeyAuth, approvalsMgr *approvals.Manager, metricsCollector *metrics.Collector) *App {
	// Apply EBPF map size overrides once per process (global maps); no-op if zero values.
	ebpftrace.SetMapSizeOverrides(
		uint32(cfg.Sandbox.Network.EBPF.MapAllowEntries),
		uint32(cfg.Sandbox.Network.EBPF.MapDenyEntries),
		uint32(cfg.Sandbox.Network.EBPF.MapLPMEntries),
		uint32(cfg.Sandbox.Network.EBPF.MapLPMDenyEntries),
		uint32(cfg.Sandbox.Network.EBPF.MapDefaultEntries),
	)

	// Initialize platform abstraction
	plat, err := platform.New()
	if err != nil {
		// Log but don't fail - platform features will be unavailable
		fmt.Fprintf(os.Stderr, "platform init: %v\n", err)
	}

	return &App{
		cfg:        cfg,
		sessions:   sessions,
		store:      store,
		policy:     engine,
		broker:     broker,
		apiKeyAuth: apiKeyAuth,
		approvals:  approvalsMgr,
		metrics:    metricsCollector,
		platform:   plat,
	}
}

type ctxKey string

const ctxKeyRole ctxKey = "role"

func (a *App) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(a.authMiddleware)

	if a.cfg.Metrics.Enabled && a.cfg.Metrics.Path != "" && a.metrics != nil {
		r.Get(a.cfg.Metrics.Path, func(w http.ResponseWriter, r *http.Request) {
			a.metrics.Handler(metrics.HandlerOptions{SessionCount: a.sessions.Count}).ServeHTTP(w, r)
		})
	}
	// Lightweight EBPF debug endpoint (read-only) for map overrides and DNS cache size.
	r.Get("/debug/ebpf", func(w http.ResponseWriter, r *http.Request) {
		ov := ebpftrace.GetMapOverrides()
		def, _ := ebpftrace.EmbeddedMapDefaults()
		writeJSON(w, http.StatusOK, map[string]any{
			"map_allow_override":    ov.Allow,
			"map_lpm_override":      ov.LPM,
			"map_deny_override":     ov.Deny,
			"map_lpm_deny_override": ov.LPMDeny,
			"map_default_override":  ov.Default,
			"map_allow_default":     def.Allow,
			"map_deny_default":      def.Deny,
			"map_lpm_default":       def.LPM,
			"map_lpm_deny_default":  def.LPMDeny,
			"map_default_default":   def.Default,
			"map_counts_last":       ebpftrace.GetLastMapCounts(),
			"map_counts_note":       "map_counts_last reflects the most recent PopulateAllowlist, not live occupancy",
			"dns_cache_entries":     DNSCacheLen(),
			"dns_cache_metrics":     DNSMetrics(),
		})
	})
	r.Get(a.cfg.Health.Path, func(w http.ResponseWriter, r *http.Request) { writeText(w, http.StatusOK, "ok\n") })
	r.Get(a.cfg.Health.ReadinessPath, func(w http.ResponseWriter, r *http.Request) { writeText(w, http.StatusOK, "ready\n") })

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/sessions", a.createSession)
		r.Get("/sessions", a.listSessions)
		r.Get("/sessions/{id}", a.getSession)
		r.Patch("/sessions/{id}", a.patchSession)
		r.Delete("/sessions/{id}", a.destroySession)

		r.Post("/sessions/{id}/exec", a.execInSession)
		r.Post("/sessions/{id}/exec/stream", a.execInSessionStream)
		r.Get("/sessions/{id}/pty", a.execInSessionPTYWS)
		r.Get("/sessions/{id}/events", a.streamEvents)
		r.Get("/sessions/{id}/history", a.sessionHistory)
		r.Get("/sessions/{id}/output/{cmdID}", a.getOutputChunk)
		r.Post("/sessions/{id}/kill/{cmdID}", a.killCommand)

		r.Get("/events/search", a.searchEvents)

		r.Group(func(r chi.Router) {
			r.Use(a.requireRoles("approver", "admin"))
			r.Get("/approvals", a.listApprovals)
			r.Post("/approvals/{id}", a.resolveApproval)
		})

		// Policy management (admin only)
		r.Group(func(r chi.Router) {
			r.Use(a.requireRoles("admin"))
			r.Get("/policies", a.listPolicies)
			r.Post("/policies", a.createPolicy)
			r.Get("/policies/{policyId}", a.getPolicy)
			r.Put("/policies/{policyId}", a.updatePolicy)
			r.Delete("/policies/{policyId}", a.deletePolicy)
			r.Post("/policies/validate", a.validatePolicy)
		})

		// Policy test endpoint (for debugging)
		r.Post("/policy/test", a.policyTest)
	})

	return r
}

func (a *App) authMiddleware(next http.Handler) http.Handler {
	if a.cfg.Development.DisableAuth || strings.EqualFold(a.cfg.Auth.Type, "none") {
		return next
	}
	// Always allow health/readiness probes without auth so local tooling (including CLI auto-start)
	// can reliably detect server availability.
	if a.cfg.Health.Path != "" || a.cfg.Health.ReadinessPath != "" {
		healthPath := a.cfg.Health.Path
		readyPath := a.cfg.Health.ReadinessPath
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL != nil {
				switch r.URL.Path {
				case healthPath, readyPath:
					next.ServeHTTP(w, r)
					return
				}
			}
			a.authMiddlewareProtected(next).ServeHTTP(w, r)
		})
	}
	return a.authMiddlewareProtected(next)
}

func (a *App) authMiddlewareProtected(next http.Handler) http.Handler {
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
			role := a.apiKeyAuth.RoleForKey(key)
			ctx := context.WithValue(r.Context(), ctxKeyRole, role)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unsupported auth type"})
	})
}

func (a *App) requireRoles(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allowed[strings.ToLower(strings.TrimSpace(r))] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a.cfg.Development.DisableAuth || strings.EqualFold(a.cfg.Auth.Type, "none") {
				// Safety: if auth is disabled, do not allow access to approval endpoints.
				// Otherwise an agent could self-approve by calling the approvals API.
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error": "approvals endpoints require auth (set auth.type=api_key and use separate agent/approver keys)",
				})
				return
			}
			role, _ := r.Context().Value(ctxKeyRole).(string)
			if role == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
				return
			}
			if _, ok := allowed[strings.ToLower(role)]; !ok {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *App) createSession(w http.ResponseWriter, r *http.Request) {
	var req types.CreateSessionRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	snap, code, err := a.createSessionCore(r.Context(), req)
	if err != nil {
		writeJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, code, snap)
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
	dnsCache := netmonitor.NewDNSCache(5 * time.Minute)
	tcp, tcpPort, err := netmonitor.StartTransparentTCP("0.0.0.0:0", s.ID, s, dnsCache, a.policy, a.approvals, em)
	if err != nil {
		return err
	}
	dns, dnsPort, err := netmonitor.StartDNS("0.0.0.0:0", "8.8.8.8:53", s.ID, s, dnsCache, a.policy, a.approvals, em)
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

func (a *App) patchSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	var req types.SessionPatchRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	if err := s.ApplyPatch(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "session_updated",
		SessionID: id,
		Fields: map[string]any{
			"cwd":   req.Cwd,
			"env":   req.Env,
			"unset": req.Unset,
		},
	}
	_ = a.store.AppendEvent(r.Context(), ev)
	a.broker.Publish(ev)

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
	a.purgeTrashForSession(s)
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

func (a *App) purgeTrashForSession(s *session.Session) {
	if a == nil || a.cfg == nil {
		return
	}
	cfg := a.cfg.Sandbox.FUSE.Audit
	if cfg.Enabled != nil && !*cfg.Enabled {
		return
	}
	trashPath := cfg.TrashPath
	if trashPath == "" {
		trashPath = ".agentsh_trash"
	}
	if !filepath.IsAbs(trashPath) {
		trashPath = filepath.Join(s.Workspace, trashPath)
	}
	var ttl time.Duration
	if cfg.TTL != "" {
		if d, err := time.ParseDuration(cfg.TTL); err == nil {
			ttl = d
		} else {
			fmt.Fprintf(os.Stderr, "trash purge: invalid ttl %q: %v\n", cfg.TTL, err)
		}
	}
	var quota int64
	if cfg.Quota != "" {
		if q, err := config.ParseByteSize(cfg.Quota); err == nil {
			quota = q
		} else {
			fmt.Fprintf(os.Stderr, "trash purge: invalid quota %q: %v\n", cfg.Quota, err)
		}
	}
	_, _ = trash.Purge(trashPath, trash.PurgeOptions{
		TTL:        ttl,
		QuotaBytes: quota,
		Session:    s.ID,
	})
}

func (a *App) killCommand(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(sessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}
	cmdID := chi.URLParam(r, "cmdID")
	current := s.CurrentCommandID()
	if current == "" || current != cmdID {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "command not running"})
		return
	}
	pid := s.CurrentProcessPID()
	if pid <= 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "command pid not available"})
		return
	}

	// Send to process group; terminate gracefully first, then forcefully.
	_ = killProcess(pid)
	go func() {
		time.Sleep(2 * time.Second)
		_ = killProcessHard(pid)
	}()

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "command_killed",
		SessionID: sessionID,
		CommandID: cmdID,
		Fields: map[string]any{
			"pid":    pid,
			"signal": "TERM",
		},
	}
	_ = a.store.AppendEvent(r.Context(), ev)
	a.broker.Publish(ev)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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
	var req types.ExecRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}
	resp, code, err := a.execInSessionCore(r.Context(), id, req)
	if err != nil {
		writeJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, code, resp)
}

func (a *App) cgroupHook(sessionID string, cmdID string, limits policy.Limits) postStartHook {
	return func(pid int) (func() error, error) {
		if a == nil || a.cfg == nil || !a.cfg.Sandbox.Cgroups.Enabled {
			return nil, nil
		}
		em := storeEmitter{store: a.store, broker: a.broker}
		return applyCgroupV2(context.Background(), em, a.cfg, sessionID, cmdID, pid, limits, a.metrics, a.policy)
	}
}

func applyIncludeEvents(resp *types.ExecResponse, include string) {
	if resp == nil {
		return
	}
	switch include {
	case "all":
		return
	case "none":
		resp.Events.Truncated = true
		resp.Events.FileOperations = []types.Event{}
		resp.Events.NetworkOperations = []types.Event{}
		resp.Events.BlockedOperations = []types.Event{}
		resp.Events.Other = []types.Event{}
		return
	case "blocked":
		resp.Events.Truncated = true
		resp.Events.FileOperations = []types.Event{}
		resp.Events.NetworkOperations = []types.Event{}
		resp.Events.Other = []types.Event{}
		return
	case "summary":
		const maxBlocked = 25
		resp.Events.Truncated = true
		resp.Events.FileOperations = []types.Event{}
		resp.Events.NetworkOperations = []types.Event{}
		resp.Events.Other = []types.Event{}
		if len(resp.Events.BlockedOperations) > maxBlocked {
			resp.Events.BlockedOperations = resp.Events.BlockedOperations[:maxBlocked]
		}
		return
	default:
		// Unknown value: keep backward compatible behavior.
		return
	}
}

// addSoftDeleteHints appends restore hints to stderr and returns suggestions for guidance.
func addSoftDeleteHints(fileOps []types.Event, stderrB []byte, stderrTotal int64) ([]byte, int64, []types.Suggestion) {
	var softSuggestions []types.Suggestion
	for _, ev := range fileOps {
		if ev.Type != "file_soft_deleted" {
			continue
		}
		token := fmt.Sprint(ev.Fields["trash_token"])
		path := ev.Path
		cmd := fmt.Sprintf("agentsh trash restore %s", token)
		softSuggestions = append(softSuggestions, types.Suggestion{
			Action:  "restore file",
			Command: cmd,
			Reason:  fmt.Sprintf("soft-deleted: %s (token=%s)", path, token),
		})
		hint := fmt.Sprintf("soft-delete: %s -> trash token %s; restore with: %s\n", path, token, cmd)
		stderrB = append(stderrB, []byte(hint)...)
		stderrTotal += int64(len(hint))
	}
	return stderrB, stderrTotal, softSuggestions
}

func guidanceForPolicyDenied(req types.ExecRequest, pre policy.Decision, preEv types.Event, approvalErr error) *types.ExecGuidance {
	g := &types.ExecGuidance{
		Status:    "blocked",
		Blocked:   true,
		Retryable: pre.PolicyDecision == types.DecisionApprove,
		Reason:    "command denied by policy",
		PolicyRule: func() string {
			if pre.Rule != "" {
				return pre.Rule
			}
			if preEv.Policy != nil {
				return preEv.Policy.Rule
			}
			return ""
		}(),
		BlockedOperation: preEv.Operation,
		BlockedTarget:    req.Command,
	}

	if approvalErr != nil && strings.Contains(strings.ToLower(approvalErr.Error()), "timeout") {
		g.Reason = "approval timed out"
		g.Retryable = true
	}
	if pre.PolicyDecision == types.DecisionApprove {
		g.Suggestions = append(g.Suggestions, types.Suggestion{
			Action: "request_approval",
			Reason: "operation requires approval per policy (enable approvals or approve via API)",
		})
	} else {
		g.Suggestions = append(g.Suggestions, types.Suggestion{
			Action: "adjust_policy",
			Reason: "operation denied by policy; adjust policy or change command",
		})
	}
	return g
}

func guidanceForResponse(req types.ExecRequest, res types.ExecResult, blockedOps []types.Event) *types.ExecGuidance {
	g := &types.ExecGuidance{}

	if len(blockedOps) > 0 {
		ev := blockedOps[0]
		rule := ""
		dec := ""
		decEff := ""
		approvalMode := ""
		if ev.Policy != nil {
			rule = ev.Policy.Rule
			dec = string(ev.Policy.Decision)
			decEff = string(ev.Policy.EffectiveDecision)
			if ev.Policy.Approval != nil {
				approvalMode = string(ev.Policy.Approval.Mode)
			}
		}
		target := ev.Path
		if target == "" {
			if ev.Remote != "" {
				target = ev.Remote
			} else if ev.Domain != "" {
				target = ev.Domain
			} else {
				target = ev.Type
			}
		}
		g.Status = "blocked"
		g.Blocked = true
		g.PolicyRule = rule
		g.BlockedOperation = ev.Operation
		if g.BlockedOperation == "" {
			g.BlockedOperation = ev.Type
		}
		g.BlockedTarget = target
		if rule != "" {
			g.Reason = fmt.Sprintf("blocked by policy (rule=%s)", rule)
		} else if dec != "" {
			g.Reason = fmt.Sprintf("blocked by policy (decision=%s)", dec)
		} else {
			g.Reason = "blocked by policy"
		}

		// If the policy decision was "approve", this is usually retryable via approvals.
		if strings.EqualFold(dec, string(types.DecisionApprove)) || strings.HasPrefix(strings.ToLower(rule), "approve-") {
			g.Retryable = true
			g.Suggestions = append(g.Suggestions, types.Suggestion{
				Action: "request_approval",
				Reason: "operation requires approval per policy",
			})
			if approvalMode != "" {
				g.Suggestions = append(g.Suggestions, types.Suggestion{
					Action: "enable_approvals",
					Reason: fmt.Sprintf("approvals are in %s mode; enable or respond to approvals to proceed", approvalMode),
				})
			}
		}

		// Heuristics: provide substitutions for common tooling.
		base := strings.ToLower(filepath.Base(req.Command))
		if base == "curl" {
			urlArg := ""
			for _, a := range req.Args {
				if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
					urlArg = a
					break
				}
			}
			if urlArg != "" {
				g.Substitutions = append(g.Substitutions, types.Suggestion{
					Action:  "substitute",
					Command: fmt.Sprintf("wget -qO- %s", urlArg),
					Reason:  "try an alternative downloader",
				})
				if strings.HasPrefix(urlArg, "http://") {
					g.Substitutions = append(g.Substitutions, types.Suggestion{
						Action:  "substitute",
						Command: fmt.Sprintf("curl -sS %s", strings.Replace(urlArg, "http://", "https://", 1)),
						Reason:  "HTTPS may be allowed where HTTP is denied",
					})
				}
			}
		}
		if strings.HasPrefix(target, "http://") && (strings.Contains(rule, "deny") || strings.Contains(rule, "default-deny")) {
			g.Substitutions = append(g.Substitutions, types.Suggestion{
				Action:  "substitute",
				Command: strings.Replace(target, "http://", "https://", 1),
				Reason:  "try HTTPS instead of HTTP",
			})
		}
		// Common pattern: unknown HTTP (port 80) blocked by default deny.
		if strings.HasSuffix(target, ":80") && rule == "default-deny-network" {
			g.Substitutions = append(g.Substitutions, types.Suggestion{
				Action:  "substitute",
				Command: "https://" + strings.TrimSuffix(target, ":80"),
				Reason:  "try HTTPS (port 443) instead of HTTP (port 80)",
			})
		}

		// File policy recourse.
		if strings.HasPrefix(ev.Type, "file_") || strings.HasPrefix(ev.Type, "dir_") || strings.HasPrefix(ev.Type, "symlink_") {
			if ev.Path != "" && !strings.HasPrefix(ev.Path, "/workspace") {
				g.Suggestions = append(g.Suggestions, types.Suggestion{
					Action: "move_to_workspace",
					Reason: "copy/move required inputs under /workspace so the policy can allow access",
				})
			}
		}

		// Generic remediation.
		g.Suggestions = append(g.Suggestions, types.Suggestion{
			Action: "inspect_events",
			Reason: "query the event log for full details (rule, operation, and target)",
		})
		g.Suggestions = append(g.Suggestions, types.Suggestion{
			Action: "adjust_policy",
			Reason: "allow the required operation (or enable approvals where appropriate)",
		})
		if !g.Retryable {
			g.Retryable = len(g.Substitutions) > 0 || strings.HasPrefix(strings.ToLower(rule), "approve-") || strings.EqualFold(decEff, string(types.DecisionApprove))
		}
		return g
	}

	if res.ExitCode == 0 {
		g.Status = "ok"
		return g
	}
	g.Status = "failed"
	g.Blocked = false
	g.Reason = "command failed"

	// Failure heuristics for better recourse.
	msg := ""
	if res.Error != nil {
		msg = strings.ToLower(res.Error.Message)
	}
	if strings.Contains(msg, "timed out") || strings.Contains(msg, "deadline exceeded") {
		g.Retryable = true
		g.Reason = "command timed out"
		g.Suggestions = append(g.Suggestions, types.Suggestion{
			Action:  "increase_timeout",
			Command: "agentsh exec --timeout 2m ...",
			Reason:  "increase --timeout for slow commands",
		})
	}
	if strings.Contains(msg, "executable file not found") || strings.Contains(msg, "no such file or directory") {
		g.Suggestions = append(g.Suggestions, types.Suggestion{
			Action: "use_absolute_exe",
			Reason: "use an absolute executable path (or install the missing tool if allowed)",
		})
	}
	if strings.Contains(msg, "permission denied") {
		g.Suggestions = append(g.Suggestions, types.Suggestion{
			Action: "fix_permissions",
			Reason: "ensure the executable is allowed and has execute permission",
		})
		base := strings.ToLower(filepath.Base(req.Command))
		if base == "python" || base == "python3" {
			if strings.Contains(msg, ".pyenv/shims/") || strings.Contains(msg, "asdf/shims/") {
				g.Substitutions = append(g.Substitutions, types.Suggestion{
					Action:  "substitute",
					Command: "/usr/bin/python3",
					Reason:  "avoid user-managed shims that may be blocked by policy",
				})
			}
		}
	}
	return g
}

// applyCommandRedirect mutates the command/args if the policy requested a redirect.
// It returns whether a redirect was applied along with the original command/args.
func applyCommandRedirect(command *string, args *[]string, pre policy.Decision) (redirected bool, originalCmd string, originalArgs []string) {
	originalCmd = *command
	originalArgs = append([]string{}, (*args)...)

	if pre.PolicyDecision == types.DecisionRedirect && pre.Redirect != nil && strings.TrimSpace(pre.Redirect.Command) != "" {
		*command = pre.Redirect.Command
		*args = append([]string{}, pre.Redirect.Args...)
		return true, originalCmd, originalArgs
	}
	return false, originalCmd, originalArgs
}

// addRedirectGuidance ensures the response carries a substitution hint when a redirect occurred.
func addRedirectGuidance(resp *types.ExecResponse, pre policy.Decision, originalCmd string, originalArgs []string) {
	if resp == nil || pre.PolicyDecision != types.DecisionRedirect || pre.Redirect == nil {
		return
	}
	if resp.Guidance == nil {
		resp.Guidance = &types.ExecGuidance{Status: "ok"}
	}
	cmdStr := pre.Redirect.Command
	if len(pre.Redirect.Args) > 0 {
		cmdStr = fmt.Sprintf("%s %s", pre.Redirect.Command, strings.Join(pre.Redirect.Args, " "))
	}
	reason := pre.Message
	if reason == "" && resp.Guidance.Reason != "" {
		reason = resp.Guidance.Reason
	}
	resp.Guidance.Substitutions = append([]types.Suggestion{{
		Action:  "redirected",
		Command: cmdStr,
		Reason:  reason,
	}}, resp.Guidance.Substitutions...)
	if resp.Guidance.PolicyRule == "" {
		resp.Guidance.PolicyRule = pre.Rule
	}
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
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
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

// policyTest evaluates a hypothetical operation against the policy engine.
func (a *App) policyTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Operation string `json:"operation"`
		Path      string `json:"path"`
	}
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}

	if req.Operation == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "operation is required"})
		return
	}
	if req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "path is required"})
		return
	}

	// Use session's policy if session_id provided, otherwise use default
	// Note: Currently all sessions use the same policy engine from the app
	engine := a.policy

	if engine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "policy engine not available"})
		return
	}

	var decision policy.Decision
	op := strings.ToLower(req.Operation)

	switch {
	case strings.HasPrefix(op, "file_") || op == "read" || op == "write" || op == "delete" || op == "create":
		// Map common operation names
		opName := op
		if strings.HasPrefix(op, "file_") {
			opName = strings.TrimPrefix(op, "file_")
		}
		decision = engine.CheckFile(req.Path, opName)

	case strings.HasPrefix(op, "net_") || op == "connect":
		// Parse host:port from path
		host, portStr, err := net.SplitHostPort(req.Path)
		if err != nil {
			host = req.Path
			portStr = "443" // default to HTTPS
		}
		port := 443
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
		decision = engine.CheckNetwork(host, port)

	case op == "exec" || op == "command":
		// Path is the command, no args for testing
		decision = engine.CheckCommand(req.Path, nil)

	default:
		// Try as file operation by default
		decision = engine.CheckFile(req.Path, op)
	}

	result := map[string]any{
		"decision":           string(decision.EffectiveDecision),
		"policy_decision":    string(decision.PolicyDecision),
		"rule":               decision.Rule,
		"reason":             decision.Message,
	}

	if decision.Redirect != nil {
		result["redirect"] = map[string]any{
			"command": decision.Redirect.Command,
			"args":    decision.Redirect.Args,
		}
	}

	writeJSON(w, http.StatusOK, result)
}
