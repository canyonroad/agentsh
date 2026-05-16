package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/landlock"
	"github.com/agentsh/agentsh/internal/policy"
	seccomppkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

var (
	wrapChown                     = os.Chown
	wrapChmod                     = os.Chmod
	startNotifyHandlerForWrapHook = startNotifyHandlerForWrap
	wrapCgroupSetupForNotifyHook  = defaultWrapCgroupSetupForNotify
)

type wrapNotifyMetadata struct {
	WrapperPID int
}

// wrapInit handles POST /api/v1/sessions/{id}/wrap-init.
// It returns the seccomp wrapper configuration for the CLI to launch the agent
// through the wrapper, and starts listening for the notify fd on a Unix socket.
func (a *App) wrapInit(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(sessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	var req types.WrapInitRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}

	resp, code, err := a.wrapInitCore(s, sessionID, req)
	if err != nil {
		writeJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, code, resp)
}

func secureNotifyDir(dir string, callerUID int) bool {
	// callerUID == 0 is the sentinel fallback path.
	if callerUID > 0 {
		if err := wrapChown(dir, callerUID, -1); err == nil {
			if err := wrapChmod(dir, 0700); err != nil {
				slog.Debug("wrap: failed to chmod notify dir", "dir", dir, "mode", "0700", "error", err)
				if err := wrapChmod(dir, 0711); err != nil {
					slog.Debug("wrap: failed to chmod notify dir", "dir", dir, "mode", "0711", "error", err)
				}
				return false
			}
			return true
		} else {
			slog.Debug("wrap: failed to chown notify dir", "dir", dir, "caller_uid", callerUID, "error", err)
			if err := wrapChmod(dir, 0711); err != nil {
				slog.Debug("wrap: failed to chmod notify dir", "dir", dir, "mode", "0711", "error", err)
			}
			return false
		}
	}
	if err := wrapChmod(dir, 0711); err != nil {
		slog.Debug("wrap: failed to chmod notify dir", "dir", dir, "mode", "0711", "error", err)
	}
	return false
}

func secureSocket(socketPath string, callerUID int, chownOK bool) {
	if chownOK && callerUID > 0 {
		if err := wrapChown(socketPath, callerUID, -1); err == nil {
			if err := wrapChmod(socketPath, 0600); err != nil {
				slog.Debug("wrap: failed to chmod socket", "socket_path", socketPath, "mode", "0600", "error", err)
			}
			return
		} else {
			slog.Debug("wrap: failed to chown socket", "socket_path", socketPath, "caller_uid", callerUID, "error", err)
		}
	}
	if err := wrapChmod(socketPath, 0666); err != nil {
		slog.Debug("wrap: failed to chmod socket", "socket_path", socketPath, "mode", "0666", "error", err)
	}
}

func validatePermissionMode(path string, want os.FileMode, kind string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	got := info.Mode().Perm()
	if got != want {
		return fmt.Errorf("wrap: %s permissions not established for %s: got %04o want %04o", kind, path, got, want)
	}
	return nil
}

// wrapInitCore contains the core logic for wrap initialization.
// Uses context.Background() (not the HTTP request context) so that
// the notify handler stays active after the HTTP response is sent.
func (a *App) wrapInitCore(s *session.Session, sessionID string, req types.WrapInitRequest) (types.WrapInitResponse, int, error) {
	// Use a background context so the notify handler outlives the HTTP request.
	// The handler will be cleaned up when the session ends or the connection closes.
	ctx := context.Background()

	// Shim mode: pre-check the agent command against policy before issuing
	// the wrapper. The shim's kernel-install path replaces the existing
	// `agentsh exec` flow with `wrap-init` + direct wrapper exec, which
	// bypasses the Exec endpoint's CheckCommand pre-check that surfaces
	// `command denied by policy` to the user. Without this guard, a denied
	// command (e.g. `sh -c "shutdown now"`) routes around policy entirely:
	// the shim invokes the wrapper, the wrapped shell spawns shutdown, and
	// in-kernel enforcement may or may not catch it depending on whether
	// it has the necessary privileges in the runtime environment.
	//
	// We accept only effective decisions that the wrapper path can faithfully
	// execute end-to-end: allow (proceed) and audit (allow + logging, which
	// the wrapped session's audit pipeline still emits). Any restrictive
	// non-allow decision (deny, approve, redirect, soft_delete) requires
	// semantics the shim wrap path does NOT implement — approval gating,
	// command rewriting, redirect target validation. For those we return
	// 403 so the shim's ModeAuto branch falls through to the existing
	// `agentsh exec` path, which has full pre-exec policy semantics
	// (approval prompt, redirect rewrite, deny + user-visible message).
	// ModeOn still fail-closes via the same path.
	//
	// Agent mode (`agentsh wrap`) intentionally retains pre-existing
	// behavior — it is invoked by an operator with explicit intent and
	// has its own integration with policy elsewhere.
	if req.Mode == "shim" {
		engine := a.policyEngineFor(s)
		if engine == nil {
			// No policy engine configured for this session AND no global
			// engine on the App — fail closed rather than letting the
			// kernel-install path run without any policy gate. In
			// production the App is always constructed with a global
			// engine; reaching this branch means a misconfiguration.
			return types.WrapInitResponse{}, http.StatusServiceUnavailable,
				fmt.Errorf("shim wrap-init: no policy engine available for session")
		}
		dec := engine.CheckCommand(req.AgentCommand, req.AgentArgs)
		// We must check BOTH the underlying PolicyDecision and the
		// EffectiveDecision. Some decisions resolve to effective-allow
		// even though they carry semantics the shim path does not
		// implement:
		//
		//   - soft_delete: PolicyDecision=soft_delete, Effective=allow.
		//     The wrapper would not redirect rm to trash; we must defer
		//     to agentsh-exec which performs the rewrite.
		//   - approve with enforce_approvals=false (monitor mode):
		//     PolicyDecision=approve, Effective=allow. Same reasoning.
		//   - redirect with enforce_redirects=false: PolicyDecision=
		//     redirect, Effective=allow. Same.
		//
		// So gate on PolicyDecision being one of {allow, audit}. Audit
		// is "allow + enhanced logging" with no rewrite, so it's safe
		// to issue a wrapper — the wrapped session's audit pipeline
		// still emits events.
		pol := dec.PolicyDecision
		if pol != types.DecisionAllow && pol != types.DecisionAudit {
			return types.WrapInitResponse{}, http.StatusForbidden,
				fmt.Errorf("command requires non-shim handling by policy (rule=%s, decision=%s)", dec.Rule, pol)
		}
	}

	// Windows uses driver-based interception, not seccomp
	if runtime.GOOS == "windows" {
		return a.wrapInitWindows(ctx, s, sessionID, req)
	}

	// Only supported on Linux (seccomp) otherwise
	if runtime.GOOS != "linux" {
		return types.WrapInitResponse{}, http.StatusBadRequest, errWrapNotSupported
	}

	if req.CallerUID < 0 {
		return types.WrapInitResponse{}, http.StatusBadRequest, fmt.Errorf("invalid caller uid: %d", req.CallerUID)
	}

	// Ptrace mode: skip seccomp wrapper entirely. Create a socket for PID handshake.
	if a.ptraceTracer != nil {
		if a.ptraceFailed.Load() {
			return types.WrapInitResponse{}, http.StatusServiceUnavailable,
				fmt.Errorf("ptrace tracer is not healthy; refusing wrap-init")
		}
		notifyDir, err := os.MkdirTemp("", "agentsh-wrap-*")
		if err != nil {
			return types.WrapInitResponse{}, http.StatusInternalServerError, err
		}
		chownOK := secureNotifyDir(notifyDir, req.CallerUID)
		// Apply same path-budget + hash truncation as seccomp wrap path
		safeID := filepath.Base(sessionID)
		const socketPathLimit = 104
		prefix := "ptrace-"
		suffix := ".sock"
		budget := socketPathLimit - len(notifyDir) - 1 - len(prefix) - len(suffix)
		if budget < 1 {
			os.RemoveAll(notifyDir)
			return types.WrapInitResponse{}, http.StatusInternalServerError,
				fmt.Errorf("temp directory path too long for Unix socket (%d bytes remaining)", budget)
		}
		if len(safeID) > budget {
			h := sha256.Sum256([]byte(safeID))
			hashStr := hex.EncodeToString(h[:])
			if budget > len(hashStr) {
				budget = len(hashStr)
			}
			safeID = hashStr[:budget]
		}
		notifySocketPath := filepath.Join(notifyDir, prefix+safeID+suffix)

		listener, err := net.Listen("unix", notifySocketPath)
		if err != nil {
			os.RemoveAll(notifyDir)
			return types.WrapInitResponse{}, http.StatusInternalServerError, err
		}
		secureSocket(notifySocketPath, req.CallerUID, chownOK)
		if err := validatePermissionMode(notifyDir, func() os.FileMode {
			if chownOK {
				return 0700
			}
			return 0711
		}(), "notify directory"); err != nil {
			_ = listener.Close()
			os.RemoveAll(notifyDir)
			return types.WrapInitResponse{}, http.StatusInternalServerError, err
		}
		if err := validatePermissionMode(notifySocketPath, func() os.FileMode {
			if chownOK {
				return 0600
			}
			return 0666
		}(), "notify socket"); err != nil {
			_ = listener.Close()
			os.RemoveAll(notifyDir)
			return types.WrapInitResponse{}, http.StatusInternalServerError, err
		}

		go a.acceptPtracePID(ctx, listener, notifySocketPath, sessionID, req.CallerUID)

		ev := types.Event{
			ID:        uuid.NewString(),
			Timestamp: time.Now().UTC(),
			Type:      "wrap_init",
			SessionID: sessionID,
			Fields: map[string]any{
				"ptrace_mode":   true,
				"agent_command": req.AgentCommand,
				"agent_args":    req.AgentArgs,
				"notify_socket": notifySocketPath,
			},
		}
		_ = a.store.AppendEvent(ctx, ev)
		a.broker.Publish(ev)

		return types.WrapInitResponse{
			PtraceMode:            true,
			SafeToBypassShellShim: true,
			NotifySocket:          notifySocketPath,
		}, http.StatusOK, nil
	}

	// Resolve wrapper binary
	wrapperBin := strings.TrimSpace(a.cfg.Sandbox.UnixSockets.WrapperBin)
	if wrapperBin == "" {
		wrapperBin = "agentsh-unixwrap"
	}

	// Resolve to absolute path
	wrapperPath, err := exec.LookPath(wrapperBin)
	if err != nil {
		return types.WrapInitResponse{}, http.StatusServiceUnavailable, errWrapperNotFound
	}

	// Resolve stub binary (optional, for redirect support)
	stubBin := "agentsh-stub"
	stubPath, _ := exec.LookPath(stubBin)

	execveEnabled := a.cfg.Sandbox.Seccomp.Execve.Enabled

	// Create a private temp directory for the notify socket to prevent
	// other local users from connecting first (security: socket path injection).
	// Sanitize session ID to a safe basename to prevent path traversal.
	safeID := filepath.Base(sessionID)
	notifyDir, err := os.MkdirTemp("", "agentsh-wrap-*")
	if err != nil {
		return types.WrapInitResponse{}, http.StatusInternalServerError, err
	}
	chownOK := secureNotifyDir(notifyDir, req.CallerUID)
	if err := validatePermissionMode(notifyDir, func() os.FileMode {
		if chownOK {
			return 0700
		}
		return 0711
	}(), "notify directory"); err != nil {
		os.RemoveAll(notifyDir)
		return types.WrapInitResponse{}, http.StatusInternalServerError, err
	}
	// Unix socket paths are limited to 104 bytes (macOS) or 108 (Linux).
	// Compute remaining budget for the session ID portion and hash if needed.
	const socketPathLimit = 104 // use the most restrictive (macOS)
	const fixedParts = len("/notify-") + len(".sock")
	budget := socketPathLimit - len(notifyDir) - fixedParts
	if budget < 1 {
		os.RemoveAll(notifyDir)
		return types.WrapInitResponse{}, http.StatusInternalServerError,
			fmt.Errorf("temp directory path too long for Unix socket (%d bytes remaining)", budget)
	}
	if len(safeID) > budget {
		h := sha256.Sum256([]byte(safeID))
		hashStr := hex.EncodeToString(h[:]) // 64 chars
		if budget > len(hashStr) {
			budget = len(hashStr)
		}
		safeID = hashStr[:budget]
	}
	notifySocketPath := filepath.Join(notifyDir, "notify-"+safeID+".sock")

	listener, err := net.Listen("unix", notifySocketPath)
	if err != nil {
		os.RemoveAll(notifyDir)
		return types.WrapInitResponse{}, http.StatusInternalServerError, err
	}
	secureSocket(notifySocketPath, req.CallerUID, chownOK)
	if err := validatePermissionMode(notifySocketPath, func() os.FileMode {
		if chownOK {
			return 0600
		}
		return 0666
	}(), "notify socket"); err != nil {
		_ = listener.Close()
		os.RemoveAll(notifyDir)
		return types.WrapInitResponse{}, http.StatusInternalServerError, err
	}

	// Start background goroutine to accept the notify fd connection.
	// In shim mode (Mode=="shim") the goroutine exits after a single accept
	// so per-invocation resources are reclaimed. In agent mode (default) the
	// function already exits naturally after one accept, so shimMode is
	// plumbed for clarity and future-proofing but changes no behavior today.
	shimMode := req.Mode == "shim"
	startListener := func() {
		a.acceptNotifyFD(ctx, listener, notifySocketPath, sessionID, s, execveEnabled, req.CallerUID, shimMode)
	}
	if a.acceptNotifyFDForTest != nil {
		a.acceptNotifyFDForTest(startListener)
	} else {
		go startListener()
	}

	// Create signal filter socket if signal filtering is enabled.
	// This must happen before marshaling the seccomp config so that
	// signal_filter_enabled accurately reflects whether the socket was created.
	// NOTE: Signal filter is disabled when execve interception is enabled because
	// stacking two seccomp USER_NOTIF filters causes notification delivery failures
	// (the signal filter's semaphore interferes with execve notification reception).
	var signalSocketPath string
	// signalFilterEnabled routes through a helper so the gate can be
	// exercised in tests end-to-end without standing up seccomp (see
	// TestWrap_SignalFilterUsesSessionPolicy).
	signalFilterEnabled := a.signalFilterEnabled(s, execveEnabled)
	if signalFilterEnabled {
		signalSocketPath = filepath.Join(notifyDir, "signal-"+safeID+".sock")
		signalListener, err := net.Listen("unix", signalSocketPath)
		if err != nil {
			slog.Warn("wrap: failed to create signal socket, disabling signal filter",
				"error", err, "session_id", sessionID)
			signalSocketPath = ""
			signalFilterEnabled = false
		} else {
			secureSocket(signalSocketPath, req.CallerUID, chownOK)
			if err := validatePermissionMode(signalSocketPath, func() os.FileMode {
				if chownOK {
					return 0600
				}
				return 0666
			}(), "signal socket"); err != nil {
				_ = signalListener.Close()
				_ = listener.Close()
				os.RemoveAll(notifyDir)
				return types.WrapInitResponse{}, http.StatusInternalServerError, err
			}
			go a.acceptSignalFD(ctx, signalListener, signalSocketPath, sessionID, s, req.CallerUID)
		}
	}

	unixSocketEnabled := a.cfg.Sandbox.Seccomp.UnixSocket.Enabled
	if a.cfg.Sandbox.UnixSockets.Enabled != nil && *a.cfg.Sandbox.UnixSockets.Enabled {
		unixSocketEnabled = true
	}

	seccompCfg := a.buildSeccompWrapperConfig(s, seccompWrapperParams{
		UnixSocketEnabled:   unixSocketEnabled,
		SignalFilterEnabled: signalFilterEnabled,
		ExecveEnabled:       execveEnabled,
	})

	// Ensure the parent directory of the about-to-be-execed command is
	// in AllowExecute. Without this, any Landlock-enabled session
	// blocks the wrap path from invoking shells whose path is not
	// already covered by a policy command rule with a slash. The
	// shim's renamed real shells (/bin/bash.real, /bin/sh.real) are
	// the canonical case (#283 on Tensorlake): typical policies use
	// bare names (`commands: [bash, sh]`), so
	// DeriveExecutePathsFromPolicy adds nothing for them, and Landlock
	// denies execve of /bin/bash.real with EACCES.
	//
	// Bare-name AgentCommand values (no slash) are skipped — there is
	// no parent directory to add, and resolving via PATH at exec time
	// is the wrapper's responsibility. We also guard against the "/"
	// and "." dirs that would broaden the allow list to root or cwd.
	if seccompCfg.LandlockEnabled && strings.ContainsRune(req.AgentCommand, '/') {
		dir := filepath.Dir(req.AgentCommand)
		if dir != "" && dir != "." && dir != "/" && !containsString(seccompCfg.AllowExecute, dir) {
			seccompCfg.AllowExecute = append(seccompCfg.AllowExecute, dir)
		}
	}

	cfgJSON, err := json.Marshal(seccompCfg)
	if err != nil {
		return types.WrapInitResponse{}, http.StatusInternalServerError, err
	}

	// Build wrapper env
	wrapperEnv := map[string]string{
		"AGENTSH_SECCOMP_CONFIG": string(cfgJSON),
	}
	if signalSocketPath != "" {
		wrapperEnv["AGENTSH_SIGNAL_SOCK_FD"] = "4" // fd 4 = ExtraFiles[1]
	}

	// Emit wrap_init event
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "wrap_init",
		SessionID: sessionID,
		Fields: map[string]any{
			"wrapper_binary": wrapperPath,
			"agent_command":  req.AgentCommand,
			"agent_args":     req.AgentArgs,
			"notify_socket":  notifySocketPath,
		},
	}
	_ = a.store.AppendEvent(ctx, ev)
	a.broker.Publish(ev)

	return types.WrapInitResponse{
		SafeToBypassShellShim: execveEnabled,
		WrapperBinary:         wrapperPath,
		StubBinary:            stubPath,
		SeccompConfig:         string(cfgJSON),
		NotifySocket:          notifySocketPath,
		SignalSocket:          signalSocketPath,
		WrapperEnv:            wrapperEnv,
	}, http.StatusOK, nil
}

// deriveLandlockAllowPaths returns the execute/read/write allow-path lists
// that wrap-init should hand to the Landlock ruleset for this session. It
// reads from the session's effective policy engine (per-session engine if
// set, otherwise the global engine) so that per-session allow_* rules are
// reflected in the Landlock configuration applied to wrapped agents.
//
// Returns three nil slices when no engine is available (test configs).
// nil slices are safe to append() to, so callers can unconditionally tack
// on config-derived paths afterwards.
//
// This helper is the regression boundary for canyonroad/agentsh#191: it
// was extracted from wrapInitCore specifically so the derivation path can
// be tested end-to-end without standing up seccomp. See
// TestWrap_LandlockDerivationUsesSessionPolicy.
func (a *App) deriveLandlockAllowPaths(s *session.Session) (execute, read, write []string) {
	engine := a.policyEngineFor(s)
	if engine == nil {
		return nil, nil, nil
	}
	pol := engine.Policy()
	execute = landlock.DeriveExecutePathsFromPolicy(pol)
	execute = append(execute, landlock.DeriveExecutePathsFromFileRules(pol)...)
	read = landlock.DeriveReadPathsFromPolicy(pol)
	write = landlock.DeriveWritePathsFromPolicy(pol)
	return execute, read, write
}

// signalFilterEnabled reports whether wrap-init should create a signal
// filter socket for this session. It consults the session's effective
// policy engine (per-session engine if set, otherwise the global engine)
// so per-session signal rules are honored — reading a.policy directly
// silently ignores non-default policy files (canyonroad/agentsh#191).
//
// Signal filtering is disabled whenever the main seccomp filter already
// uses SECCOMP_RET_USER_NOTIF (for execve interception, unix socket
// monitoring, file monitoring, or metadata interception). Stacking two
// USER_NOTIF filters on the same thread causes notification delivery
// failures that break the agent: on Alpine/musl we observed libreadline
// EBADF loops because the signal filter's listener interferes with the
// main filter's openat notifications. See
// TestAlpineEnvInject_BashBuiltinDisabled for the reproducer.
//
// This helper is the regression boundary for #191's signal-filter half:
// it was extracted from wrapInitCore specifically so the gate can be
// tested end-to-end without standing up seccomp. See
// TestWrap_SignalFilterUsesSessionPolicy.
func (a *App) signalFilterEnabled(s *session.Session, execveEnabled bool) bool {
	if a.mainFilterUsesUserNotify(execveEnabled) {
		return false
	}
	engine := a.policyEngineFor(s)
	if engine == nil {
		return false
	}
	return engine.SignalEngine() != nil
}

// mainFilterUsesUserNotify reports whether the main seccomp filter
// installed by agentsh-unixwrap will use SECCOMP_RET_USER_NOTIF for any
// reason. This mirrors the feature gates in
// unixmon.InstallFilterWithConfig: each of these flags causes the
// wrapper to register ActNotify rules in the main filter. Callers use
// this to avoid stacking a second USER_NOTIF filter (the signal filter)
// on top of one that is already in use, which breaks notification
// delivery on real workloads.
//
// execveEnabled is passed in rather than read from a.cfg because core.go
// overrides it to false in hybrid-ptrace mode — the wrapper will not
// install execve notify rules in that case.
//
// Returns false when a.cfg is nil: tests construct bare Apps without
// a config, and in that case no wrapper-installed filter exists.
func (a *App) mainFilterUsesUserNotify(execveEnabled bool) bool {
	if execveEnabled {
		return true
	}
	if a.cfg == nil {
		return false
	}
	if a.cfg.Sandbox.Seccomp.UnixSocket.Enabled {
		return true
	}
	if config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.Enabled, false) {
		return true
	}
	if config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata, false) {
		return true
	}
	block, onBlock, err := config.EffectiveSyscallBlock(a.cfg.Sandbox.Seccomp)
	if err == nil && blockListUsesNotify(block, onBlock) {
		return true
	}
	if blockedFamiliesUseNotifyForSeccomp(a.cfg.Sandbox.Seccomp) {
		return true
	}
	if seccompSocketRulesUseNotify(a.cfg.Sandbox.Seccomp) {
		return true
	}
	return false
}

// blockListUsesNotify reports whether the block-list action installs
// SECCOMP_RET_USER_NOTIF rules on this arch. Only `log` and
// `log_and_kill` route block-listed syscalls through user-notify;
// `errno` and `kill` are kernel-side actions. The block-list also
// needs at least one syscall name that resolves on the running arch
// — otherwise the wrapper installs zero ActNotify rules and no FD is
// produced, so flipping the gate here would cause ptrace sync to wait
// for an FD/READY that never arrives.
func blockListUsesNotify(block []string, onBlock string) bool {
	if onBlock != "log" && onBlock != "log_and_kill" {
		return false
	}
	return resolvableBlockListCount(block) > 0
}

// containsString returns true when s appears in xs. Used by wrapInitCore
// to dedupe entries appended to AllowExecute (the AgentCommand parent
// dir might already be present from policy or global config — adding it
// twice is harmless but noisier in logs and serialized config).
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// blockedFamiliesUsesNotify reports whether any BlockedSocketFamilies entry
// uses an action that requires the userspace notify handler (log or log_and_kill).
// errno and kill are handled kernel-side and do not require a notify fd.
func blockedFamiliesUsesNotify(families []config.SandboxSeccompSocketFamilyConfig) bool {
	for _, f := range families {
		if f.Action == "log" || f.Action == "log_and_kill" {
			return true
		}
	}
	return false
}

func blockedFamiliesUseNotifyForSeccomp(seccompCfg config.SandboxSeccompConfig) bool {
	families, err := config.ResolveEffectiveBlockedFamilies(seccompCfg)
	if err != nil {
		slog.Warn("seccomp: failed to resolve blocked_socket_families; socket family rules will not use user notify", "error", err)
		return false
	}
	for _, f := range families {
		if f.Action == seccomppkg.OnBlockLog || f.Action == seccomppkg.OnBlockLogAndKill {
			return true
		}
	}
	return false
}

func socketRulesUsesNotify(rules []config.SandboxSeccompSocketRuleConfig) bool {
	return seccompSocketRulesUseNotify(config.SandboxSeccompConfig{SocketRules: rules})
}

func seccompSocketRulesUseNotify(seccompCfg config.SandboxSeccompConfig) bool {
	rules, err := config.ResolveSocketRules(seccompCfg)
	if err != nil {
		slog.Warn("seccomp: failed to resolve socket_rules; socket rules will not use user notify", "error", err)
		return false
	}
	return resolvedSocketRulesUseNotify(rules)
}

func resolvedSocketRulesUseNotify(rules []seccomppkg.SocketRule) bool {
	for _, r := range rules {
		if r.Action == seccomppkg.OnBlockLog || r.Action == seccomppkg.OnBlockLogAndKill {
			return true
		}
	}
	return false
}

// acceptNotifyFD listens on the Unix socket for a single connection from the CLI,
// receives the seccomp notify fd, and starts the notify handler.
//
// shimMode is true when the caller set Mode=="shim" on the WrapInitRequest.
// In both modes the function accepts exactly one valid connection (or exits on
// timeout/error), so shimMode currently changes no runtime behavior — it is
// plumbed for clarity and to make the per-invocation contract explicit in the
// call site.
func (a *App) acceptNotifyFD(ctx context.Context, listener net.Listener, socketPath string, sessionID string, s *session.Session, execveEnabled bool, expectedUID int, shimMode bool) {
	defer listener.Close()
	// Clean up the entire private temp directory containing the socket
	defer os.RemoveAll(filepath.Dir(socketPath))

	// Set a timeout for accepting the connection
	if dl, ok := listener.(*net.UnixListener); ok {
		dl.SetDeadline(time.Now().Add(30 * time.Second))
	}

	var conn net.Conn
	var notifyPeerPID int
	for {
		nextConn, err := listener.Accept()
		if err != nil {
			slog.Debug("wrap: failed to accept notify connection", "session_id", sessionID, "error", err)
			return
		}

		unixConn, ok := nextConn.(*net.UnixConn)
		if !ok {
			_ = nextConn.Close()
			slog.Debug("wrap: connection is not a Unix connection", "session_id", sessionID)
			continue
		}

		// Read the notify-socket peer credentials and enforce the expected UID.
		creds := getConnPeerCreds(unixConn)
		notifyPeerPID = creds.PID
		if notifyPeerPID > 0 {
			slog.Debug("wrap: got notify-socket peer credentials",
				"peer_pid", notifyPeerPID, "peer_uid", creds.UID, "session_id", sessionID)
		}
		if expectedUID < 0 {
			_ = nextConn.Close()
			slog.Warn("wrap: rejecting notify connection with invalid caller UID",
				"expected_uid", expectedUID, "session_id", sessionID)
			return
		}
		if expectedUID > 0 && creds.UID != uint32(expectedUID) {
			_ = nextConn.Close()
			slog.Warn("wrap: rejecting notify connection from unexpected UID",
				"peer_uid", creds.UID, "expected_uid", expectedUID, "session_id", sessionID)
			continue
		}

		conn = nextConn
		break
	}
	defer conn.Close()

	unixConn := conn.(*net.UnixConn)

	notifyFD, meta, hasMeta, err := recvNotifyFDForWrap(unixConn)
	if err != nil {
		slog.Debug("wrap: failed to receive notify fd", "session_id", sessionID, "error", err)
		if statusErr := writeNotifyStatusForWrap(unixConn, false); statusErr != nil {
			slog.Debug("wrap: failed to write notify setup rejection", "session_id", sessionID, "error", statusErr)
		}
		return
	}
	if notifyFD == nil {
		slog.Debug("wrap: received nil notify fd", "session_id", sessionID)
		if statusErr := writeNotifyStatusForWrap(unixConn, false); statusErr != nil {
			slog.Debug("wrap: failed to write notify setup rejection", "session_id", sessionID, "error", statusErr)
		}
		return
	}

	wrapperPID := notifyPeerPID
	if hasMeta && meta.WrapperPID > 0 {
		wrapperPID = meta.WrapperPID
	}

	var cleanup func() error
	if wrapNeedsCgroupBeforeAck(a, s) {
		if !hasMeta || meta.WrapperPID <= 0 {
			_ = notifyFD.Close()
			if statusErr := writeNotifyStatusForWrap(unixConn, false); statusErr != nil {
				slog.Debug("wrap: failed to write notify setup rejection", "session_id", sessionID, "error", statusErr)
			}
			slog.Warn("wrap: rejecting notify fd without wrapper pid metadata", "session_id", sessionID)
			return
		}
		cgroupCleanup, err := wrapCgroupSetupForNotifyHook(ctx, a, s, sessionID, wrapperPID)
		if err != nil {
			_ = notifyFD.Close()
			if statusErr := writeNotifyStatusForWrap(unixConn, false); statusErr != nil {
				slog.Debug("wrap: failed to write notify setup rejection", "session_id", sessionID, "error", statusErr)
			}
			slog.Warn("wrap: cgroup setup before ack failed", "session_id", sessionID, "wrapper_pid", wrapperPID, "error", err)
			return
		}
		cleanup = cgroupCleanup
	}

	slog.Info("wrap: received notify fd", "session_id", sessionID, "fd", notifyFD.Fd(), "wrapper_pid", wrapperPID)

	// Start the notify handler using existing infrastructure
	startNotifyHandlerForWrapHook(ctx, notifyFD, sessionID, a, execveEnabled, wrapperPID, s, cleanup)
	if err := writeNotifyStatusForWrap(unixConn, true); err != nil {
		slog.Debug("wrap: failed to write notify setup status", "session_id", sessionID, "error", err)
	}
}

func wrapNeedsCgroupBeforeAck(a *App, s *session.Session) bool {
	if a == nil || a.cfg == nil {
		return false
	}
	if a.cfg.Sandbox.Network.EBPF.Required {
		return true
	}
	if !a.cfg.Sandbox.Cgroups.Enabled {
		return false
	}
	if a.cfg.Sandbox.Network.EBPF.Enabled || a.cfg.Sandbox.Network.EBPF.Enforce {
		return true
	}
	engine := a.policyEngineFor(s)
	if engine == nil {
		return false
	}
	lim := engine.Limits()
	return lim.MaxMemoryMB > 0 || lim.CPUQuotaPercent > 0 || lim.PidsMax > 0
}

func defaultWrapCgroupSetupForNotify(ctx context.Context, a *App, s *session.Session, sessionID string, wrapperPID int) (func() error, error) {
	if !wrapNeedsCgroupBeforeAck(a, s) {
		return nil, nil
	}
	if wrapperPID <= 0 {
		return nil, fmt.Errorf("wrap cgroup setup requires wrapper pid")
	}
	if a.cfg.Sandbox.Network.EBPF.Required && !a.cfg.Sandbox.Cgroups.Enabled {
		return nil, fmt.Errorf("ebpf required but sandbox.cgroups.enabled=false")
	}
	if !a.cfg.Sandbox.Cgroups.Enabled {
		return nil, nil
	}

	engine := a.policyEngineFor(s)
	lim := policy.Limits{}
	if engine != nil {
		lim = engine.Limits()
	}
	cmdID := "wrap-" + uuid.NewString()
	em := storeEmitter{store: a.store, broker: a.broker}
	return applyCgroupV2(ctx, em, a, sessionID, cmdID, wrapperPID, lim, a.metrics, engine)
}

// acceptSignalFD listens on the Unix socket for a single connection from the CLI,
// receives the signal filter notify fd, and starts the signal handler.
func (a *App) acceptSignalFD(ctx context.Context, listener net.Listener, socketPath string, sessionID string, s *session.Session, expectedUID int) {
	defer listener.Close()
	// Note: do NOT remove the parent directory here — acceptNotifyFD owns that cleanup.

	if dl, ok := listener.(*net.UnixListener); ok {
		dl.SetDeadline(time.Now().Add(30 * time.Second))
	}

	var conn net.Conn
	for {
		nextConn, err := listener.Accept()
		if err != nil {
			slog.Debug("wrap: failed to accept signal connection", "session_id", sessionID, "error", err)
			return
		}

		unixConn, ok := nextConn.(*net.UnixConn)
		if !ok {
			_ = nextConn.Close()
			continue
		}

		creds := getConnPeerCreds(unixConn)
		if expectedUID < 0 {
			_ = nextConn.Close()
			slog.Warn("wrap: rejecting signal connection with invalid caller UID",
				"expected_uid", expectedUID, "session_id", sessionID)
			return
		}
		if expectedUID > 0 && creds.UID != uint32(expectedUID) {
			_ = nextConn.Close()
			slog.Warn("wrap: rejecting signal connection from unexpected UID",
				"peer_uid", creds.UID, "expected_uid", expectedUID, "session_id", sessionID)
			continue
		}

		conn = nextConn
		break
	}
	defer conn.Close()

	unixConn := conn.(*net.UnixConn)

	file, err := unixConn.File()
	if err != nil {
		return
	}

	signalFD, err := recvFDFromConn(file)
	file.Close()
	if err != nil {
		slog.Debug("wrap: failed to receive signal fd", "session_id", sessionID, "error", err)
		return
	}
	if signalFD == nil {
		return
	}

	slog.Info("wrap: received signal fd", "session_id", sessionID, "fd", signalFD.Fd())
	startSignalHandlerForWrap(ctx, signalFD, sessionID, a, s)
}
