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

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/landlock"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

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

// wrapInitCore contains the core logic for wrap initialization.
// Uses context.Background() (not the HTTP request context) so that
// the notify handler stays active after the HTTP response is sent.
func (a *App) wrapInitCore(s *session.Session, sessionID string, req types.WrapInitRequest) (types.WrapInitResponse, int, error) {
	// Use a background context so the notify handler outlives the HTTP request.
	// The handler will be cleaned up when the session ends or the connection closes.
	ctx := context.Background()

	// Windows uses driver-based interception, not seccomp
	if runtime.GOOS == "windows" {
		return a.wrapInitWindows(ctx, s, sessionID, req)
	}

	// Only supported on Linux (seccomp) otherwise
	if runtime.GOOS != "linux" {
		return types.WrapInitResponse{}, http.StatusBadRequest, errWrapNotSupported
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

	// Build seccomp config
	execveEnabled := a.cfg.Sandbox.Seccomp.Execve.Enabled
	seccompCfg := seccompWrapperConfig{
		UnixSocketEnabled: a.cfg.Sandbox.Seccomp.UnixSocket.Enabled,
		BlockedSyscalls:   a.cfg.Sandbox.Seccomp.Syscalls.Block,
		ExecveEnabled:     execveEnabled,
	}

	// Add Landlock config if enabled
	if a.cfg.Landlock.Enabled {
		llResult := capabilities.DetectLandlock()
		if llResult.Available {
			workspace := s.WorkspaceMountPath()
			seccompCfg.LandlockEnabled = true
			seccompCfg.LandlockABI = llResult.ABI
			seccompCfg.Workspace = workspace

			if a.policy != nil {
				seccompCfg.AllowExecute = landlock.DeriveExecutePathsFromPolicy(a.policy.Policy())
				seccompCfg.AllowRead = landlock.DeriveReadPathsFromPolicy(a.policy.Policy())
				seccompCfg.AllowWrite = landlock.DeriveWritePathsFromPolicy(a.policy.Policy())
			}

			seccompCfg.AllowExecute = append(seccompCfg.AllowExecute, a.cfg.Landlock.AllowExecute...)
			seccompCfg.AllowRead = append(seccompCfg.AllowRead, a.cfg.Landlock.AllowRead...)
			seccompCfg.AllowWrite = append(seccompCfg.AllowWrite, a.cfg.Landlock.AllowWrite...)
			seccompCfg.DenyPaths = append(seccompCfg.DenyPaths, a.cfg.Landlock.DenyPaths...)

			// Allow all network by default — agentsh proxy handles network policy.
			seccompCfg.AllowNetwork = true
			seccompCfg.AllowBind = true
		}
	}

	// Check if unix socket monitoring is enabled at all
	unixEnabled := a.cfg.Sandbox.UnixSockets.Enabled != nil && *a.cfg.Sandbox.UnixSockets.Enabled
	if unixEnabled {
		seccompCfg.UnixSocketEnabled = true
	}

	// Create a private temp directory for the notify socket to prevent
	// other local users from connecting first (security: socket path injection).
	// Sanitize session ID to a safe basename to prevent path traversal.
	safeID := filepath.Base(sessionID)
	notifyDir, err := os.MkdirTemp("", "agentsh-wrap-*")
	if err != nil {
		return types.WrapInitResponse{}, http.StatusInternalServerError, err
	}
	if err := os.Chmod(notifyDir, 0700); err != nil {
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

	// Start background goroutine to accept the notify fd connection
	go a.acceptNotifyFD(ctx, listener, notifySocketPath, sessionID, s, execveEnabled)

	// Create signal filter socket if signal filtering is enabled.
	// This must happen before marshaling the seccomp config so that
	// signal_filter_enabled accurately reflects whether the socket was created.
	var signalSocketPath string
	signalFilterEnabled := a.policy != nil && a.policy.SignalEngine() != nil
	if signalFilterEnabled {
		signalSocketPath = filepath.Join(notifyDir, "signal-"+safeID+".sock")
		signalListener, err := net.Listen("unix", signalSocketPath)
		if err != nil {
			slog.Warn("wrap: failed to create signal socket, disabling signal filter",
				"error", err, "session_id", sessionID)
			signalSocketPath = ""
			signalFilterEnabled = false
		} else {
			go a.acceptSignalFD(ctx, signalListener, signalSocketPath, sessionID)
		}
	}
	seccompCfg.SignalFilterEnabled = signalFilterEnabled

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
		WrapperBinary: wrapperPath,
		StubBinary:    stubPath,
		SeccompConfig: string(cfgJSON),
		NotifySocket:  notifySocketPath,
		SignalSocket:  signalSocketPath,
		WrapperEnv:    wrapperEnv,
	}, http.StatusOK, nil
}

// acceptNotifyFD listens on the Unix socket for a single connection from the CLI,
// receives the seccomp notify fd, and starts the notify handler.
func (a *App) acceptNotifyFD(ctx context.Context, listener net.Listener, socketPath string, sessionID string, s *session.Session, execveEnabled bool) {
	defer listener.Close()
	// Clean up the entire private temp directory containing the socket
	defer os.RemoveAll(filepath.Dir(socketPath))

	// Set a timeout for accepting the connection
	if dl, ok := listener.(*net.UnixListener); ok {
		dl.SetDeadline(time.Now().Add(30 * time.Second))
	}

	conn, err := listener.Accept()
	if err != nil {
		slog.Debug("wrap: failed to accept notify connection", "session_id", sessionID, "error", err)
		return
	}
	defer conn.Close()

	// Receive the notify fd from the CLI via SCM_RIGHTS
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		slog.Debug("wrap: connection is not a Unix connection", "session_id", sessionID)
		return
	}

	// Get wrapper PID from socket credentials for depth tracking
	wrapperPID := getConnPeerPID(unixConn)
	if wrapperPID > 0 {
		slog.Debug("wrap: got wrapper PID from socket credentials",
			"wrapper_pid", wrapperPID, "session_id", sessionID)
	}

	file, err := unixConn.File()
	if err != nil {
		slog.Debug("wrap: failed to get file from connection", "session_id", sessionID, "error", err)
		return
	}

	// Use the existing RecvFD infrastructure to receive the notify fd
	notifyFD, err := recvFDFromConn(file)
	file.Close()
	if err != nil {
		slog.Debug("wrap: failed to receive notify fd", "session_id", sessionID, "error", err)
		return
	}
	if notifyFD == nil {
		slog.Debug("wrap: received nil notify fd", "session_id", sessionID)
		return
	}

	slog.Info("wrap: received notify fd", "session_id", sessionID, "fd", notifyFD.Fd())

	// Start the notify handler using existing infrastructure
	startNotifyHandlerForWrap(ctx, notifyFD, sessionID, a, execveEnabled, wrapperPID)
}

// acceptSignalFD listens on the Unix socket for a single connection from the CLI,
// receives the signal filter notify fd, and starts the signal handler.
func (a *App) acceptSignalFD(ctx context.Context, listener net.Listener, socketPath string, sessionID string) {
	defer listener.Close()
	// Note: do NOT remove the parent directory here — acceptNotifyFD owns that cleanup.

	if dl, ok := listener.(*net.UnixListener); ok {
		dl.SetDeadline(time.Now().Add(30 * time.Second))
	}

	conn, err := listener.Accept()
	if err != nil {
		slog.Debug("wrap: failed to accept signal connection", "session_id", sessionID, "error", err)
		return
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}

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
	startSignalHandlerForWrap(ctx, signalFD, sessionID, a)
}
