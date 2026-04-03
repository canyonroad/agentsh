//go:build darwin

package server

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/platform/darwin/policysock"
	"github.com/agentsh/agentsh/internal/policy"
)

// startPolicySocket creates and starts the policy socket server for macOS
// system extension IPC. It sets the policySockCancel and policySockDone
// fields on the Server so the socket is shut down when the server stops.
func (s *Server) startPolicySocket(cfg *config.Config, engine *policy.Engine) {
	sockPath := cfg.PolicySocket.Path
	if sockPath == "" {
		return
	}

	// Ensure the socket's parent directory exists.
	if dir := filepath.Dir(sockPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			slog.Warn("policy socket disabled: cannot create directory",
				"dir", dir, "error", err)
			return
		}
	}

	// Build the policy adapter that bridges policy.Engine to the policysock
	// handler interface. Pass nil for session resolver for now; the session
	// tracker within the policysock server handles PID-to-session mapping
	// via register_session messages from the system extension.
	tracker := policysock.NewSessionTracker()
	adapter := policysock.NewPolicyAdapter(engine, tracker)

	// Create command resolver and event handler.
	cmdResolver := policysock.NewCommandResolver()
	eventHandler := policysock.NewESFEventHandler(s.store, cmdResolver, tracker)

	psrv := policysock.NewServer(sockPath, adapter)
	psrv.SetTeamID(cfg.PolicySocket.TeamID)
	psrv.SetExecHandler(adapter)
	psrv.SetSnapshotBuilder(adapter)
	psrv.SetSessionRegistrar(tracker)
	psrv.SetEventHandler(eventHandler)

	// Store resolver and tracker so exec handler can register PIDs and sessions.
	s.cmdResolver = cmdResolver
	s.sessionTracker = tracker

	ctx, cancel := context.WithCancel(context.Background())
	s.policySockCancel = cancel
	s.policySockDone = make(chan struct{})

	go func() {
		defer close(s.policySockDone)
		if err := psrv.Run(ctx); err != nil {
			slog.Error("policy socket server exited with error", "error", err)
		}
	}()

	// Wait for the server to become ready (or fail).
	<-psrv.Ready()
	if err := psrv.StartErr(); err != nil {
		slog.Warn("policy socket server failed to start", "error", err)
		cancel()
		<-s.policySockDone
		s.policySockCancel = nil
		s.policySockDone = nil
		return
	}

	slog.Info("policy socket server started", "path", sockPath)
}
