package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/api"
	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/auth"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/internal/store/jsonl"
	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type Server struct {
	httpServer *http.Server
	store      *composite.Store
	broker     *events.Broker
	sessions   *session.Manager

	sessionTimeout time.Duration
	idleTimeout    time.Duration
	reapInterval   time.Duration
}

func New(cfg *config.Config) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}

	policyPath, err := resolvePolicyPath(cfg)
	if err != nil {
		return nil, err
	}
	p, err := policy.LoadFromFile(policyPath)
	if err != nil {
		return nil, err
	}
	enforceApprovals := cfg.Approvals.Enabled
	engine, err := policy.NewEngine(p, enforceApprovals)
	if err != nil {
		return nil, err
	}
	limits := engine.Limits()

	sqlitePath := cfg.Audit.Storage.SQLitePath
	if sqlitePath == "" {
		sqlitePath = filepath.Join(filepath.Dir(cfg.Sessions.BaseDir), "events.db")
	}
	db, err := sqlite.Open(sqlitePath)
	if err != nil {
		return nil, err
	}

	var jsonlStore *jsonl.Store
	if cfg.Audit.Output != "" {
		jsonlStore, err = jsonl.New(cfg.Audit.Output, cfg.Audit.Rotation.MaxSizeMB, cfg.Audit.Rotation.MaxBackups)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	var store *composite.Store
	if jsonlStore != nil {
		store = composite.New(db, db, jsonlStore)
	} else {
		store = composite.New(db, db)
	}

	sessions := session.NewManager(cfg.Sessions.MaxSessions)
	broker := events.NewBroker()
	emitter := serverEmitter{store: store, broker: broker}

	var approvalsMgr *approvals.Manager
	if cfg.Approvals.Enabled {
		timeout, _ := time.ParseDuration(cfg.Approvals.Timeout)
		approvalsMgr = approvals.New(cfg.Approvals.Mode, timeout, emitter)
	}

	var apiKeyAuth *auth.APIKeyAuth
	if !cfg.Development.DisableAuth && cfg.Auth.Type == "api_key" {
		loaded, err := auth.LoadAPIKeys(cfg.Auth.APIKey.KeysFile, cfg.Auth.APIKey.HeaderName)
		if err != nil {
			_ = store.Close()
			return nil, err
		}
		apiKeyAuth = loaded
	}

	app := api.NewApp(cfg, sessions, store, engine, broker, apiKeyAuth, approvalsMgr)
	router := app.Router()

	s := &http.Server{
		Addr:              cfg.Server.HTTP.Addr,
		Handler:           router,
		ReadHeaderTimeout: 15 * time.Second,
	}

	sessionTimeout := limits.SessionTimeout
	idleTimeout := limits.IdleTimeout
	if cfg.Sessions.DefaultTimeout != "" {
		d, err := time.ParseDuration(cfg.Sessions.DefaultTimeout)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("parse sessions.default_timeout: %w", err)
		}
		if d > 0 && (sessionTimeout == 0 || d < sessionTimeout) {
			sessionTimeout = d
		}
	}
	if cfg.Sessions.DefaultIdleTimeout != "" {
		d, err := time.ParseDuration(cfg.Sessions.DefaultIdleTimeout)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("parse sessions.default_idle_timeout: %w", err)
		}
		if d > 0 && (idleTimeout == 0 || d < idleTimeout) {
			idleTimeout = d
		}
	}
	reapInterval := 1 * time.Minute
	if cfg.Sessions.CleanupInterval != "" {
		d, err := time.ParseDuration(cfg.Sessions.CleanupInterval)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("parse sessions.cleanup_interval: %w", err)
		}
		if d > 0 {
			reapInterval = d
		}
	}

	return &Server{
		httpServer:     s,
		store:          store,
		broker:         broker,
		sessions:       sessions,
		sessionTimeout: sessionTimeout,
		idleTimeout:    idleTimeout,
		reapInterval:   reapInterval,
	}, nil
}

type serverEmitter struct {
	store  *composite.Store
	broker *events.Broker
}

func (e serverEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	return e.store.AppendEvent(ctx, ev)
}
func (e serverEmitter) Publish(ev types.Event) { e.broker.Publish(ev) }

func (s *Server) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if s.sessionTimeout > 0 || s.idleTimeout > 0 {
		ticker := time.NewTicker(s.reapInterval)
		defer ticker.Stop()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					s.reapOnce(time.Now().UTC())
				}
			}
		}()
	}

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	}
}

func (s *Server) Close() error {
	if s.sessions != nil {
		for _, sess := range s.sessions.List() {
			_ = sess.CloseNetNS()
			_ = sess.CloseProxy()
			_ = sess.UnmountWorkspace()
		}
	}
	if s.store != nil {
		_ = s.store.Close()
	}
	return nil
}

func (s *Server) reapOnce(now time.Time) {
	reaped := s.sessions.ReapExpired(now, s.sessionTimeout, s.idleTimeout)
	for _, sess := range reaped {
		_ = sess.CloseNetNS()
		_ = sess.CloseProxy()
		_ = sess.UnmountWorkspace()

		expiredBy := "unknown"
		createdAt, last := sess.Timestamps()
		if s.sessionTimeout > 0 && now.Sub(createdAt) > s.sessionTimeout {
			expiredBy = "session_timeout"
		} else if s.idleTimeout > 0 && now.Sub(last) > s.idleTimeout {
			expiredBy = "idle_timeout"
		}

		ev := types.Event{
			ID:        uuid.NewString(),
			Timestamp: now,
			Type:      "session_expired",
			SessionID: sess.ID,
			Fields: map[string]any{
				"expired_by":      expiredBy,
				"session_timeout": s.sessionTimeout.String(),
				"idle_timeout":    s.idleTimeout.String(),
			},
		}
		_ = s.store.AppendEvent(context.Background(), ev)
		if s.broker != nil {
			s.broker.Publish(ev)
		}
	}
}

func resolvePolicyPath(cfg *config.Config) (string, error) {
	if cfg.Policies.Dir != "" {
		if p, err := policy.ResolvePolicyPath(cfg.Policies.Dir, cfg.Policies.Default); err == nil {
			return p, nil
		}
	}
	localCandidates := []string{
		"default-policy.yml",
		"default-policy.yaml",
		filepath.Join("configs", "default-policy.yaml"),
		filepath.Join("configs", "default-policy.yml"),
	}
	for _, p := range localCandidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("could not find default policy (set policies.dir or add default-policy.yml)")
}
