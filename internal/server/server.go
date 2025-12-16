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
	"github.com/agentsh/agentsh/internal/auth"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/internal/store/jsonl"
	"github.com/agentsh/agentsh/internal/store/sqlite"
)

type Server struct {
	httpServer *http.Server
	store      *composite.Store
	sessions   *session.Manager
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
	engine, err := policy.NewEngine(p, false /* enforceApprovals */)
	if err != nil {
		return nil, err
	}

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

	sessions := session.NewManager(100)
	broker := events.NewBroker()

	var apiKeyAuth *auth.APIKeyAuth
	if !cfg.Development.DisableAuth && cfg.Auth.Type == "api_key" {
		loaded, err := auth.LoadAPIKeys(cfg.Auth.APIKey.KeysFile, cfg.Auth.APIKey.HeaderName)
		if err != nil {
			_ = store.Close()
			return nil, err
		}
		apiKeyAuth = loaded
	}

	app := api.NewApp(cfg, sessions, store, engine, broker, apiKeyAuth)
	router := app.Router()

	s := &http.Server{
		Addr:              cfg.Server.HTTP.Addr,
		Handler:           router,
		ReadHeaderTimeout: 15 * time.Second,
	}

	return &Server{httpServer: s, store: store, sessions: sessions}, nil
}

func (s *Server) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

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
			_ = sess.CloseProxy()
			_ = sess.UnmountWorkspace()
		}
	}
	if s.store != nil {
		_ = s.store.Close()
	}
	return nil
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
