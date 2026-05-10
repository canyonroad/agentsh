//go:build linux

// Package postgres implements the AgentSH PostgreSQL proxy per
// docs/agentsh-db-access-spec.md §11–§14 and the macro design at
// docs/superpowers/specs/2026-05-10-db-plan-04-pg-proxy-skeleton-design.md.
//
// Plan 04a ships only the listener skeleton: bind Unix sockets per declared
// db_service, peer-authenticate via SO_PEERCRED + UID-equality, accept and
// immediately close. Plan 04b adds the handshake / TLS layer; Plan 04c adds
// Simple Query classification and DBEvent emission.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

// Service is the proxy-internal flattened view of one db_service. The proxy
// needs the listener path (from internal/db/service.Listener) and the
// upstream + tls_mode metadata (from internal/db/policy.DBService). Callers
// in internal/api are responsible for joining them.
type Service struct {
	Name     string           // matches policy.DBService.Name
	Family   string           // "postgres"
	Dialect  string           // postgres / aurora_postgres / cockroachdb / redshift
	Upstream string           // host:port
	TLSMode  string           // terminate_reissue / passthrough / terminate_plaintext_upstream
	Listen   ServiceListener  // unix-socket path or tcp host:port
	Service  policy.DBService // full DBService for downstream evaluation
}

// ServiceListener mirrors internal/db/service.Listener but is the package-
// local concrete type the proxy operates on. Plan 04a only binds Kind=="unix".
type ServiceListener struct {
	Kind string // "unix" or "tcp"
	Path string // when Kind == "unix"
	Host string // when Kind == "tcp"
	Port int    // when Kind == "tcp"
}

// Config captures the supervisor-supplied parameters for a Server.
// StateDir is always required. Services and Sink are required only when
// Unavoidability != UnavoidabilityOff. Logger defaults to slog.Default
// when nil.
type Config struct {
	Unavoidability service.Unavoidability
	Services       []Service
	StateDir       string
	Sink           events.Sink
	Logger         *slog.Logger
}

// Server runs the AgentSH PostgreSQL proxy listeners.
type Server struct {
	cfg      Config
	logger   *slog.Logger
	sentinel bool // true when Unavoidability == off; Start/Shutdown are no-ops
	mu       sync.Mutex
	started  bool
	shutdown bool
}

// New validates cfg and returns a *Server. When cfg.Unavoidability ==
// UnavoidabilityOff, returns a sentinel server whose Start/Shutdown are
// no-ops. Returns an error when required fields are missing.
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.StateDir == "" {
		return nil, errors.New("postgres.New: StateDir is required")
	}
	if cfg.Unavoidability == service.UnavoidabilityOff {
		return &Server{cfg: cfg, logger: cfg.Logger, sentinel: true}, nil
	}
	if cfg.Sink == nil {
		return nil, errors.New("postgres.New: Sink is required when Unavoidability != off")
	}
	if len(cfg.Services) == 0 {
		return nil, errors.New("postgres.New: at least one Service is required when Unavoidability != off")
	}
	for i, svc := range cfg.Services {
		if svc.Name == "" {
			return nil, fmt.Errorf("postgres.New: services[%d].Name is empty", i)
		}
		if svc.Listen.Kind != "unix" && svc.Listen.Kind != "tcp" {
			return nil, fmt.Errorf("postgres.New: services[%d].Listen.Kind = %q; want unix or tcp", i, svc.Listen.Kind)
		}
		if svc.Listen.Kind == "unix" && svc.Listen.Path == "" {
			return nil, fmt.Errorf("postgres.New: services[%d].Listen.Path is empty for unix listener", i)
		}
	}
	return &Server{cfg: cfg, logger: cfg.Logger}, nil
}

// Start binds listeners and runs accept loops until ctx is cancelled.
// Returns nil for sentinel servers. Returns the first listener-bind error;
// subsequent listeners are torn down.
//
// Plan 04a: connection handler is a no-op that closes the conn after the
// peercred check. Plan 04b plugs in the real handshake handler.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("postgres.Server: Start called twice")
	}
	s.started = true
	s.mu.Unlock()

	if s.sentinel {
		s.logger.Info("postgres.Server: sentinel mode (Unavoidability == off); not binding listeners")
		return nil
	}

	// Listener bind + accept loop is implemented in Task 5.
	return errors.New("postgres.Server.Start: listener bind not yet implemented (Plan 04a Task 5)")
}

// Shutdown stops accept loops, waits for in-flight conns to close, and
// unlinks Unix sockets. Returns nil for sentinel servers.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shutdown {
		return nil
	}
	s.shutdown = true
	if s.sentinel {
		return nil
	}
	// Implemented in Task 5.
	return nil
}
