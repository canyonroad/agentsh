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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/db/tlsleaf"
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

type SessionResolver interface {
	ResolveSessionID(pid int32) (string, bool)
}

// Config captures the supervisor-supplied parameters for a Server.
// StateDir is always required. Services and Sink are required only when
// Unavoidability != UnavoidabilityOff. Logger defaults to slog.Default
// when nil.
type Config struct {
	Unavoidability  service.Unavoidability
	Services        []Service
	StateDir        string
	Sink            events.Sink
	Logger          *slog.Logger
	Policy          *policy.RuleSet // current rule set; nil means "no rules" (implicit deny). Hot-swappable in a later plan.
	Approver        policy.Approver // defaults to policy.NopApprover{} when nil.
	AgentSessionID  string
	SessionResolver SessionResolver

	// MaxQueryBytes caps the 'Q' frame body. Default 1 MiB when zero.
	// Statements above the cap get a synthetic ErrorResponse(54000) + close.
	MaxQueryBytes int

	// CancelMappingMax caps the proxy-wide BackendKeyData translation table.
	// Default 100k when zero.
	CancelMappingMax int

	// CancelGraceWindow retains disconnected cancel mappings for late
	// side-channel CancelRequests. Default 5 minutes when zero.
	CancelGraceWindow time.Duration

	// UpstreamTLSConfigForTest, when non-nil, overrides the production
	// upstream-TLS config (system roots, verify-full, MinVersion=TLS12,
	// ServerName from svc.Upstream). Test-only — production callsites must
	// leave this nil. dialUpstream uses this verbatim when non-nil.
	UpstreamTLSConfigForTest *tls.Config

	// classifierForTest, when non-nil, overrides the per-dialect Parser map
	// built by New(). Test-only — production callsites must leave this nil.
	classifierForTest func(dialect string) classify_pg.Parser
}

// Server runs the AgentSH PostgreSQL proxy listeners.
type Server struct {
	cfg      Config
	logger   *slog.Logger
	sentinel bool // true when Unavoidability == off; Start blocks on ctx, Shutdown is a no-op

	mu       sync.Mutex
	started  bool
	shutdown bool

	// Populated under mu before started=true so Shutdown always sees them.
	cancel    context.CancelFunc
	eg        *errgroup.Group
	listeners map[string]*unixListener
	conns     *activeConns

	// done is closed by Start when it returns (including early-error paths
	// after the started guard commits). Shutdown selects on it to drain
	// accept loops without calling eg.Wait directly.
	done chan struct{}

	caMu  sync.Mutex
	caRef *tlsleaf.CA

	policyPtr   atomic.Pointer[policy.RuleSet]
	classifiers map[string]classify_pg.Parser
	cancelMap   *cancelMap
}

// New validates cfg and returns a *Server. When cfg.Unavoidability ==
// UnavoidabilityOff, returns a sentinel server whose Start/Shutdown are
// no-ops. Returns an error when required fields are missing.
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Approver == nil {
		cfg.Approver = policy.NopApprover{}
	}
	if cfg.StateDir == "" {
		return nil, errors.New("postgres.New: StateDir is required")
	}
	if cfg.Unavoidability == service.UnavoidabilityOff {
		if cfg.MaxQueryBytes == 0 {
			cfg.MaxQueryBytes = 1 << 20
		}
		if cfg.CancelMappingMax == 0 {
			cfg.CancelMappingMax = defaultCancelMappingMax
		}
		if cfg.CancelGraceWindow == 0 {
			cfg.CancelGraceWindow = defaultCancelGraceWindow
		}
		srv := &Server{
			cfg:      cfg,
			logger:   cfg.Logger,
			sentinel: true,
			done:     make(chan struct{}),
			cancelMap: newCancelMap(cancelMapConfig{
				Max:         cfg.CancelMappingMax,
				GraceWindow: cfg.CancelGraceWindow,
			}),
		}
		srv.policyPtr.Store(cfg.Policy)
		return srv, nil
	}
	if cfg.Sink == nil {
		return nil, errors.New("postgres.New: Sink is required when Unavoidability != off")
	}
	if len(cfg.Services) == 0 {
		return nil, errors.New("postgres.New: at least one Service is required when Unavoidability != off")
	}
	if cfg.AgentSessionID == "" {
		return nil, errors.New("postgres.New: AgentSessionID is required when Unavoidability != off")
	}
	if cfg.SessionResolver == nil {
		return nil, errors.New("postgres.New: SessionResolver is required when Unavoidability != off")
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
	if cfg.MaxQueryBytes == 0 {
		cfg.MaxQueryBytes = 1 << 20
	}
	if cfg.CancelMappingMax == 0 {
		cfg.CancelMappingMax = defaultCancelMappingMax
	}
	if cfg.CancelGraceWindow == 0 {
		cfg.CancelGraceWindow = defaultCancelGraceWindow
	}
	classifiers, err := buildClassifierMap(cfg.Services)
	if err != nil {
		return nil, err
	}
	srv := &Server{
		cfg:         cfg,
		logger:      cfg.Logger,
		done:        make(chan struct{}),
		classifiers: classifiers,
		cancelMap: newCancelMap(cancelMapConfig{
			Max:         cfg.CancelMappingMax,
			GraceWindow: cfg.CancelGraceWindow,
		}),
	}
	srv.policyPtr.Store(cfg.Policy)
	return srv, nil
}

// Start binds listeners and runs accept loops until ctx is cancelled.
// For sentinel servers (Unavoidability == off), Start binds no listeners and
// blocks on ctx.Done() so callers can use a single goroutine pattern
// regardless of mode; returns ctx.Err().
// Returns the first listener-bind error; subsequent listeners are torn down.
//
// Plan 04a: connection handler is a no-op that closes the conn after the
// peercred check. Plan 04b plugs in the real handshake handler.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("postgres.Server: Start called twice")
	}
	if s.shutdown {
		s.mu.Unlock()
		return errors.New("postgres.Server: Start after Shutdown")
	}

	// Initialise all run-state fields while still holding the lock, before
	// setting started=true. This closes the window where Shutdown could run
	// between started=true and the fields being populated, and find cancel==nil.
	runCtx, cancel := context.WithCancel(ctx)
	eg := new(errgroup.Group)
	s.cancel = cancel
	s.eg = eg
	s.conns = newActiveConns()
	s.listeners = make(map[string]*unixListener)
	s.started = true
	s.mu.Unlock()

	// done is closed when Start returns, regardless of how it exits. This
	// lets Shutdown drain without calling eg.Wait itself (Finding 2).
	defer close(s.done)

	if s.sentinel {
		s.logger.Info("postgres.Server: sentinel mode (Unavoidability == off); not binding listeners")
		<-runCtx.Done()
		return runCtx.Err()
	}

	// Bind all listeners up-front; a partial failure tears the rest down.
	// Indexed by service name so a future tcp-listener service does not
	// disturb the alignment between cfg.Services and bound listeners.
	bound := make(map[string]*unixListener, len(s.cfg.Services))
	for _, svc := range s.cfg.Services {
		if svc.Listen.Kind != "unix" {
			s.logger.Warn("postgres.Server: skipping non-unix listener (Plan 04a binds unix only)",
				"service", svc.Name, "kind", svc.Listen.Kind)
			continue
		}
		ln, err := bindUnixListener(svc.Listen.Path)
		if err != nil {
			for _, b := range bound {
				_ = b.Close()
			}
			return fmt.Errorf("bind listener for service %q: %w", svc.Name, err)
		}
		bound[svc.Name] = ln
		s.logger.Info("postgres.Server: bound listener", "service", svc.Name, "path", svc.Listen.Path)
	}

	// Hand listeners over to the Server so Shutdown can close them.
	// If Shutdown already ran during the bind phase, runCtx is already
	// cancelled; close anything we just bound and return.
	s.mu.Lock()
	s.listeners = bound
	alreadyShutdown := s.shutdown
	s.mu.Unlock()

	if alreadyShutdown {
		for _, ln := range bound {
			_ = ln.Close()
		}
		return runCtx.Err()
	}

	for _, svc := range s.cfg.Services {
		ln, ok := bound[svc.Name]
		if !ok {
			continue
		}
		svcCopy := svc
		lnCopy := ln
		eg.Go(func() error {
			return s.acceptLoop(runCtx, svcCopy, lnCopy)
		})
	}

	err := eg.Wait()
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

// Shutdown stops accept loops, waits for in-flight conns to close, and
// unlinks Unix sockets. Returns nil for sentinel servers.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return nil
	}
	s.shutdown = true
	cancel := s.cancel
	listeners := s.listeners
	conns := s.conns
	sentinel := s.sentinel
	s.mu.Unlock()

	if cancel == nil {
		// Start was never called; nothing to do.
		return nil
	}
	cancel()
	if sentinel {
		return nil
	}
	for _, ln := range listeners {
		_ = ln.Close()
	}
	if conns != nil {
		conns.CloseAll()
	}
	// Wait for Start (and therefore all accept loops) to finish, bounded
	// by the caller's deadline. Only Start calls eg.Wait; Shutdown waits
	// on the done channel that Start closes on its way out.
	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (s *Server) acceptLoop(ctx context.Context, svc Service, ln *unixListener) error {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Warn("postgres.Server: accept error", "service", svc.Name, "err", err)
			return err
		}
		s.conns.Add(conn)
		go func() {
			defer s.conns.Remove(conn)
			defer conn.Close()
			s.handleConn(ctx, svc, conn)
		}()
	}
}

// handleConn is the per-connection handler. Reads SO_PEERCRED from the peer,
// resolves the peer PID to an AgentSH session, and on resolver miss/mismatch
// silently closes the conn while emitting a db_listener_auth_fail lifecycle event.
// Plan 04a: successful peercred is a no-op (conn closed by deferred Close in
// acceptLoop). Plan 04b plugs in the real handshake.
func (s *Server) handleConn(ctx context.Context, svc Service, conn net.Conn) {
	uid, pid, err := readPeerCred(conn)
	if err != nil {
		s.logger.Warn("postgres.Server: peercred read failed; closing", "service", svc.Name, "err", err)
		s.emitListenerAuthFail(ctx, svc, 0, 0, "", "peercred_read_failed")
		return
	}
	peerSessionID, ok := "", false
	if s.cfg.SessionResolver != nil {
		peerSessionID, ok = s.cfg.SessionResolver.ResolveSessionID(pid)
	}
	if !ok || peerSessionID == "" {
		s.emitListenerAuthFail(ctx, svc, uid, pid, "", "session_unknown")
		return
	}
	if peerSessionID != s.cfg.AgentSessionID {
		s.emitListenerAuthFail(ctx, svc, uid, pid, peerSessionID, "session_mismatch")
		return
	}
	pc := newProxyConn(s, svc, conn, uid)
	if err := pc.run(ctx); err != nil &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, net.ErrClosed) &&
		!errors.Is(err, io.EOF) &&
		!errors.Is(err, io.ErrUnexpectedEOF) {
		s.logger.Warn("postgres.Server: proxyConn exited with error", "service", svc.Name, "err", err)
	}
}

// emitListenerAuthFail emits a db_listener_auth_fail lifecycle event via the
// configured Sink. The ctx is the per-connection runCtx, which Shutdown
// cancels — under shutdown races the event may be dropped (the sink emit
// returns context.Canceled and we log warn). Acceptable for Plan 04a; Plan
// 04b's real sink may want a background ctx with a short timeout to ensure
// shutdown-race events still survive.
func (s *Server) emitListenerAuthFail(ctx context.Context, svc Service, uid uint32, pid int32, peerSessionID, reason string) {
	if s.cfg.Sink == nil {
		return
	}
	ev := events.LifecycleEvent{
		EventID:       newEventID(),
		Timestamp:     timeNow(),
		DBService:     svc.Name,
		Kind:          "db_listener_auth_fail",
		SessionID:     s.cfg.AgentSessionID,
		Reason:        reason,
		PeerUID:       uid,
		PeerPID:       pid,
		PeerSessionID: peerSessionID,
	}
	if err := s.cfg.Sink.EmitLifecycle(ctx, ev); err != nil {
		s.logger.Warn("postgres.Server: sink emit failed", "kind", ev.Kind, "err", err)
	}
}

// ca returns the CA, loading or generating it on first call. Concurrent
// callers see the same instance.
func (s *Server) ca() (*tlsleaf.CA, error) {
	s.caMu.Lock()
	defer s.caMu.Unlock()
	if s.caRef != nil {
		return s.caRef, nil
	}
	ca, err := tlsleaf.LoadOrCreate(s.cfg.StateDir, timeNow)
	if err != nil {
		return nil, fmt.Errorf("postgres.Server: load CA: %w", err)
	}
	s.caRef = ca
	s.logger.Info("postgres.Server: CA loaded",
		"key", filepath.Join(s.cfg.StateDir, "db-ca.key"),
		"cert", filepath.Join(s.cfg.StateDir, "db-ca.crt"))
	return ca, nil
}

// SetPolicy atomically replaces the active rule set. A nil ruleset means
// "implicit deny everywhere" (matches policy.Evaluate(stmt, nil, _)).
func (s *Server) SetPolicy(rs *policy.RuleSet) { s.policyPtr.Store(rs) }

func (s *Server) policy() *policy.RuleSet { return s.policyPtr.Load() }
