package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/api"
	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/auth"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	storepkg "github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/internal/store/jsonl"
	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/internal/store/webhook"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type Server struct {
	httpServer *http.Server
	httpLn     net.Listener

	unixServer *http.Server
	unixLn     net.Listener
	unixPath   string

	grpcServer *grpc.Server
	grpcLn     net.Listener

	store      *composite.Store
	broker     *events.Broker
	sessions   *session.Manager

	sessionTimeout time.Duration
	idleTimeout    time.Duration
	reapInterval   time.Duration

	pprofLn     net.Listener
	pprofServer *http.Server
}

func New(cfg *config.Config) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}

	// Safety: approvals via API require authentication. Otherwise an agent could self-approve
	// by calling the approvals endpoints on localhost.
	if cfg.Approvals.Enabled && strings.EqualFold(strings.TrimSpace(cfg.Approvals.Mode), "api") {
		if cfg.Development.DisableAuth || strings.EqualFold(strings.TrimSpace(cfg.Auth.Type), "none") {
			return nil, fmt.Errorf("approvals.mode=api requires auth.type=api_key (auth is disabled)")
		}
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

	metricsCollector := metrics.New()

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

	var webhookStore *webhook.Store
	if cfg.Audit.Webhook.URL != "" {
		flushEvery, err := time.ParseDuration(cfg.Audit.Webhook.FlushInterval)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("parse audit.webhook.flush_interval: %w", err)
		}
		timeout, err := time.ParseDuration(cfg.Audit.Webhook.Timeout)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("parse audit.webhook.timeout: %w", err)
		}
		webhookStore, err = webhook.New(cfg.Audit.Webhook.URL, cfg.Audit.Webhook.BatchSize, flushEvery, timeout, cfg.Audit.Webhook.Headers)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
	}

	var eventStores []storepkg.EventStore
	if jsonlStore != nil {
		eventStores = append(eventStores, jsonlStore)
	}
	if webhookStore != nil {
		eventStores = append(eventStores, webhookStore)
	}
	// Wrap primary event store so metrics count each event exactly once.
	primary := metrics.WrapEventStore(db, metricsCollector)
	store := composite.New(primary, db, eventStores...)

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

	app := api.NewApp(cfg, sessions, store, engine, broker, apiKeyAuth, approvalsMgr, metricsCollector)
	router := app.Router()

	readTimeoutStr := cfg.Server.HTTP.ReadTimeout
	if readTimeoutStr == "" {
		readTimeoutStr = "30s"
	}
	readTimeout, err := time.ParseDuration(readTimeoutStr)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("parse server.http.read_timeout: %w", err)
	}
	writeTimeoutStr := cfg.Server.HTTP.WriteTimeout
	if writeTimeoutStr == "" {
		writeTimeoutStr = "5m"
	}
	writeTimeout, err := time.ParseDuration(writeTimeoutStr)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("parse server.http.write_timeout: %w", err)
	}
	maxReqSizeStr := cfg.Server.HTTP.MaxRequestSize
	if maxReqSizeStr == "" {
		maxReqSizeStr = "10MB"
	}
	maxReqBytes, err := config.ParseByteSize(maxReqSizeStr)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("parse server.http.max_request_size: %w", err)
	}
	handler := withRequestBodyLimit(router, maxReqBytes)

	s := &http.Server{
		Addr:              cfg.Server.HTTP.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
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

	srv := &Server{
		httpServer:     s,
		store:          store,
		broker:         broker,
		sessions:       sessions,
		sessionTimeout: sessionTimeout,
		idleTimeout:    idleTimeout,
		reapInterval:   reapInterval,
	}

	ln, err := listenHTTP(cfg)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	srv.httpLn = ln

	if cfg.Server.GRPC.Enabled {
		grpcLn, grpcErr := listenGRPC(cfg)
		if grpcErr != nil {
			_ = store.Close()
			return nil, grpcErr
		}

		var opts []grpc.ServerOption
		opts = append(opts,
			grpc.UnaryInterceptor(api.GRPCUnaryAuthInterceptor(app)),
			grpc.StreamInterceptor(api.GRPCStreamAuthInterceptor(app)),
		)
		if cfg.Server.TLS.Enabled {
			if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" {
				_ = grpcLn.Close()
				_ = store.Close()
				return nil, fmt.Errorf("server.tls enabled but cert_file/key_file missing")
			}
			creds, err := credentials.NewServerTLSFromFile(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
			if err != nil {
				_ = grpcLn.Close()
				_ = store.Close()
				return nil, fmt.Errorf("load grpc tls keypair: %w", err)
			}
			opts = append(opts, grpc.Creds(creds))
		}

		gs := grpc.NewServer(opts...)
		api.RegisterGRPC(gs, app)
		hs := health.NewServer()
		hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		healthpb.RegisterHealthServer(gs, hs)

		srv.grpcLn = grpcLn
		srv.grpcServer = gs
	}

	if cfg.Server.UnixSocket.Enabled && cfg.Server.UnixSocket.Path != "" {
		unixPath := cfg.Server.UnixSocket.Path
		if err := os.MkdirAll(filepath.Dir(unixPath), 0o755); err != nil {
			if isPermissionErr(err) {
				fmt.Fprintf(os.Stderr, "agentsh: unix socket disabled (mkdir): %v\n", err)
				goto unixDone
			}
			_ = store.Close()
			return nil, fmt.Errorf("unix socket mkdir: %w", err)
		}
		_ = os.Remove(unixPath)
		unixLn, err := net.Listen("unix", unixPath)
		if err != nil {
			if isPermissionErr(err) {
				fmt.Fprintf(os.Stderr, "agentsh: unix socket disabled (listen): %v\n", err)
				goto unixDone
			}
			_ = store.Close()
			return nil, fmt.Errorf("unix socket listen: %w", err)
		}
		perms := os.FileMode(0o660)
		if p := cfg.Server.UnixSocket.Permissions; p != "" {
			u, perr := strconv.ParseUint(p, 0, 32)
			if perr != nil {
				_ = unixLn.Close()
				_ = store.Close()
				return nil, fmt.Errorf("unix socket permissions %q: %w", p, perr)
			}
			perms = os.FileMode(u)
		}
		if err := os.Chmod(unixPath, perms); err != nil {
			if isPermissionErr(err) {
				fmt.Fprintf(os.Stderr, "agentsh: unix socket disabled (chmod): %v\n", err)
				_ = unixLn.Close()
				goto unixDone
			}
			_ = unixLn.Close()
			_ = store.Close()
			return nil, fmt.Errorf("unix socket chmod: %w", err)
		}
		srv.unixLn = unixLn
		srv.unixPath = unixPath
		srv.unixServer = &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 15 * time.Second,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
		}
	}
unixDone:

	if cfg.Development.PProf.Enabled {
		addr := cfg.Development.PProf.Addr
		if addr == "" {
			addr = "localhost:6060"
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("pprof listen: %w", err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		srv.pprofLn = ln
		srv.pprofServer = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	}

	return srv, nil
}

func isPermissionErr(err error) bool {
	return os.IsPermission(err) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

func withRequestBodyLimit(next http.Handler, maxBytes int64) http.Handler {
	if maxBytes <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func listenHTTP(cfg *config.Config) (net.Listener, error) {
	addr := cfg.Server.HTTP.Addr
	if cfg.Development.DisableAuth || strings.EqualFold(strings.TrimSpace(cfg.Auth.Type), "none") {
		if !isLoopbackListenAddr(addr) {
			return nil, fmt.Errorf("refusing to listen on %q with auth.type=none (use 127.0.0.1/localhost or enable auth)", addr)
		}
	}
	if !cfg.Server.TLS.Enabled {
		return net.Listen("tcp", addr)
	}
	if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" {
		return nil, fmt.Errorf("server.tls enabled but cert_file/key_file missing")
	}
	cert, err := tlsLoad(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	if err != nil {
		return nil, err
	}
	return tlsListen(addr, cert)
}

func listenGRPC(cfg *config.Config) (net.Listener, error) {
	addr := cfg.Server.GRPC.Addr
	if addr == "" {
		addr = "127.0.0.1:9090"
	}
	if cfg.Development.DisableAuth || strings.EqualFold(strings.TrimSpace(cfg.Auth.Type), "none") {
		if !isLoopbackListenAddr(addr) {
			return nil, fmt.Errorf("refusing to listen on %q with auth.type=none (use 127.0.0.1/localhost or enable auth)", addr)
		}
	}
	return net.Listen("tcp", addr)
}

func isLoopbackListenAddr(addr string) bool {
	a := strings.TrimSpace(addr)
	if a == "" {
		return false
	}
	// ":8080" binds on all interfaces.
	if strings.HasPrefix(a, ":") {
		return false
	}
	host, _, err := net.SplitHostPort(a)
	if err != nil {
		// If it's missing a port, treat as a hostname/IP.
		host = a
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// Conservative: unknown hostnames could resolve non-loopback.
	return false
}

func tlsLoad(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load tls keypair: %w", err)
	}
	return cert, nil
}

func tlsListen(addr string, cert tls.Certificate) (net.Listener, error) {
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	return tls.Listen("tcp", addr, cfg)
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

	if s.pprofLn != nil && s.pprofServer != nil {
		go func() { _ = s.pprofServer.Serve(s.pprofLn) }()
	}

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

	errCh := make(chan error, 3)
	go func() {
		if err := s.httpServer.Serve(s.httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	if s.unixServer != nil && s.unixLn != nil {
		go func() {
			if err := s.unixServer.Serve(s.unixLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}
	if s.grpcServer != nil && s.grpcLn != nil {
		go func() {
			if err := s.grpcServer.Serve(s.grpcLn); err != nil {
				errCh <- err
			}
		}()
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if s.pprofServer != nil {
			_ = s.pprofServer.Shutdown(shutdownCtx)
		}
		if s.unixServer != nil {
			_ = s.unixServer.Shutdown(shutdownCtx)
		}
		if s.grpcServer != nil {
			s.grpcServer.GracefulStop()
		}
		return s.httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		if s.pprofServer != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = s.pprofServer.Shutdown(shutdownCtx)
		}
		if s.unixServer != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = s.unixServer.Shutdown(shutdownCtx)
		}
		if s.grpcServer != nil {
			s.grpcServer.Stop()
		}
		return fmt.Errorf("server: %w", err)
	}
}

func (s *Server) Close() error {
	if s.httpLn != nil {
		_ = s.httpLn.Close()
		s.httpLn = nil
	}
	if s.unixLn != nil {
		_ = s.unixLn.Close()
		s.unixLn = nil
	}
	if s.grpcLn != nil {
		_ = s.grpcLn.Close()
		s.grpcLn = nil
	}
	if s.grpcServer != nil {
		s.grpcServer.Stop()
		s.grpcServer = nil
	}
	if s.unixPath != "" {
		_ = os.Remove(s.unixPath)
		s.unixPath = ""
	}
	if s.pprofLn != nil {
		_ = s.pprofLn.Close()
		s.pprofLn = nil
	}
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

func (s *Server) PProfAddr() string {
	if s == nil || s.pprofLn == nil {
		return ""
	}
	return s.pprofLn.Addr().String()
}

func (s *Server) GRPCAddr() string {
	if s == nil || s.grpcLn == nil {
		return ""
	}
	return s.grpcLn.Addr().String()
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
		filepath.Join("/etc/agentsh", "default-policy.yaml"),
		filepath.Join("/etc/agentsh", "default-policy.yml"),
		filepath.Join("/etc/agentsh", "policies", cfg.Policies.Default+".yaml"),
		filepath.Join("/etc/agentsh", "policies", cfg.Policies.Default+".yml"),
	}
	for _, p := range localCandidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("could not find default policy (set policies.dir or add default-policy.yml)")
}
