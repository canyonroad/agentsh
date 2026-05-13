package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/db/events"
	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

// dbProxyService is the per-service input to startDBProxy. The api layer
// joins the policy-side DBService (from internal/db/policy) with a
// supervisor-derived listener path into this flat shape so the proxy
// package never has to know how listener paths are computed.
type dbProxyService struct {
	Name       string
	DBService  dbpolicy.DBService
	ListenKind string // "unix" or "tcp"
	ListenPath string // when ListenKind == "unix"
	ListenHost string // when ListenKind == "tcp"
	ListenPort int    // when ListenKind == "tcp"
}

type dbProxyDeps struct {
	Unavoidability  dbservice.Unavoidability
	Services        []dbProxyService
	StateDir        string
	Sink            events.Sink
	Policy          *dbpolicy.RuleSet // live rule set for connect-rule eval
	AgentSessionID  string
	SessionResolver postgres.SessionResolver
}

// buildDBProxyConfig assembles a postgres.Config from deps and ensures
// listener parent directories exist for unix listeners.
func buildDBProxyConfig(deps dbProxyDeps) (postgres.Config, error) {
	cfg := postgres.Config{
		Unavoidability:  deps.Unavoidability,
		StateDir:        deps.StateDir,
		Sink:            deps.Sink,
		Policy:          deps.Policy,
		AgentSessionID:  deps.AgentSessionID,
		SessionResolver: deps.SessionResolver,
	}
	for _, s := range deps.Services {
		if s.ListenKind == "unix" && s.ListenPath != "" {
			if err := os.MkdirAll(filepath.Dir(s.ListenPath), 0o700); err != nil {
				return postgres.Config{}, fmt.Errorf("buildDBProxyConfig: mkdir for service %q listener: %w", s.Name, err)
			}
		}
		cfg.Services = append(cfg.Services, postgres.Service{
			Name:     s.Name,
			Family:   s.DBService.Family,
			Dialect:  s.DBService.Dialect,
			Upstream: s.DBService.Upstream,
			TLSMode:  s.DBService.TLSMode,
			Listen: postgres.ServiceListener{
				Kind: s.ListenKind,
				Path: s.ListenPath,
				Host: s.ListenHost,
				Port: s.ListenPort,
			},
			Service: s.DBService,
		})
	}
	return cfg, nil
}

// startDBProxy constructs and starts the AgentSH PostgreSQL proxy. Returns
// the *postgres.Server so the caller can wire Shutdown into supervisor lifecycle.
//
// Plan 04a: under Unavoidability == off, returns a sentinel server that
// does nothing. Under observe/enforce, binds Unix-socket listeners.
//
// For unix listeners, the parent directory of each ListenPath is created
// (mkdir -p style) before bind so a fresh StateDir works on first boot.
func startDBProxy(ctx context.Context, deps dbProxyDeps) (*postgres.Server, error) {
	srv, _, err := startDBProxyWithStartError(ctx, deps)
	return srv, err
}

func startDBProxyWithStartError(ctx context.Context, deps dbProxyDeps) (*postgres.Server, <-chan error, error) {
	cfg, err := buildDBProxyConfig(deps)
	if err != nil {
		return nil, nil, fmt.Errorf("startDBProxy: %w", err)
	}
	srv, err := postgres.New(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("startDBProxy: new server: %w", err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
		close(errCh)
	}()
	return srv, errCh, nil
}

// loadDBRuleSet decodes the supervisor's loaded policy into a *dbpolicy.RuleSet.
// Returns nil when no DB rules are present (decoding succeeds with an empty
// services map). Errors are returned to the caller; they should be fatal
// because misconfigured DB policy should not silently disable interception.
func loadDBRuleSet(p *rootpolicy.Policy) (*dbpolicy.RuleSet, error) {
	if p == nil {
		return nil, nil
	}
	rs, _, err := dbpolicy.Decode(p)
	if err != nil {
		return nil, fmt.Errorf("loadDBRuleSet: decode db policy: %w", err)
	}
	return rs, nil
}

// collectDBProxyServices enumerates every declared db_service in rs and
// synthesizes the supervisor-derived listener path. Plan 04a convention:
// ${stateDir}/db-services/${name}.sock for each service.
func collectDBProxyServices(rs *dbpolicy.RuleSet, stateDir string) []dbProxyService {
	if rs == nil {
		return nil
	}
	services := rs.AllServices()
	if len(services) == 0 {
		return nil
	}
	out := make([]dbProxyService, 0, len(services))
	for _, s := range services {
		out = append(out, dbProxyService{
			Name:       s.Name,
			DBService:  s,
			ListenKind: "unix",
			ListenPath: filepath.Join(stateDir, "db-services", s.Name+".sock"),
		})
	}
	return out
}
