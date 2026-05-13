package api

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"gopkg.in/yaml.v3"
)

const dbProxySessionIdentity = "agentsh-db-proxy"

type defaultDBResolver struct{}

func (defaultDBResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func sessionDBProxyStateDir(baseDir, sessionID string) string {
	return filepath.Join(baseDir, sessionID, "db-proxy")
}

func dbServiceConfigFromProxyServices(services []dbProxyService) (dbservice.Config, error) {
	cfg := dbservice.Config{Services: make([]dbservice.Service, 0, len(services))}
	for _, svc := range services {
		host, portText, err := net.SplitHostPort(svc.DBService.Upstream)
		if err != nil {
			return dbservice.Config{}, fmt.Errorf("db service %q upstream %q: %w", svc.Name, svc.DBService.Upstream, err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port <= 0 {
			return dbservice.Config{}, fmt.Errorf("db service %q upstream %q: invalid port %q", svc.Name, svc.DBService.Upstream, portText)
		}
		cfg.Services = append(cfg.Services, dbservice.Service{
			Name:    svc.Name,
			Family:  svc.DBService.Family,
			Dialect: svc.DBService.Dialect,
			Upstream: dbservice.Endpoint{
				Host: host,
				Port: port,
			},
			Listen: dbservice.Listener{
				Kind: svc.ListenKind,
				Path: svc.ListenPath,
				Host: svc.ListenHost,
				Port: svc.ListenPort,
			},
			TLSMode: svc.DBService.TLSMode,
		})
	}
	return cfg, nil
}

func mergeDBUnavoidabilityBundle(base *policy.Policy, bundle dbservice.Bundle) *policy.Policy {
	if base == nil {
		base = &policy.Policy{}
	}
	merged := clonePolicy(base)
	merged.NetworkRules = append(merged.NetworkRules, bundle.Policy.NetworkRules...)
	merged.CommandRules = append(merged.CommandRules, bundle.Policy.CommandRules...)
	merged.UnixRules = append(merged.UnixRules, bundle.Policy.UnixRules...)
	merged.DnsRedirectRules = append(merged.DnsRedirectRules, bundle.Policy.DnsRedirectRules...)
	merged.ConnectRedirectRules = append(merged.ConnectRedirectRules, bundle.Policy.ConnectRedirectRules...)
	merged.Metadata = append(merged.Metadata, bundle.Metadata...)
	return merged
}

func collectSortedDBProxyServices(rs *dbpolicy.RuleSet, stateDir string) []dbProxyService {
	services := collectDBProxyServices(rs, stateDir)
	sort.Slice(services, func(i, j int) bool {
		return services[i].Name < services[j].Name
	})
	return services
}

func (a *App) compileDBPolicyForSession(ctx context.Context, s *session.Session, base *policy.Policy, policyVars map[string]string, enforceApprovals bool) (*policy.Engine, *dbpolicy.RuleSet, string, error) {
	_ = ctx
	if base == nil {
		return a.policy, nil, "", nil
	}
	rs, err := loadDBRuleSet(base)
	if err != nil {
		return nil, nil, "", err
	}
	if rs.Unavoidability() == dbservice.UnavoidabilityOff || len(rs.AllServices()) == 0 {
		engine, err := policy.NewEngineWithVariables(base, enforceApprovals, true, policyVars)
		return engine, rs, "", err
	}

	stateDir := sessionDBProxyStateDir(a.cfg.Sessions.BaseDir, s.ID)
	services := collectSortedDBProxyServices(rs, stateDir)
	serviceCfg, err := dbServiceConfigFromProxyServices(services)
	if err != nil {
		return nil, nil, "", err
	}
	bundle, err := dbservice.GenerateBundle(serviceCfg, dbservice.BundleOptions{
		SessionID:                  s.ID,
		ProxySessionID:             dbProxySessionIdentity,
		SocketBaseDir:              filepath.Join(stateDir, "db-services"),
		IncludeToolRules:           true,
		Mode:                       rs.Unavoidability(),
		AllowHostnameOnlyInEnforce: false,
		Resolver:                   defaultDBResolver{},
	})
	if err != nil {
		return nil, nil, "", err
	}
	merged := mergeDBUnavoidabilityBundle(base, bundle)
	engine, err := policy.NewEngineWithVariables(merged, enforceApprovals, true, policyVars)
	if err != nil {
		return nil, nil, "", err
	}
	return engine, rs, stateDir, nil
}

func (a *App) startSessionDBProxy(ctx context.Context, s *session.Session, rs *dbpolicy.RuleSet, stateDir string) error {
	if rs == nil || rs.Unavoidability() == dbservice.UnavoidabilityOff || len(rs.AllServices()) == 0 {
		return nil
	}
	resolver, ok := a.dbProxySessionResolver().(postgres.SessionResolver)
	if !ok || resolver == nil {
		return fmt.Errorf("DB proxy session resolver is required when DB unavoidability is %s", rs.Unavoidability())
	}

	proxyCtx, cancel := context.WithCancel(context.Background())
	services := collectSortedDBProxyServices(rs, stateDir)
	srv, err := startDBProxy(proxyCtx, dbProxyDeps{
		Unavoidability:  rs.Unavoidability(),
		Services:        services,
		StateDir:        stateDir,
		Sink:            dbAuditSink{store: a.store, broker: a.broker},
		Policy:          rs,
		AgentSessionID:  s.ID,
		SessionResolver: resolver,
	})
	if err != nil {
		cancel()
		return err
	}
	if err := waitForDBProxyListeners(ctx, services, 2*time.Second); err != nil {
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
		return err
	}
	s.SetDBProxy(filepath.Join(stateDir, "db-services"), func() error {
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		return srv.Shutdown(shutdownCtx)
	})
	return nil
}

func waitForDBProxyListeners(ctx context.Context, services []dbProxyService, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		missing := ""
		for _, svc := range services {
			if svc.ListenKind != "unix" || svc.ListenPath == "" {
				continue
			}
			fi, err := os.Stat(svc.ListenPath)
			if err != nil {
				missing = svc.ListenPath
				break
			}
			if fi.Mode()&os.ModeSocket == 0 {
				return fmt.Errorf("DB proxy listener path %q is not a socket", svc.ListenPath)
			}
		}
		if missing == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("DB proxy listener did not start at %q", missing)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (a *App) cleanupCreatedSession(s *session.Session) {
	if s == nil {
		return
	}
	_ = s.CloseDBProxy()
	_ = s.CloseNetNS()
	_ = s.CloseProxy()
	_ = s.CloseLLMProxy()
	_ = s.UnmountWorkspace()
	_ = a.sessions.Destroy(s.ID)
}

func clonePolicy(p *policy.Policy) *policy.Policy {
	if p == nil {
		return nil
	}
	clone := *p
	clone.Metadata = append([]policy.RuleMetadata(nil), p.Metadata...)
	clone.FileRules = append([]policy.FileRule(nil), p.FileRules...)
	clone.NetworkRules = append([]policy.NetworkRule(nil), p.NetworkRules...)
	clone.CommandRules = append([]policy.CommandRule(nil), p.CommandRules...)
	clone.UnixRules = append([]policy.UnixSocketRule(nil), p.UnixRules...)
	clone.RegistryRules = append([]policy.RegistryRule(nil), p.RegistryRules...)
	clone.SignalRules = append([]policy.SignalRule(nil), p.SignalRules...)
	clone.DnsRedirectRules = append([]policy.DnsRedirectRule(nil), p.DnsRedirectRules...)
	clone.ConnectRedirectRules = append([]policy.ConnectRedirectRule(nil), p.ConnectRedirectRules...)
	clone.PackageRules = append([]policy.PackageRule(nil), p.PackageRules...)
	clone.HTTPServices = append([]policy.HTTPService(nil), p.HTTPServices...)
	if p.EnvInject != nil {
		clone.EnvInject = make(map[string]string, len(p.EnvInject))
		for k, v := range p.EnvInject {
			clone.EnvInject[k] = v
		}
	}
	if p.Providers != nil {
		clone.Providers = make(map[string]yaml.Node, len(p.Providers))
		for k, v := range p.Providers {
			clone.Providers[k] = v
		}
	}
	return &clone
}
