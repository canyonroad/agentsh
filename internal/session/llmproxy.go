package session

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/mcpregistry"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/proxy"
	"gopkg.in/yaml.v3"
)

// StartLLMProxy creates and starts an embedded LLM proxy for the session.
// It configures the proxy with the provided settings and stores the proxy URL
// and cleanup function in the session.
//
// The function returns the proxy URL that the agent should use for LLM API calls,
// a cleanup function to stop the proxy, and any error that occurred.
func StartLLMProxy(
	sess *Session,
	proxyCfg config.ProxyConfig,
	dlpCfg config.DLPConfig,
	storageCfg config.LLMStorageConfig,
	mcpCfg config.SandboxMCPConfig,
	storagePath string,
	logger *slog.Logger,
	providers map[string]yaml.Node,
	httpServices []policy.HTTPService,
	envInject map[string]string,
) (string, func() error, error) {
	if sess == nil {
		return "", nil, fmt.Errorf("session is nil")
	}

	// In mcp-only mode, force DLP disabled and body storage on.
	if proxyCfg.IsMCPOnly() {
		dlpCfg.Mode = "disabled"
		storageCfg.StoreBodies = true
	}

	// Build the proxy config
	cfg := proxy.Config{
		SessionID: sess.ID,
		Proxy:     proxyCfg,
		DLP:       dlpCfg,
		Storage:   storageCfg,
		MCP:       mcpCfg,
	}

	// Create the proxy
	p, err := proxy.New(cfg, storagePath, logger)
	if err != nil {
		return "", nil, fmt.Errorf("create llm proxy: %w", err)
	}

	// Create MCP registry when any MCP feature needs it.
	needsRegistry := mcpCfg.EnforcePolicy ||
		proxyCfg.IsMCPOnly() ||
		mcpCfg.RateLimits.Enabled ||
		mcpCfg.VersionPinning.Enabled

	if needsRegistry {
		registry := mcpregistry.NewRegistry()
		// Pre-register declared network servers so their addresses are available for network detection.
		// Stdio servers are skipped — they have no network address and would falsely inflate
		// the distinct-server count (triggering premature OnMultiServer callbacks).
		for _, srv := range mcpCfg.Servers {
			if addr := extractAddr(srv); addr != "" {
				registry.Register(srv.ID, srv.Type, addr, nil)
			}
		}
		p.SetRegistry(registry)
		sess.SetMCPRegistry(registry)
	}

	// Start the proxy
	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		return "", nil, fmt.Errorf("start llm proxy: %w", err)
	}

	// Build the proxy URL
	addr := p.Addr()
	if addr == nil {
		// This shouldn't happen after successful Start, but handle it gracefully
		_ = p.Stop(ctx)
		return "", nil, fmt.Errorf("proxy address is nil after start")
	}
	proxyURL := fmt.Sprintf("http://%s", addr.String())

	// Create the cleanup function
	closeFn := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.Stop(ctx)
	}

	// Bootstrap credentials and register hooks if services are configured.
	// Done BEFORE storing on session so a failure leaves no stale state.
	if len(httpServices) > 0 {
		resolved, resolveErr := ResolveServiceConfigs(httpServices)
		if resolveErr != nil {
			_ = p.Stop(ctx)
			return "", nil, fmt.Errorf("resolve services: %w", resolveErr)
		}

		if resolved != nil {
			providerConfigs, provErr := ResolveProviderConfigs(providers)
			if provErr != nil {
				_ = p.Stop(ctx)
				return "", nil, fmt.Errorf("resolve providers: %w", provErr)
			}

			registry, regErr := BuildSecretsRegistry(ctx, providerConfigs)
			if regErr != nil {
				_ = p.Stop(ctx)
				return "", nil, fmt.Errorf("build secrets registry: %w", regErr)
			}

			table, secretsCleanup, bsErr := BootstrapCredentials(ctx, registry, resolved.ServiceConfigs)
			if bsErr != nil {
				_ = registry.Close()
				_ = p.Stop(ctx)
				return "", nil, fmt.Errorf("bootstrap credentials: %w", bsErr)
			}

			// Register hooks: leak guard first, then creds substitution (both global).
			leakGuard := proxy.NewLeakGuardHook(table, logger)
			credsSub := proxy.NewCredsSubHook(table, resolved.ScrubServices)
			p.HookRegistry().Register("", leakGuard)
			p.HookRegistry().Register("", credsSub)

			// Register per-service header injection hooks.
			for _, ih := range resolved.InjectHeaders {
				hook := proxy.NewHeaderInjectionHook(ih.ServiceName, ih.HeaderName, ih.Template, table)
				p.HookRegistry().Register(ih.ServiceName, hook)
			}

			// Wrap registry close into the secrets cleanup.
			origCleanup := secretsCleanup
			combinedCleanup := func() {
				origCleanup()
				_ = registry.Close()
			}
			sess.SetCredsTable(table, combinedCleanup)
			LogSecretsInitialized(logger, sess.ID, len(resolved.ServiceConfigs))
		}
	}

	// Store in session only after all setup (including bootstrap) succeeds.
	sess.SetLLMProxy(proxyURL, closeFn)
	sess.SetProxyInstance(p)

	return proxyURL, closeFn, nil
}

// proxyEnvVarer is the minimal interface that Session uses to fetch
// env vars from the proxy instance. The concrete type is *proxy.Proxy;
// Session holds it as interface{} to avoid an import cycle, so we
// type-assert against this local interface at read time.
type proxyEnvVarer interface {
	EnvVars() map[string]string
}

// LLMProxyEnvVars returns the environment variables that should be set for
// the agent process to use the embedded LLM proxy.
//
// When a proxy instance is attached to the session, this delegates to the
// proxy's EnvVars() so declared http_services (*_API_URL) are included.
// Falls back to the three legacy LLM base URLs when no proxy instance is
// attached (shouldn't happen in production, preserved for test paths that
// call SetLLMProxy without SetProxyInstance).
//
// Returns nil if no LLM proxy URL is configured for the session.
func (s *Session) LLMProxyEnvVars() map[string]string {
	s.mu.Lock()
	proxyURL := s.llmProxyURL
	proxyInst := s.llmProxy
	sessID := s.ID
	s.mu.Unlock()

	if proxyURL == "" {
		return nil
	}

	// Prefer the proxy's own env var builder — it includes the legacy
	// LLM URLs plus the declared http_services URLs.
	if p, ok := proxyInst.(proxyEnvVarer); ok {
		if env := p.EnvVars(); env != nil {
			return env
		}
	}

	// Fallback for sessions with a URL but no attached proxy instance.
	return map[string]string{
		"ANTHROPIC_BASE_URL": proxyURL,
		"OPENAI_BASE_URL":    proxyURL,
		"AGENTSH_SESSION_ID": sessID,
	}
}

// extractAddr parses host:port from a server declaration's URL.
// Returns "" for stdio servers or unparseable URLs.
func extractAddr(srv config.MCPServerDeclaration) string {
	if srv.Type == "stdio" || srv.URL == "" {
		return ""
	}
	u, err := url.Parse(srv.URL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, port)
}
