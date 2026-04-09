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
	"github.com/agentsh/agentsh/internal/proxy"
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
	secretsFetcher SecretFetcher,
	services []ServiceConfig,
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
	if len(services) > 0 && secretsFetcher != nil {
		table, secretsCleanup, err := BootstrapCredentials(ctx, secretsFetcher, services)
		if err != nil {
			_ = p.Stop(ctx)
			return "", nil, fmt.Errorf("bootstrap credentials: %w", err)
		}

		// Register hooks: leak guard first, then creds substitution.
		leakGuard := proxy.NewLeakGuardHook(table, logger)
		credsSub := proxy.NewCredsSubHook(table)
		p.HookRegistry().Register("", leakGuard)
		p.HookRegistry().Register("", credsSub)

		sess.SetCredsTable(table, secretsCleanup)
		LogSecretsInitialized(logger, sess.ID, len(services))
	}

	// Store in session only after all setup (including bootstrap) succeeds.
	sess.SetLLMProxy(proxyURL, closeFn)
	sess.SetProxyInstance(p)

	return proxyURL, closeFn, nil
}

// LLMProxyEnvVars returns the environment variables that should be set for
// the agent process to use the embedded LLM proxy.
//
// Returns nil if no LLM proxy is configured for the session.
func (s *Session) LLMProxyEnvVars() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.llmProxyURL == "" {
		return nil
	}

	return map[string]string{
		"ANTHROPIC_BASE_URL": s.llmProxyURL,
		"OPENAI_BASE_URL":    s.llmProxyURL,
		"AGENTSH_SESSION_ID": s.ID,
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
