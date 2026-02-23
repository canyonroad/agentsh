package session

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/llmproxy"
	"github.com/agentsh/agentsh/internal/mcpregistry"
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
	cfg := llmproxy.Config{
		SessionID: sess.ID,
		Proxy:     proxyCfg,
		DLP:       dlpCfg,
		Storage:   storageCfg,
		MCP:       mcpCfg,
	}

	// Create the proxy
	proxy, err := llmproxy.New(cfg, storagePath, logger)
	if err != nil {
		return "", nil, fmt.Errorf("create llm proxy: %w", err)
	}

	// Create MCP registry and inject into proxy if MCP policy is configured
	if mcpCfg.EnforcePolicy {
		registry := mcpregistry.NewRegistry()
		proxy.SetRegistry(registry)
		sess.SetMCPRegistry(registry)
	}

	// Start the proxy
	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		return "", nil, fmt.Errorf("start llm proxy: %w", err)
	}

	// Build the proxy URL
	addr := proxy.Addr()
	if addr == nil {
		// This shouldn't happen after successful Start, but handle it gracefully
		_ = proxy.Stop(ctx)
		return "", nil, fmt.Errorf("proxy address is nil after start")
	}
	proxyURL := fmt.Sprintf("http://%s", addr.String())

	// Create the cleanup function
	closeFn := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return proxy.Stop(ctx)
	}

	// Store in session
	sess.SetLLMProxy(proxyURL, closeFn)
	sess.SetProxyInstance(proxy)

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
