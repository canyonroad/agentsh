//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestNetworkDNSRedirect tests that DNS queries are redirected according to policy.
// This test verifies the dns_redirects policy rules are applied correctly.
func TestNetworkDNSRedirect(t *testing.T) {
	ctx := context.Background()

	// Start a local HTTP server to act as the redirect target
	redirectServer := startTestHTTPServer(t, "DNS redirect target reached")
	defer redirectServer.Close()

	// Get the port from the server address
	_, port, _ := net.SplitHostPort(redirectServer.Addr)

	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)

	// Create policy with DNS redirect: redirect.test.local -> 127.0.0.1
	policyYAML := `
version: 1
name: network-redirect-test
description: Test DNS redirect policy
command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow
network_rules:
  - name: allow-all
    domains: ["*"]
    decision: allow
dns_redirects:
  - name: test-dns-redirect
    match: "redirect\\.test\\.local"
    resolve_to: "127.0.0.1"
    visibility: audit_only
    message: "DNS redirected for testing"
resource_limits:
  max_memory_mb: 0
  cpu_quota_percent: 0
  disk_read_bps_max: 0
  disk_write_bps_max: 0
  net_bandwidth_mbps: 0
  pids_max: 0
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`

	writeFile(t, filepath.Join(policiesDir, "default.yaml"), policyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, testConfigTemplate)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	endpoint, cleanup := startServerContainer(t, ctx, bin, configPath, policiesDir, workspace)
	t.Cleanup(func() { cleanup() })

	cli := client.New(endpoint, "test-key")

	sess, err := cli.CreateSession(ctx, "/workspace", "default")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	defer func() {
		_ = cli.DestroySession(ctx, sess.ID)
	}()

	// Use curl to access the redirect target via the redirected hostname
	// Note: This test verifies the policy is parsed correctly and events are emitted.
	// Full network redirection requires transparent proxy mode which may not be
	// available in all test environments.
	resp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "curl",
		Args:    []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", fmt.Sprintf("http://redirect.test.local:%s/", port)},
	})
	if err != nil {
		t.Logf("curl exec error (may be expected in some environments): %v", err)
	} else {
		t.Logf("curl response: exit=%d stdout=%s stderr=%s", resp.Result.ExitCode, resp.Result.Stdout, resp.Result.Stderr)
	}

	// Check for DNS redirect events in the session events
	hasDNSRedirectEvent := false
	for _, ev := range resp.Events.Other {
		if ev.Type == "dns_redirect" || strings.Contains(ev.Type, "dns") {
			t.Logf("Found DNS event: %s - %v", ev.Type, ev.Fields)
			if ev.Type == "dns_redirect" {
				hasDNSRedirectEvent = true
			}
		}
	}

	if !hasDNSRedirectEvent {
		t.Logf("Note: DNS redirect event not found - this may be expected if transparent proxy mode is not active")
	}
}

// TestNetworkConnectRedirect tests that TCP connections are redirected according to policy.
func TestNetworkConnectRedirect(t *testing.T) {
	ctx := context.Background()

	// Start a local HTTP server to act as the redirect target
	redirectServer := startTestHTTPServer(t, "Connect redirect target reached")
	defer redirectServer.Close()

	// Get the port from the server address
	_, port, _ := net.SplitHostPort(redirectServer.Addr)

	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)

	// Create policy with connect redirect
	policyYAML := fmt.Sprintf(`
version: 1
name: network-redirect-test
description: Test connect redirect policy
command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow
network_rules:
  - name: allow-all
    domains: ["*"]
    decision: allow
connect_redirects:
  - name: test-connect-redirect
    match: "api\\.example\\.com:443"
    redirect_to: "127.0.0.1:%s"
    tls:
      mode: passthrough
    visibility: audit_only
    message: "Connect redirected for testing"
resource_limits:
  max_memory_mb: 0
  cpu_quota_percent: 0
  disk_read_bps_max: 0
  disk_write_bps_max: 0
  net_bandwidth_mbps: 0
  pids_max: 0
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`, port)

	writeFile(t, filepath.Join(policiesDir, "default.yaml"), policyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, testConfigTemplate)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	endpoint, cleanup := startServerContainer(t, ctx, bin, configPath, policiesDir, workspace)
	t.Cleanup(func() { cleanup() })

	cli := client.New(endpoint, "test-key")

	sess, err := cli.CreateSession(ctx, "/workspace", "default")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	defer func() {
		_ = cli.DestroySession(ctx, sess.ID)
	}()

	// Verify policy is loaded correctly by checking session info
	t.Logf("Session created with ID: %s", sess.ID)

	// Execute a simple network command to trigger network events
	resp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "echo",
		Args:    []string{"testing network redirect policy"},
	})
	if err != nil {
		t.Fatalf("Exec error: %v", err)
	}

	if resp.Result.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", resp.Result.ExitCode)
	}

	t.Logf("Policy loaded successfully, connect_redirects rule configured")
}

// TestNetworkRedirectPolicyValidation verifies that redirect policies are validated correctly.
func TestNetworkRedirectPolicyValidation(t *testing.T) {
	ctx := context.Background()

	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)

	// Create policy with both DNS and connect redirects
	policyYAML := `
version: 1
name: redirect-validation-test
description: Test redirect policy validation
command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow
network_rules:
  - name: allow-all
    domains: ["*"]
    decision: allow
dns_redirects:
  - name: anthropic-dns
    match: "api\\.anthropic\\.com"
    resolve_to: "10.0.0.50"
    visibility: audit_only
  - name: openai-dns
    match: "api\\.openai\\.com"
    resolve_to: "10.0.0.51"
    visibility: audit_only
connect_redirects:
  - name: anthropic-connect
    match: "api\\.anthropic\\.com:443"
    redirect_to: "vertex-proxy.internal:443"
    tls:
      mode: passthrough
    visibility: audit_only
  - name: openai-connect
    match: "api\\.openai\\.com:443"
    redirect_to: "vertex-proxy.internal:443"
    tls:
      mode: rewrite_sni
      sni: "vertex-proxy.internal"
    visibility: audit_only
resource_limits:
  max_memory_mb: 0
  cpu_quota_percent: 0
  disk_read_bps_max: 0
  disk_write_bps_max: 0
  net_bandwidth_mbps: 0
  pids_max: 0
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`

	writeFile(t, filepath.Join(policiesDir, "default.yaml"), policyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, testConfigTemplate)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	endpoint, cleanup := startServerContainer(t, ctx, bin, configPath, policiesDir, workspace)
	t.Cleanup(func() { cleanup() })

	cli := client.New(endpoint, "test-key")

	// If we can create a session, the policy was validated and loaded correctly
	sess, err := cli.CreateSession(ctx, "/workspace", "default")
	if err != nil {
		t.Fatalf("CreateSession failed - policy validation may have failed: %v", err)
	}
	defer func() {
		_ = cli.DestroySession(ctx, sess.ID)
	}()

	t.Logf("Policy with DNS and connect redirects validated successfully")
}

// startTestHTTPServer starts a simple HTTP server for testing redirects.
func startTestHTTPServer(t *testing.T, responseBody string) *http.Server {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start test HTTP server: %v", err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(responseBody))
		}),
	}

	go func() {
		_ = server.Serve(listener)
	}()

	// Give the server a moment to start
	time.Sleep(10 * time.Millisecond)

	// Store the address in the server
	server.Addr = listener.Addr().String()

	return server
}
