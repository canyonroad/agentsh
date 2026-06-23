package netmonitor

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/config"
	dbevents "github.com/agentsh/agentsh/internal/db/events"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/mcpregistry"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/tor"
	"github.com/agentsh/agentsh/pkg/types"
)

type stubEmitter struct {
	events []types.Event
}

func (s *stubEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	s.events = append(s.events, ev)
	return nil
}
func (s *stubEmitter) Publish(ev types.Event) {
	s.events = append(s.events, ev)
}

type captureDBBypassEmitter struct {
	events    []types.Event
	published []types.Event
}

func (c *captureDBBypassEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	c.events = append(c.events, ev)
	return nil
}

func (c *captureDBBypassEmitter) Publish(ev types.Event) {
	c.published = append(c.published, ev)
}

func newNetmonitorDBUnavoidabilityEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "test-db-unavoidability",
		Metadata: []policy.RuleMetadata{
			{
				RuleName:    "db-appdb-deny-direct",
				Source:      dbservice.RuleSourceDBUnavoidability,
				DBService:   "appdb",
				BypassMode:  dbservice.BypassModeTCPDirect,
				Destination: "db.internal:5432",
			},
		},
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "db-appdb-deny-direct",
				Domains:  []string{"db.internal"},
				Ports:    []int{5432},
				Decision: "deny",
				Message:  "Direct database egress is blocked; use the AgentSH DB proxy",
			},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestMustAtoi(t *testing.T) {
	if got := mustAtoi("123", 9); got != 123 {
		t.Fatalf("want 123, got %d", got)
	}
	if got := mustAtoi("abc", 7); got != 7 {
		t.Fatalf("non-numeric should return default, got %d", got)
	}
	if got := mustAtoi("0", 5); got != 5 {
		t.Fatalf("zero should return default, got %d", got)
	}
}

func TestResolveAndEmitDNSIPBypassesLookup(t *testing.T) {
	p := &Proxy{emit: &stubEmitter{}}
	ip := p.resolveAndEmitDNS(context.Background(), "cmd", "127.0.0.1")
	if ip != "127.0.0.1" {
		t.Fatalf("expected ip passthrough, got %q", ip)
	}
}

func TestProxyEmitDBBypassAttempt(t *testing.T) {
	capture := &captureDBBypassEmitter{}
	p := &Proxy{
		sessionID: "session-db",
		policy:    newNetmonitorDBUnavoidabilityEngine(t),
	}
	p.SetDBBypassEmitter(dbevents.NewBypassEmitter(capture))

	p.emitDBBypassAttempt(context.Background(), "cmd-123", 0, "db-appdb-deny-direct", "blocked by policy")

	if len(capture.events) != 1 {
		t.Fatalf("db bypass events = %d, want 1", len(capture.events))
	}
	if len(capture.published) != 1 {
		t.Fatalf("published db bypass events = %d, want 1", len(capture.published))
	}
	ev := capture.events[0]
	if ev.Type != "db_bypass_attempt" {
		t.Fatalf("event type = %q, want db_bypass_attempt", ev.Type)
	}
	if ev.SessionID != "session-db" || ev.CommandID != "cmd-123" || ev.PID != 0 {
		t.Fatalf("event identity = session %q command %q pid %d", ev.SessionID, ev.CommandID, ev.PID)
	}
	if ev.Fields["process_identity"] != "command:cmd-123" {
		t.Fatalf("process_identity = %v, want command:cmd-123", ev.Fields["process_identity"])
	}
	if ev.Fields["rule_name"] != "db-appdb-deny-direct" || ev.Fields["bypass_mode"] != dbservice.BypassModeTCPDirect {
		t.Fatalf("db metadata fields = %+v", ev.Fields)
	}
	if ev.Fields["reason"] != "blocked by policy" {
		t.Fatalf("reason = %v", ev.Fields["reason"])
	}
}

func TestStartProxyInstallsInitialDBBypassEmitter(t *testing.T) {
	capture := &captureDBBypassEmitter{}
	p, _, err := StartProxy("127.0.0.1:0", "session-db", nil, newNetmonitorDBUnavoidabilityEngine(t), nil, &stubEmitter{}, dbevents.NewBypassEmitter(capture))
	if err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer p.Close()

	p.emitDBBypassAttempt(context.Background(), "", 0, "db-appdb-deny-direct", "blocked before publish")

	if len(capture.events) != 1 {
		t.Fatalf("db bypass events = %d, want 1", len(capture.events))
	}
}

func TestProxyUsesSessionPolicyEngineForNetworkChecks(t *testing.T) {
	basePolicy := &policy.Policy{
		Version: 1,
		Name:    "base-allow",
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "allow-db",
				Domains:  []string{"db.internal"},
				Ports:    []int{5432},
				Decision: "allow",
			},
		},
	}
	baseEngine, err := policy.NewEngine(basePolicy, false, true)
	if err != nil {
		t.Fatalf("NewEngine(base): %v", err)
	}
	mgr := session.NewManager(1)
	sess, err := mgr.CreateWithID("session-db-policy", t.TempDir(), "")
	if err != nil {
		t.Fatalf("CreateWithID: %v", err)
	}
	sess.SetPolicyEngine(newNetmonitorDBUnavoidabilityEngine(t))

	p := &Proxy{sessionID: sess.ID, sess: sess, policy: baseEngine}
	got := p.checkNetwork(context.Background(), "db.internal", 5432)
	if got.EffectiveDecision != types.DecisionDeny || got.Rule != "db-appdb-deny-direct" {
		t.Fatalf("checkNetwork = %+v, want session-local DB deny", got)
	}
}

func TestMaybeApproveTimeoutDenies(t *testing.T) {
	em := &stubEmitter{}
	mgr := approvals.New("remote", 1*time.Millisecond, em) // remote mode skips prompt goroutine

	p := &Proxy{approvals: mgr}
	dec := policy.Decision{
		PolicyDecision:    types.DecisionApprove,
		EffectiveDecision: types.DecisionApprove,
		Rule:              "r",
	}
	got := p.maybeApprove(context.Background(), "", dec, "network", "example.com")
	if got.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("expected deny when approval times out, got %v", got.EffectiveDecision)
	}
}

func TestMaybeApproveNoApprovalsLeavesDecision(t *testing.T) {
	p := &Proxy{approvals: nil}
	dec := policy.Decision{
		PolicyDecision:    types.DecisionApprove,
		EffectiveDecision: types.DecisionApprove,
	}
	got := p.maybeApprove(context.Background(), "", dec, "network", "example.com")
	if got.EffectiveDecision != types.DecisionApprove {
		t.Fatalf("expected unchanged decision when approvals manager missing, got %v", got.EffectiveDecision)
	}
}

func TestEmitConnectRedirectEvent(t *testing.T) {
	em := &stubEmitter{}
	p := &Proxy{
		sessionID: "test-session",
		emit:      em,
	}

	result := &policy.ConnectRedirectResult{
		Matched:    true,
		Rule:       "anthropic-redirect",
		RedirectTo: "vertex-proxy.internal:443",
		TLSMode:    "passthrough",
		Visibility: "audit_only",
		Message:    "Routed through Vertex",
	}

	p.emitConnectRedirectEvent(context.Background(), "cmd-123", "api.anthropic.com", "api.anthropic.com:443", 443, result)

	// Event should be emitted twice (AppendEvent + Publish)
	if len(em.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(em.events))
	}

	ev := em.events[0]
	if ev.Type != "connect_redirect" {
		t.Errorf("expected type 'connect_redirect', got %s", ev.Type)
	}
	if ev.SessionID != "test-session" {
		t.Errorf("expected sessionID 'test-session', got %s", ev.SessionID)
	}
	if ev.Domain != "api.anthropic.com" {
		t.Errorf("expected domain 'api.anthropic.com', got %s", ev.Domain)
	}
	if ev.Fields["redirect_to"] != "vertex-proxy.internal:443" {
		t.Errorf("expected redirect_to 'vertex-proxy.internal:443', got %v", ev.Fields["redirect_to"])
	}
	if ev.Fields["tls_mode"] != "passthrough" {
		t.Errorf("expected tls_mode 'passthrough', got %v", ev.Fields["tls_mode"])
	}
}

func TestEmitConnectRedirectEventWithSNI(t *testing.T) {
	em := &stubEmitter{}
	p := &Proxy{
		sessionID: "test-session",
		emit:      em,
	}

	result := &policy.ConnectRedirectResult{
		Matched:    true,
		Rule:       "sni-rewrite",
		RedirectTo: "vertex-proxy.internal:443",
		TLSMode:    "rewrite_sni",
		SNI:        "vertex-proxy.internal",
		Visibility: "audit_only",
		Message:    "SNI rewritten",
	}

	p.emitConnectRedirectEvent(context.Background(), "cmd-456", "api.openai.com", "api.openai.com:443", 443, result)

	if len(em.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(em.events))
	}

	ev := em.events[0]
	if ev.Fields["sni"] != "vertex-proxy.internal" {
		t.Errorf("expected sni 'vertex-proxy.internal', got %v", ev.Fields["sni"])
	}
	if ev.Fields["tls_mode"] != "rewrite_sni" {
		t.Errorf("expected tls_mode 'rewrite_sni', got %v", ev.Fields["tls_mode"])
	}
}

func TestEmitConnectRedirectEventWithUnixRedirect(t *testing.T) {
	em := &stubEmitter{}
	p := &Proxy{
		sessionID: "test-session",
		emit:      em,
	}
	socketPath := filepath.Join(t.TempDir(), "db", "appdb.sock")

	result := &policy.ConnectRedirectResult{
		Matched:        true,
		Rule:           "db-unix-redirect",
		RedirectToUnix: socketPath,
		TLSMode:        "passthrough",
		Visibility:     "audit_only",
		Message:        "Routed to local database socket",
	}

	p.emitConnectRedirectEvent(context.Background(), "cmd-789", "db.internal", "db.internal:5432", 5432, result)

	if len(em.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(em.events))
	}

	ev := em.events[0]
	if ev.Fields["redirect_to_unix"] != socketPath {
		t.Errorf("expected redirect_to_unix socket path, got %v", ev.Fields["redirect_to_unix"])
	}
	if _, ok := ev.Fields["redirect_to"]; ok {
		t.Errorf("did not expect redirect_to for unix redirect, got %v", ev.Fields["redirect_to"])
	}
}

func TestEmitConnectRedirectEventNilEmitter(t *testing.T) {
	p := &Proxy{
		sessionID: "test-session",
		emit:      nil,
	}

	result := &policy.ConnectRedirectResult{
		Matched:    true,
		Rule:       "test",
		RedirectTo: "proxy:443",
	}

	// Should not panic
	p.emitConnectRedirectEvent(context.Background(), "cmd", "example.com", "example.com:443", 443, result)
}

func TestConnectDialTarget_UnixRedirect(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), "agentsh", "sessions", "sess-1", "db", "appdb.sock")

	got := connectDialTarget(connectDialTargetInput{
		OriginalHostPort: "db.internal:5432",
		ResolvedIP:       "10.0.0.10",
		OriginalPort:     "5432",
		Redirect: &policy.ConnectRedirectResult{
			Matched:        true,
			RedirectToUnix: socketPath,
		},
	})
	if got.Network != "unix" {
		t.Fatalf("Network = %q, want unix", got.Network)
	}
	if got.Address != socketPath {
		t.Fatalf("Address = %q", got.Address)
	}
}

func TestHandleConnect_UnixRedirectNetConnectFields(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "db", "appdb.sock")
	pol := &policy.Policy{
		Version: 1,
		NetworkRules: []policy.NetworkRule{
			{Name: "allow-db", Decision: "allow", Domains: []string{"127.0.0.1"}, Ports: []int{5432}},
		},
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:           "db-unix-redirect",
				Match:          `^127\.0\.0\.1:5432$`,
				RedirectToUnix: socketPath,
				Visibility:     "audit_only",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	em := &stubEmitter{}
	p := &Proxy{sessionID: "s", policy: engine, emit: em}

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		_ = p.handleConn(server)
		close(done)
	}()

	_, _ = client.Write([]byte("CONNECT 127.0.0.1:5432 HTTP/1.1\r\nHost: 127.0.0.1:5432\r\n\r\n"))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _ := client.Read(buf)
	if !strings.Contains(string(buf[:n]), "502 Bad Gateway") {
		t.Fatalf("expected 502 response for missing unix socket, got %q", string(buf[:n]))
	}
	client.Close()
	<-done

	for _, ev := range em.events {
		if ev.Type != "net_connect" {
			continue
		}
		if ev.Fields["redirect_to_unix"] != socketPath {
			t.Fatalf("redirect_to_unix = %v, want %q in event %+v", ev.Fields["redirect_to_unix"], socketPath, ev)
		}
		if _, ok := ev.Fields["redirect_to"]; ok {
			t.Fatalf("did not expect redirect_to for unix redirect, got %v in event %+v", ev.Fields["redirect_to"], ev)
		}
		return
	}
	t.Fatalf("expected net_connect event, got %+v", em.events)
}

func TestHandleConnect_UnixRedirectBypassesOriginalNetworkDeny(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "db", "appdb.sock")
	pol := &policy.Policy{
		Version: 1,
		Metadata: []policy.RuleMetadata{
			{
				RuleName:   "deny-db-direct",
				Source:     "db_unavoidability",
				BypassMode: "tcp_direct",
			},
			{
				RuleName:   "db-unix-redirect",
				Source:     "db_unavoidability",
				BypassMode: "tcp_direct",
			},
		},
		NetworkRules: []policy.NetworkRule{
			{Name: "deny-db-direct", Decision: "deny", Domains: []string{"db.internal"}, Ports: []int{5432}},
		},
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:           "db-unix-redirect",
				Match:          `^db\.internal:5432$`,
				RedirectToUnix: socketPath,
				Visibility:     "audit_only",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	em := &stubEmitter{}
	p := &Proxy{sessionID: "s", policy: engine, emit: em}

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		_ = p.handleConn(server)
		close(done)
	}()

	_, _ = client.Write([]byte("CONNECT db.internal:5432 HTTP/1.1\r\nHost: db.internal:5432\r\n\r\n"))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _ := client.Read(buf)
	if !strings.Contains(string(buf[:n]), "502 Bad Gateway") {
		t.Fatalf("expected 502 response for missing unix socket, got %q", string(buf[:n]))
	}
	client.Close()
	<-done
}

func TestHandleConnect_UnixRedirectDoesNotBypassDBDenyWithoutRedirectMetadata(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "db", "appdb.sock")
	pol := &policy.Policy{
		Version: 1,
		Metadata: []policy.RuleMetadata{
			{
				RuleName:   "deny-db-direct",
				Source:     "db_unavoidability",
				BypassMode: "tcp_direct",
			},
		},
		NetworkRules: []policy.NetworkRule{
			{Name: "deny-db-direct", Decision: "deny", Domains: []string{"db.internal"}, Ports: []int{5432}},
		},
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:           "non-db-unix-redirect",
				Match:          `^db\.internal:5432$`,
				RedirectToUnix: socketPath,
				Visibility:     "audit_only",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	em := &stubEmitter{}
	p := &Proxy{sessionID: "s", policy: engine, emit: em}

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		_ = p.handleConn(server)
		close(done)
	}()

	_, _ = client.Write([]byte("CONNECT db.internal:5432 HTTP/1.1\r\nHost: db.internal:5432\r\n\r\n"))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _ := client.Read(buf)
	if !strings.Contains(string(buf[:n]), "403 Forbidden") {
		t.Fatalf("expected 403 response for non-DB redirect despite DB deny, got %q", string(buf[:n]))
	}
	client.Close()
	<-done
}

func TestHandleConnect_UnixRedirectDoesNotBypassNonDBNetworkDeny(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "db", "appdb.sock")
	pol := &policy.Policy{
		Version: 1,
		NetworkRules: []policy.NetworkRule{
			{Name: "deny-db-direct", Decision: "deny", Domains: []string{"db.internal"}, Ports: []int{5432}},
		},
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:           "db-unix-redirect",
				Match:          `^db\.internal:5432$`,
				RedirectToUnix: socketPath,
				Visibility:     "audit_only",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	em := &stubEmitter{}
	p := &Proxy{sessionID: "s", policy: engine, emit: em}

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		_ = p.handleConn(server)
		close(done)
	}()

	_, _ = client.Write([]byte("CONNECT db.internal:5432 HTTP/1.1\r\nHost: db.internal:5432\r\n\r\n"))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _ := client.Read(buf)
	if !strings.Contains(string(buf[:n]), "403 Forbidden") {
		t.Fatalf("expected 403 response for non-DB deny despite unix redirect, got %q", string(buf[:n]))
	}
	client.Close()
	<-done
}

func TestHandleConnect_NonRedirectedNetworkDenyReturnsForbidden(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		NetworkRules: []policy.NetworkRule{
			{Name: "deny-db-direct", Decision: "deny", Domains: []string{"127.0.0.1"}, Ports: []int{5432}},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	em := &stubEmitter{}
	p := &Proxy{sessionID: "s", policy: engine, emit: em}

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		_ = p.handleConn(server)
		close(done)
	}()

	_, _ = client.Write([]byte("CONNECT 127.0.0.1:5432 HTTP/1.1\r\nHost: 127.0.0.1:5432\r\n\r\n"))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _ := client.Read(buf)
	if !strings.Contains(string(buf[:n]), "403 Forbidden") {
		t.Fatalf("expected 403 response for denied non-redirected CONNECT, got %q", string(buf[:n]))
	}
	client.Close()
	<-done
}

func TestCheckConnectNetwork_DeniedApprovalWithUnixRedirectStaysDenied(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		NetworkRules: []policy.NetworkRule{
			{Name: "approve-db", Decision: "approve", Domains: []string{"db.internal"}, Ports: []int{5432}},
		},
	}
	engine, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	em := &stubEmitter{}
	p := &Proxy{
		sessionID: "s",
		policy:    engine,
		approvals: approvals.New("remote", 1*time.Millisecond, em),
		emit:      em,
	}

	dec := p.checkConnectNetwork(context.Background(), "cmd", "db.internal", "db.internal:5432", 5432, &policy.ConnectRedirectResult{
		Matched:        true,
		Rule:           "db-unix-redirect",
		RedirectToUnix: filepath.Join(t.TempDir(), "db", "appdb.sock"),
	})
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("EffectiveDecision = %v, want deny", dec.EffectiveDecision)
	}
}

func TestConnectDialTarget_TCPRedirectWinsOverResolvedIP(t *testing.T) {
	got := connectDialTarget(connectDialTargetInput{
		OriginalHostPort: "api.example.com:443",
		ResolvedIP:       "10.0.0.10",
		OriginalPort:     "443",
		Redirect: &policy.ConnectRedirectResult{
			Matched:    true,
			RedirectTo: "proxy.internal:8443",
		},
	})
	if got.Network != "tcp" {
		t.Fatalf("Network = %q, want tcp", got.Network)
	}
	if got.Address != "proxy.internal:8443" {
		t.Fatalf("Address = %q", got.Address)
	}
}

func TestConnectDialTarget_ResolvedIPFallback(t *testing.T) {
	got := connectDialTarget(connectDialTargetInput{
		OriginalHostPort: "api.example.com:443",
		ResolvedIP:       "10.0.0.10",
		OriginalPort:     "443",
	})
	if got.Network != "tcp" {
		t.Fatalf("Network = %q, want tcp", got.Network)
	}
	if got.Address != "10.0.0.10:443" {
		t.Fatalf("Address = %q", got.Address)
	}
}

func newSessionWithRegistry(addrs map[string]string) *session.Session {
	sess := &session.Session{ID: "test-session"}
	reg := mcpregistry.NewRegistry()
	for addr, serverID := range addrs {
		reg.Register(serverID, "http", addr, nil)
	}
	sess.SetMCPRegistry(reg)
	return sess
}

func TestMCPConnectionTaggingMatchesDomain(t *testing.T) {
	em := &stubEmitter{}
	sess := newSessionWithRegistry(map[string]string{
		"mcp.example.com:443": "test-server",
	})

	emitMCPConnectionIfMatched(context.Background(), sess, em, "test-session", "cmd-1", "MCP.Example.Com", "mcp.example.com:443", 443)

	var mcpEvents []types.Event
	for _, ev := range em.events {
		if ev.Type == "mcp_network_connection" {
			mcpEvents = append(mcpEvents, ev)
		}
	}
	if len(mcpEvents) != 2 { // AppendEvent + Publish
		t.Fatalf("expected 2 mcp_network_connection events, got %d", len(mcpEvents))
	}
	ev := mcpEvents[0]
	if ev.Domain != "mcp.example.com" {
		t.Errorf("expected lowercased domain 'mcp.example.com', got %q", ev.Domain)
	}
	if ev.Fields["server_id"] != "test-server" {
		t.Errorf("expected server_id 'test-server', got %v", ev.Fields["server_id"])
	}
	if ev.SessionID != "test-session" {
		t.Errorf("expected sessionID 'test-session', got %q", ev.SessionID)
	}
	if ev.CommandID != "cmd-1" {
		t.Errorf("expected commandID 'cmd-1', got %q", ev.CommandID)
	}
}

func TestMCPConnectionTaggingMatchesRemote(t *testing.T) {
	em := &stubEmitter{}
	sess := newSessionWithRegistry(map[string]string{
		"192.168.1.10:8080": "ip-server",
	})

	// domain won't match, but remote (IP:port) should
	emitMCPConnectionIfMatched(context.Background(), sess, em, "test-session", "cmd-2", "some-host", "192.168.1.10:8080", 8080)

	var mcpEvents []types.Event
	for _, ev := range em.events {
		if ev.Type == "mcp_network_connection" {
			mcpEvents = append(mcpEvents, ev)
		}
	}
	if len(mcpEvents) != 2 {
		t.Fatalf("expected 2 mcp_network_connection events, got %d", len(mcpEvents))
	}
	if mcpEvents[0].Fields["server_id"] != "ip-server" {
		t.Errorf("expected server_id 'ip-server', got %v", mcpEvents[0].Fields["server_id"])
	}
}

func TestMCPConnectionTaggingNoMatchSkips(t *testing.T) {
	em := &stubEmitter{}
	sess := newSessionWithRegistry(map[string]string{
		"mcp.example.com:443": "test-server",
	})

	emitMCPConnectionIfMatched(context.Background(), sess, em, "test-session", "cmd-3", "other.com", "other.com:443", 443)

	for _, ev := range em.events {
		if ev.Type == "mcp_network_connection" {
			t.Fatal("unexpected mcp_network_connection event for unregistered address")
		}
	}
}

func TestMCPConnectionTaggingNilSession(t *testing.T) {
	em := &stubEmitter{}

	// Should not panic
	emitMCPConnectionIfMatched(context.Background(), nil, em, "test-session", "cmd", "example.com", "example.com:443", 443)

	if len(em.events) != 0 {
		t.Fatalf("expected 0 events with nil session, got %d", len(em.events))
	}
}

func TestMCPConnectionTaggingNoRegistry(t *testing.T) {
	em := &stubEmitter{}
	sess := &session.Session{ID: "test-session"}
	// Don't set registry

	// Should not panic, no events emitted
	emitMCPConnectionIfMatched(context.Background(), sess, em, "test-session", "cmd", "example.com", "example.com:443", 443)

	if len(em.events) != 0 {
		t.Fatalf("expected 0 events with no registry, got %d", len(em.events))
	}
}

func TestProxyEmitNetEventThreatMetadata(t *testing.T) {
	em := &stubEmitter{}
	p := &Proxy{
		sessionID: "test-session",
		emit:      em,
	}
	dec := policy.Decision{
		PolicyDecision:    types.DecisionDeny,
		EffectiveDecision: types.DecisionDeny,
		Rule:              "threat-feed:urlhaus",
		ThreatFeed:        "urlhaus",
		ThreatMatch:       "evil.com",
		ThreatAction:      "deny",
	}
	ev := p.emitNetEvent(context.Background(), "net_connect", "cmd-1", "evil.com", "1.2.3.4:443", 443, dec, nil)
	if ev.Policy == nil {
		t.Fatal("expected Policy to be set")
	}
	if ev.Policy.ThreatFeed != "urlhaus" {
		t.Errorf("expected ThreatFeed %q, got %q", "urlhaus", ev.Policy.ThreatFeed)
	}
	if ev.Policy.ThreatMatch != "evil.com" {
		t.Errorf("expected ThreatMatch %q, got %q", "evil.com", ev.Policy.ThreatMatch)
	}
	if ev.Policy.ThreatAction != "deny" {
		t.Errorf("expected ThreatAction %q, got %q", "deny", ev.Policy.ThreatAction)
	}
}

func TestProxyEmitNetEventNoThreatMetadata(t *testing.T) {
	em := &stubEmitter{}
	p := &Proxy{
		sessionID: "test-session",
		emit:      em,
	}
	dec := policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionAllow,
		Rule:              "allow-all",
	}
	ev := p.emitNetEvent(context.Background(), "net_connect", "cmd-1", "safe.com", "1.2.3.4:443", 443, dec, nil)
	if ev.Policy == nil {
		t.Fatal("expected Policy to be set")
	}
	if ev.Policy.ThreatFeed != "" {
		t.Errorf("expected empty ThreatFeed, got %q", ev.Policy.ThreatFeed)
	}
	if ev.Policy.ThreatAction != "" {
		t.Errorf("expected empty ThreatAction, got %q", ev.Policy.ThreatAction)
	}
}

func TestMCPConnectionTaggingNilEmitter(t *testing.T) {
	sess := newSessionWithRegistry(map[string]string{
		"mcp.example.com:443": "test-server",
	})

	// Should not panic with nil emitter
	emitMCPConnectionIfMatched(context.Background(), sess, nil, "test-session", "cmd", "mcp.example.com", "mcp.example.com:443", 443)
}

// TestProxyHandleHTTPOnionRemapsVectorToOnionHTTP drives handleHTTP against a
// .onion host and asserts the emitted tor_control event carries
// vector == "onion_http". CheckNetworkCtx tags the Tor verdict with the
// onion_dns vector (EvalOnionName always returns VectorOnionDNS); the HTTP
// proxy path in handleHTTP (proxy.go:392-401) is the layer responsible for
// relabeling it to onion_http. This guards that remap — the only non-trivial
// logic among the five emit sites.
func TestProxyHandleHTTPOnionRemapsVectorToOnionHTTP(t *testing.T) {
	// Deny-by-default Tor policy with the onion vector on (zero TorConfig
	// resolves to enabled, mode=deny, all vectors true).
	torPol, err := tor.New(config.ResolveTorConfig(config.TorConfig{}))
	if err != nil {
		t.Fatalf("tor.New: %v", err)
	}

	// Allow-all base policy so the only deny comes from the Tor checker.
	basePolicy := &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		NetworkRules: []policy.NetworkRule{
			{Name: "allow-all", Domains: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(basePolicy, false, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	engine.SetTorPolicy(&tor.PolicyAdapter{Policy: torPol})

	sess := &session.Session{ID: "tor-session"}
	sess.SetCurrentProcessPID(4242)

	em := &stubEmitter{}
	p := &Proxy{sessionID: "tor-session", sess: sess, policy: engine, emit: em}

	// EvalOnionName matches any .onion suffix; use a syntactically valid
	// v3-style onion host.
	const onionHost = "abcdefghij234567abcdefghij234567abcdefghij234567abcdefghij234567.onion"
	req := httptest.NewRequest("GET", "http://"+onionHost+"/", nil)

	client, server := net.Pipe()

	done := make(chan struct{})
	go func() {
		_ = p.handleHTTP(server, req)
		close(done)
	}()

	// Drain the client side so handleHTTP's 403 write doesn't block the pipe.
	go func() {
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		for {
			if _, e := client.Read(buf); e != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleHTTP did not return")
	}
	client.Close()

	var torEv *types.Event
	for i := range em.events {
		if em.events[i].Type == "tor_control" {
			torEv = &em.events[i]
			break
		}
	}
	if torEv == nil {
		t.Fatalf("no tor_control event emitted; got %d events: %+v", len(em.events), em.events)
	}
	if torEv.Type != "tor_control" {
		t.Fatalf("event type = %q, want tor_control", torEv.Type)
	}
	if got := torEv.Fields["vector"]; got != "onion_http" {
		t.Fatalf("vector = %v, want onion_http (the handleHTTP remap from onion_dns)", got)
	}
	if torEv.PID != 4242 {
		t.Fatalf("event PID = %d, want 4242", torEv.PID)
	}
	if got := torEv.Fields["decision"]; got != "deny" {
		t.Fatalf("decision = %v, want deny", got)
	}
}
