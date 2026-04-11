package netmonitor

import (
	"net"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

// newEngineWithDeclaredGitHub builds a minimal policy.Engine with a
// declared http_service for api.github.com. A permissive network rule
// is added so that a direct request would otherwise be permitted; that
// ensures the test exercises the declared-service fail-closed gate
// rather than an incidental network_rules deny.
func newEngineWithDeclaredGitHub(t *testing.T, allowDirect bool) *policy.Engine {
	t.Helper()
	pol := &policy.Policy{
		Version: 1,
		NetworkRules: []policy.NetworkRule{
			// Use an explicit glob matching api.github.com so we don't
			// rely on '*' crossing dot separators. gobwas/glob compiled
			// with a '.' separator treats '*' as one-segment only.
			{Name: "allow-github", Decision: "allow", Domains: []string{"*.github.com", "api.github.com"}},
		},
		HTTPServices: []policy.HTTPService{{
			Name:        "github",
			Upstream:    "https://api.github.com",
			ExposeAs:    "GITHUB_API_URL",
			AllowDirect: allowDirect,
			Default:     "allow",
		}},
	}
	if err := policy.ValidateHTTPServices(pol.HTTPServices); err != nil {
		t.Fatalf("validate: %v", err)
	}
	e, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// TestHandleConnect_DeniesDeclaredHost verifies that CONNECT to a host
// declared as an http_services upstream is rejected with a 403 and a
// guidance message pointing at the service's env var, even when
// network_rules would otherwise permit it.
func TestHandleConnect_DeniesDeclaredHost(t *testing.T) {
	eng := newEngineWithDeclaredGitHub(t, false)
	em := &stubEmitter{}
	p := &Proxy{sessionID: "s", policy: eng, emit: em}

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		_ = p.handleConn(server)
		close(done)
	}()

	_, _ = client.Write([]byte("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n"))
	buf := make([]byte, 512)
	n, _ := client.Read(buf)
	resp := string(buf[:n])

	if !strings.Contains(resp, "403 Forbidden") {
		t.Fatalf("expected 403 response, got %q", resp)
	}
	if !strings.Contains(resp, "GITHUB_API_URL") {
		t.Errorf("expected response to mention GITHUB_API_URL, got %q", resp)
	}
	client.Close()
	<-done

	var gotDeniedEvent bool
	for _, ev := range em.events {
		if ev.Type != "http_service_denied_direct" {
			continue
		}
		gotDeniedEvent = true
		if ev.Fields["service_name"] != "github" {
			t.Errorf("expected service_name=github, got %v", ev.Fields["service_name"])
		}
		if ev.Fields["env_var"] != "GITHUB_API_URL" {
			t.Errorf("expected env_var=GITHUB_API_URL, got %v", ev.Fields["env_var"])
		}
		if ev.Domain != "api.github.com" {
			t.Errorf("expected domain api.github.com, got %q", ev.Domain)
		}
	}
	if !gotDeniedEvent {
		t.Errorf("expected http_service_denied_direct event, events=%+v", em.events)
	}
}

// TestHandleHTTP_DeniesDeclaredHost verifies that a plain HTTP (non-CONNECT)
// proxy request targeting a declared http_services upstream is also rejected
// with a 403 and the env var guidance. This is the path used by curl when
// asked to speak http:// through the proxy.
func TestHandleHTTP_DeniesDeclaredHost(t *testing.T) {
	eng := newEngineWithDeclaredGitHub(t, false)
	em := &stubEmitter{}
	p := &Proxy{sessionID: "s", policy: eng, emit: em}

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		_ = p.handleConn(server)
		close(done)
	}()

	req := "GET http://api.github.com/user HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
	_, _ = client.Write([]byte(req))
	buf := make([]byte, 512)
	n, _ := client.Read(buf)
	resp := string(buf[:n])

	if !strings.Contains(resp, "403 Forbidden") {
		t.Fatalf("expected 403 response, got %q", resp)
	}
	if !strings.Contains(resp, "GITHUB_API_URL") {
		t.Errorf("expected response to mention GITHUB_API_URL, got %q", resp)
	}
	client.Close()
	<-done

	var gotDeniedEvent bool
	for _, ev := range em.events {
		if ev.Type != "http_service_denied_direct" {
			continue
		}
		gotDeniedEvent = true
		if ev.Fields["service_name"] != "github" {
			t.Errorf("expected service_name=github, got %v", ev.Fields["service_name"])
		}
		if ev.Fields["env_var"] != "GITHUB_API_URL" {
			t.Errorf("expected env_var=GITHUB_API_URL, got %v", ev.Fields["env_var"])
		}
	}
	if !gotDeniedEvent {
		t.Errorf("expected http_service_denied_direct event, events=%+v", em.events)
	}
}

// TestHandleConnect_AllowDirectSkipsCheck verifies that a declared service
// with allow_direct: true is NOT blocked by the fail-closed gate. The
// connection should proceed past the gate; we can't complete a CONNECT
// in the pipe harness (no upstream listener), but we MUST not see a 403
// whose body mentions the env var — that's the signature of the
// fail-closed block we're opting out of.
func TestHandleConnect_AllowDirectSkipsCheck(t *testing.T) {
	eng := newEngineWithDeclaredGitHub(t, true)
	em := &stubEmitter{}
	p := &Proxy{sessionID: "s", policy: eng, emit: em}

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		_ = p.handleConn(server)
		close(done)
	}()

	_, _ = client.Write([]byte("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n"))
	buf := make([]byte, 512)
	n, _ := client.Read(buf)
	resp := string(buf[:n])

	// Must not be the fail-closed 403 with the env var hint.
	if strings.Contains(resp, "GITHUB_API_URL") {
		t.Errorf("allow_direct=true should skip the fail-closed block, got %q", resp)
	}
	// A http_service_denied_direct event must NOT be emitted.
	for _, ev := range em.events {
		if ev.Type == "http_service_denied_direct" {
			t.Errorf("unexpected http_service_denied_direct event when allow_direct=true: %+v", ev)
		}
	}
	client.Close()
	<-done
}
