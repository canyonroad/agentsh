package netmonitor

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestHandleConnectDeniedWrites403(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		NetworkRules: []policy.NetworkRule{
			{Name: "deny-all", Decision: "deny", Domains: []string{"*"}},
		},
	}
	engine, err := policy.NewEngine(pol, false)
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

	_, _ = client.Write([]byte("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"))
	buf := make([]byte, 128)
	n, _ := client.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "403 Forbidden") {
		t.Fatalf("expected 403 response, got %q", resp)
	}
	client.Close()
	<-done
	if len(em.events) == 0 || em.events[0].Type != "net_connect" || em.events[0].Policy.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("expected deny event recorded, got %+v", em.events)
	}
}

func TestHandleHTTPAllowsAndEmitsEvents(t *testing.T) {
	srv := newHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	em := &stubEmitter{}
	p := &Proxy{sessionID: "s", emit: em}

	client, server := net.Pipe()
	defer client.Close()

	go func() {
		_ = p.handleConn(server)
	}()

	req := "GET http://" + hostPort + "/foo HTTP/1.1\r\nHost: " + hostPort + "\r\n\r\n"
	_, _ = client.Write([]byte(req))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBuf := make([]byte, 256)
	n, _ := client.Read(respBuf)
	resp := string(respBuf[:n])
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("expected 200 OK, got %q", resp)
	}
	if len(em.events) < 2 {
		t.Fatalf("expected events recorded, got %+v", em.events)
	}
}

// newHTTPServer forces IPv4 localhost to avoid environments that disallow IPv6 loopback binds.
func newHTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		httpListenSkip.Do(func() {
			t.Logf("skipping HTTP proxy tests: listen tcp4 disallowed (%v)", err)
		})
		t.Skipf("skipping HTTP proxy tests: listen tcp4 disallowed (%v)", err)
	}
	srv := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

var httpListenSkip sync.Once
