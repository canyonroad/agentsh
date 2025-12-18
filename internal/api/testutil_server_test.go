package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newHTTPTestServerOrSkip(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("httptest server listen not permitted in this environment: %v", err)
		}
		t.Fatalf("listen: %v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

