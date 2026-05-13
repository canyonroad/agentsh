package service

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateBundle_RequiresSessionID(t *testing.T) {
	_, err := GenerateBundle(Config{Services: []Service{validBundleService(t, "appdb")}}, BundleOptions{
		Mode: UnavoidabilityEnforce,
	})
	if !errors.Is(err, ErrBundleInvalidOptions) {
		t.Fatalf("GenerateBundle err = %v, want ErrBundleInvalidOptions", err)
	}
}

func TestGenerateBundle_RejectsTCPListenerInEnforce(t *testing.T) {
	svc := validBundleService(t, "appdb")
	svc.Listen = Listener{Kind: "tcp", Host: "127.0.0.1", Port: 15432}

	_, err := GenerateBundle(Config{Services: []Service{svc}}, BundleOptions{
		SessionID:      "sess-1",
		ProxySessionID: "db-proxy-sess",
		Mode:           UnavoidabilityEnforce,
	})
	if err == nil {
		t.Fatal("GenerateBundle returned nil error")
	}
	if !strings.Contains(err.Error(), "spec section 12.5") {
		t.Fatalf("error = %v, want spec section 12.5 reference", err)
	}
}

func validBundleService(t *testing.T, name string) Service {
	t.Helper()

	return Service{
		Name:    name,
		Family:  "postgres",
		Dialect: "postgres",
		Upstream: Endpoint{
			Host: "db.internal",
			Port: 5432,
		},
		Listen: Listener{
			Kind: "unix",
			Path: filepath.Join(t.TempDir(), "sessions", "sess-1", "db", name+".sock"),
		},
		TLSMode: "terminate_reissue",
	}
}
