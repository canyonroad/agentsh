package service

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
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

func TestGenerateBundle_SingleServiceCoreRules(t *testing.T) {
	b, err := GenerateBundle(Config{Services: []Service{validBundleService(t, "appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	if len(b.Policy.ConnectRedirectRules) != 1 {
		t.Fatalf("connect redirects = %d, want 1", len(b.Policy.ConnectRedirectRules))
	}
	redirect := b.Policy.ConnectRedirectRules[0]
	if redirect.Name != "db-appdb-redirect" {
		t.Fatalf("redirect name = %q", redirect.Name)
	}
	if redirect.RedirectToUnix == "" {
		t.Fatal("redirect_to_unix is empty")
	}
	if redirect.RedirectTo != "" {
		t.Fatalf("redirect_to = %q, want empty", redirect.RedirectTo)
	}

	if len(b.Policy.NetworkRules) != 1 {
		t.Fatalf("network rules = %d, want 1", len(b.Policy.NetworkRules))
	}
	netRule := b.Policy.NetworkRules[0]
	if netRule.Name != "db-appdb-allow-redirect" {
		t.Fatalf("network rule name = %q", netRule.Name)
	}
	if len(netRule.Domains) != 1 || netRule.Domains[0] != "db.internal" {
		t.Fatalf("network domains = %+v", netRule.Domains)
	}
	if len(netRule.Ports) != 1 || netRule.Ports[0] != 5432 {
		t.Fatalf("network ports = %+v", netRule.Ports)
	}
	if netRule.Decision != "allow" {
		t.Fatalf("network decision = %q", netRule.Decision)
	}

	if len(b.Policy.UnixRules) != 1 {
		t.Fatalf("unix rules = %d, want 1", len(b.Policy.UnixRules))
	}
	if b.Policy.UnixRules[0].Decision != "deny" {
		t.Fatalf("unix decision = %q", b.Policy.UnixRules[0].Decision)
	}

	if len(b.Metadata) != len(b.Policy.Metadata) {
		t.Fatalf("Bundle.Metadata length = %d, Policy.Metadata length = %d", len(b.Metadata), len(b.Policy.Metadata))
	}
	assertMetadata(t, b.Metadata, "db-appdb-redirect", "appdb", BypassModeTCPDirect, "db.internal:5432")
	assertMetadata(t, b.Metadata, "db-appdb-allow-redirect", "appdb", BypassModeTCPDirect, "db.internal:5432")
	assertMetadata(t, b.Metadata, "db-appdb-deny-local-postgres-sockets", "appdb", BypassModeUnixSocket, "postgres-local-sockets")
}

func TestGenerateBundle_MultipleServicesHaveStableNames(t *testing.T) {
	app := validBundleService(t, "appdb")
	warehouse := validBundleService(t, "warehouse-db")
	warehouse.Upstream.Host = "warehouse.internal"
	warehouse.Upstream.Port = 15432
	warehouse.Listen.Path = filepath.Join(t.TempDir(), "db", "warehouse.sock")

	b, err := GenerateBundle(Config{Services: []Service{app, warehouse}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	seen := map[string]bool{}
	for _, m := range b.Metadata {
		if seen[m.RuleName] {
			t.Fatalf("duplicate metadata rule name %q", m.RuleName)
		}
		seen[m.RuleName] = true
	}
	for _, name := range []string{
		"db-appdb-redirect",
		"db-warehouse-db-redirect",
		"db-appdb-allow-redirect",
		"db-warehouse-db-allow-redirect",
	} {
		if !seen[name] {
			t.Fatalf("missing metadata for %q in %+v", name, b.Metadata)
		}
	}
}

func TestGenerateBundle_RedirectTargetAllowedByNetworkPolicy(t *testing.T) {
	b, err := GenerateBundle(Config{Services: []Service{validBundleService(t, "appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	engine, err := policy.NewEngine(&b.Policy, false, true)
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}

	redirect := engine.EvaluateConnectRedirect("db.internal:5432")
	if !redirect.Matched || redirect.RedirectToUnix == "" {
		t.Fatalf("EvaluateConnectRedirect = %+v", redirect)
	}
	network := engine.CheckNetwork("db.internal", 5432)
	if string(network.EffectiveDecision) != "allow" {
		t.Fatalf("CheckNetwork decision = %+v, want allow so CONNECT can dial redirected unix target", network)
	}
}

func TestGenerateBundle_CollidingSanitizedServiceNamesAreUnique(t *testing.T) {
	services := []Service{
		validBundleService(t, "app_db"),
		validBundleService(t, "app-db"),
		validBundleService(t, "app/db"),
	}
	for i := range services {
		services[i].Listen.Path = filepath.Join(t.TempDir(), "db", services[i].Name+".sock")
		services[i].Upstream.Port = 5432 + i
	}

	b, err := GenerateBundle(Config{Services: services}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	seen := map[string]bool{}
	for _, m := range b.Metadata {
		if seen[m.RuleName] {
			t.Fatalf("duplicate metadata rule name %q in %+v", m.RuleName, b.Metadata)
		}
		seen[m.RuleName] = true
	}
	if len(seen) != len(b.Metadata) {
		t.Fatalf("unique metadata names = %d, metadata = %d", len(seen), len(b.Metadata))
	}
}

func TestGenerateBundle_PolicyCompiles(t *testing.T) {
	b, err := GenerateBundle(Config{Services: []Service{validBundleService(t, "appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	if err := b.Policy.Validate(); err != nil {
		t.Fatalf("Policy.Validate: %v", err)
	}
	if _, err := policy.NewEngine(&b.Policy, false, true); err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
}

func assertMetadata(t *testing.T, got []policy.RuleMetadata, ruleName, service, mode, destination string) {
	t.Helper()
	for _, m := range got {
		if m.RuleName == ruleName {
			if m.Source != RuleSourceDBUnavoidability || m.DBService != service || m.BypassMode != mode || m.Destination != destination {
				t.Fatalf("metadata for %q = %+v", ruleName, m)
			}
			return
		}
	}
	t.Fatalf("missing metadata for rule %q in %+v", ruleName, got)
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
