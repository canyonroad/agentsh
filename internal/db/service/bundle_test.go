package service

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strconv"
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
	if netRule.Name != "db-appdb-deny-direct" {
		t.Fatalf("network rule name = %q", netRule.Name)
	}
	if len(netRule.Domains) != 1 || netRule.Domains[0] != "db.internal" {
		t.Fatalf("network domains = %+v", netRule.Domains)
	}
	if len(netRule.Ports) != 1 || netRule.Ports[0] != 5432 {
		t.Fatalf("network ports = %+v", netRule.Ports)
	}
	if netRule.Decision != "deny" {
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
	assertMetadata(t, b.Metadata, "db-appdb-deny-direct", "appdb", BypassModeTCPDirect, "db.internal:5432")
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
		"db-appdb-deny-direct",
		"db-warehouse-db-deny-direct",
	} {
		if !seen[name] {
			t.Fatalf("missing metadata for %q in %+v", name, b.Metadata)
		}
	}
}

func TestGenerateBundle_RedirectTargetDeniedByNetworkPolicy(t *testing.T) {
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
	if string(network.EffectiveDecision) != "deny" {
		t.Fatalf("CheckNetwork decision = %+v, want deny for direct DB egress", network)
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

func TestGenerateBundle_AddsResolvedIPDenies(t *testing.T) {
	resolver := &fakeIPResolver{ips: []net.IP{
		net.ParseIP("10.0.0.15"),
		net.ParseIP("2001:db8::15"),
	}}
	b, err := GenerateBundle(Config{Services: []Service{validBundleService(t, "appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
		Resolver:         resolver,
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	if len(resolver.calls) != 1 || resolver.calls[0] != "db.internal" {
		t.Fatalf("resolver calls = %+v, want [db.internal]", resolver.calls)
	}
	if !resolver.sawDeadline {
		t.Fatal("resolver context had no deadline")
	}

	assertNetworkRule(t, b.Policy.NetworkRules, "db-appdb-deny-ip-10-0-0-15", "10.0.0.15/32", 5432)
	assertNetworkRule(t, b.Policy.NetworkRules, "db-appdb-deny-ip-2001-db8-15", "2001:db8::15/128", 5432)
	assertMetadata(t, b.Metadata, "db-appdb-deny-ip-10-0-0-15", "appdb", BypassModeDNSAlias, "10.0.0.15:5432")
	assertMetadata(t, b.Metadata, "db-appdb-deny-ip-2001-db8-15", "appdb", BypassModeDNSAlias, "[2001:db8::15]:5432")
}

func TestGenerateBundle_SkipsDNSExpansionForIPLiteralUpstream(t *testing.T) {
	resolver := &fakeIPResolver{ips: []net.IP{net.ParseIP("10.0.0.15")}}
	svc := validBundleService(t, "appdb")
	svc.Upstream.Host = "10.0.0.20"

	b, err := GenerateBundle(Config{Services: []Service{svc}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
		Resolver:         resolver,
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	if len(resolver.calls) != 0 {
		t.Fatalf("resolver calls = %+v, want none", resolver.calls)
	}
	if len(b.Policy.NetworkRules) != 1 {
		t.Fatalf("network rules = %d, want only core direct deny", len(b.Policy.NetworkRules))
	}
}

func TestGenerateBundle_DNSFailureObserveWarns(t *testing.T) {
	b, err := GenerateBundle(Config{Services: []Service{validBundleService(t, "appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityObserve,
		IncludeToolRules: false,
		Resolver:         &fakeIPResolver{err: errors.New("dns unavailable")},
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	assertDNSExpansionWarning(t, b.Warnings, "appdb", "db.internal")
}

func TestGenerateBundle_DNSFailureEnforceFailsUnlessAllowed(t *testing.T) {
	_, err := GenerateBundle(Config{Services: []Service{validBundleService(t, "appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
		Resolver:         &fakeIPResolver{err: errors.New("dns unavailable")},
	})
	if err == nil {
		t.Fatal("GenerateBundle returned nil error")
	}

	b, err := GenerateBundle(Config{Services: []Service{validBundleService(t, "appdb")}}, BundleOptions{
		SessionID:                  "sess-1",
		ProxySessionID:             "db-proxy-sess",
		Mode:                       UnavoidabilityEnforce,
		IncludeToolRules:           false,
		AllowHostnameOnlyInEnforce: true,
		Resolver:                   &fakeIPResolver{err: errors.New("dns unavailable")},
	})
	if err != nil {
		t.Fatalf("GenerateBundle with hostname-only override: %v", err)
	}
	assertDNSExpansionWarning(t, b.Warnings, "appdb", "db.internal")
}

func TestGenerateBundle_ResolvedIPRuleNamesUseCollisionResistantServiceParts(t *testing.T) {
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
		Resolver:         &fakeIPResolver{ips: []net.IP{net.ParseIP("10.0.0.15")}},
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	for _, svc := range services {
		ruleName := "db-app-db-" + ruleNameHash(svc.Name) + "-deny-ip-10-0-0-15"
		destination := net.JoinHostPort("10.0.0.15", strconv.Itoa(svc.Upstream.Port))
		assertMetadata(t, b.Metadata, ruleName, svc.Name, BypassModeDNSAlias, destination)
	}
	seen := map[string]bool{}
	for _, m := range b.Metadata {
		if seen[m.RuleName] {
			t.Fatalf("duplicate metadata rule name %q in %+v", m.RuleName, b.Metadata)
		}
		seen[m.RuleName] = true
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

type fakeIPResolver struct {
	ips         []net.IP
	err         error
	calls       []string
	sawDeadline bool
}

func (f *fakeIPResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	f.calls = append(f.calls, host)
	if _, ok := ctx.Deadline(); ok {
		f.sawDeadline = true
	}
	return f.ips, f.err
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

func assertNetworkRule(t *testing.T, got []policy.NetworkRule, name, cidr string, port int) {
	t.Helper()
	for _, rule := range got {
		if rule.Name != name {
			continue
		}
		if len(rule.CIDRs) != 1 || rule.CIDRs[0] != cidr {
			t.Fatalf("network rule %q CIDRs = %+v, want [%s]", name, rule.CIDRs, cidr)
		}
		if len(rule.Ports) != 1 || rule.Ports[0] != port {
			t.Fatalf("network rule %q ports = %+v, want [%d]", name, rule.Ports, port)
		}
		if rule.Decision != "deny" {
			t.Fatalf("network rule %q decision = %q, want deny", name, rule.Decision)
		}
		return
	}
	t.Fatalf("missing network rule %q in %+v", name, got)
}

func assertDNSExpansionWarning(t *testing.T, got []BundleWarning, service, host string) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("warnings = %+v, want one warning", got)
	}
	if got[0].Code != "DNS_EXPANSION_FAILED" {
		t.Fatalf("warning code = %q, want DNS_EXPANSION_FAILED", got[0].Code)
	}
	if got[0].Service != service {
		t.Fatalf("warning service = %q, want %q", got[0].Service, service)
	}
	if !strings.Contains(got[0].Message, host) {
		t.Fatalf("warning message = %q, want host %q", got[0].Message, host)
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
