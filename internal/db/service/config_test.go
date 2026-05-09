package service

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseConfig_Minimal(t *testing.T) {
	in := []byte(`
services:
  - name: appdb
    family: postgres
    dialect: postgres
    upstream:
      host: db.internal
      port: 5432
    listen:
      kind: unix
      path: /run/agentsh/db/appdb.sock
    tls_mode: terminate_reissue
`)
	cfg, err := ParseConfig(in)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(cfg.Services) != 1 {
		t.Fatalf("got %d services, want 1", len(cfg.Services))
	}
	s := cfg.Services[0]
	if s.Name != "appdb" || s.Family != "postgres" || s.Dialect != "postgres" {
		t.Errorf("unexpected service: %+v", s)
	}
	if s.Upstream.Host != "db.internal" || s.Upstream.Port != 5432 {
		t.Errorf("unexpected upstream: %+v", s.Upstream)
	}
	if s.Listen.Kind != "unix" || s.Listen.Path != "/run/agentsh/db/appdb.sock" {
		t.Errorf("unexpected listen: %+v", s.Listen)
	}
	if s.TLSMode != "terminate_reissue" {
		t.Errorf("unexpected tls mode: %s", s.TLSMode)
	}
}

func TestParseConfig_Validate_RejectsUnknownDialect(t *testing.T) {
	in := []byte(`
services:
  - name: appdb
    family: postgres
    dialect: oracle
    upstream: {host: x, port: 1}
    listen: {kind: unix, path: /x}
    tls_mode: passthrough
`)
	if _, err := ParseConfig(in); err == nil {
		t.Fatal("expected error for unknown dialect")
	}
}

func TestParseConfig_Validate_RejectsUnknownTLSMode(t *testing.T) {
	in := []byte(`
services:
  - name: appdb
    family: postgres
    dialect: postgres
    upstream: {host: x, port: 1}
    listen: {kind: unix, path: /x}
    tls_mode: bad
`)
	if _, err := ParseConfig(in); err == nil {
		t.Fatal("expected error for unknown tls_mode")
	}
}

func TestParseConfig_Validate_RejectsEmptyName(t *testing.T) {
	in := []byte(`
services:
  - name: ""
    family: postgres
    dialect: postgres
    upstream: {host: x, port: 1}
    listen: {kind: unix, path: /x}
    tls_mode: passthrough
`)
	if _, err := ParseConfig(in); err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestParseConfig_Validate_RejectsDuplicateNames(t *testing.T) {
	in := []byte(`
services:
  - {name: appdb, family: postgres, dialect: postgres, upstream: {host: x, port: 1}, listen: {kind: unix, path: /a}, tls_mode: passthrough}
  - {name: appdb, family: postgres, dialect: postgres, upstream: {host: x, port: 1}, listen: {kind: unix, path: /b}, tls_mode: passthrough}
`)
	if _, err := ParseConfig(in); err == nil {
		t.Fatal("expected error for duplicate names")
	}
}

func TestParseConfig_RoundTrip(t *testing.T) {
	original := Config{
		Services: []Service{{
			Name: "appdb", Family: "postgres", Dialect: "postgres",
			Upstream: Endpoint{Host: "db", Port: 5432},
			Listen:   Listener{Kind: "unix", Path: "/run/x"},
			TLSMode:  "passthrough",
		}},
	}
	raw, err := yaml.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := ParseConfig(raw)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(parsed.Services) != 1 || parsed.Services[0].Name != "appdb" {
		t.Errorf("round-trip mismatch: %+v", parsed)
	}
}
