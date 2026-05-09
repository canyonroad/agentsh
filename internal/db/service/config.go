package service

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Config is the top-level YAML schema for the `db_services` block per §9.1.
type Config struct {
	Services []Service `yaml:"services"`
}

// Service describes one declared database service. The supervisor uses this to
// install a Unix-socket listener and a destination rule that makes outbound
// access to (Upstream.Host, Upstream.Port) unavoidable for governed processes.
type Service struct {
	Name     string   `yaml:"name"`
	Family   string   `yaml:"family"`  // currently always "postgres"
	Dialect  string   `yaml:"dialect"` // postgres | aurora_postgres | redshift | cockroachdb
	Upstream Endpoint `yaml:"upstream"`
	Listen   Listener `yaml:"listen"`
	TLSMode  string   `yaml:"tls_mode"` // terminate_reissue | passthrough | terminate_plaintext_upstream
}

// Endpoint is a host:port pair — the upstream DB the proxy connects to.
type Endpoint struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// Listener describes where the proxy accepts client connections.
// Phase 1 supports kind="unix" (path) and kind="tcp" (host, port).
type Listener struct {
	Kind string `yaml:"kind"`
	Path string `yaml:"path,omitempty"`
	Host string `yaml:"host,omitempty"`
	Port int    `yaml:"port,omitempty"`
}

var (
	validFamilies = map[string]bool{"postgres": true}
	validDialects = map[string]bool{
		"postgres":        true,
		"aurora_postgres": true,
		"redshift":        true,
		"cockroachdb":     true,
	}
	validTLSModes = map[string]bool{
		"terminate_reissue":           true,
		"passthrough":                 true,
		"terminate_plaintext_upstream": true,
	}
	validListenKinds = map[string]bool{"unix": true, "tcp": true}
)

// ParseConfig parses YAML bytes into a validated Config.
// Returns an error if any service entry is malformed; valid entries are not
// returned partially.
func ParseConfig(raw []byte) (Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("yaml: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	seen := make(map[string]struct{}, len(c.Services))
	for i, s := range c.Services {
		if s.Name == "" {
			return fmt.Errorf("services[%d]: name is required", i)
		}
		if _, dup := seen[s.Name]; dup {
			return fmt.Errorf("services[%d]: duplicate service name %q", i, s.Name)
		}
		seen[s.Name] = struct{}{}
		if !validFamilies[s.Family] {
			return fmt.Errorf("services[%d] %s: family %q not supported", i, s.Name, s.Family)
		}
		if !validDialects[s.Dialect] {
			return fmt.Errorf("services[%d] %s: dialect %q not supported", i, s.Name, s.Dialect)
		}
		if !validTLSModes[s.TLSMode] {
			return fmt.Errorf("services[%d] %s: tls_mode %q not supported", i, s.Name, s.TLSMode)
		}
		if s.Upstream.Host == "" || s.Upstream.Port <= 0 {
			return fmt.Errorf("services[%d] %s: upstream host and port required", i, s.Name)
		}
		if !validListenKinds[s.Listen.Kind] {
			return fmt.Errorf("services[%d] %s: listen.kind %q not supported", i, s.Name, s.Listen.Kind)
		}
		if s.Listen.Kind == "unix" && s.Listen.Path == "" {
			return fmt.Errorf("services[%d] %s: listen.path required for kind=unix", i, s.Name)
		}
		if s.Listen.Kind == "tcp" && (s.Listen.Host == "" || s.Listen.Port <= 0) {
			return fmt.Errorf("services[%d] %s: listen.host and port required for kind=tcp", i, s.Name)
		}
	}
	return nil
}

// ErrNoServices is returned when the config block is empty.
var ErrNoServices = errors.New("no services declared")
