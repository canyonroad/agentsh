package server_test

// Three-case integration test for AuditWatchtowerConfig.LogGoawayMessage
// (Task 27b). The test drives the full config.Load → Validate →
// applyDefaultsWithSource pipeline from real YAML fixtures written to a
// TempDir, then calls ResolveLogGoawayMessageForTest to assert the
// three-state resolution.
//
// Assertions:
//
//  1. unset: YAML omits log_goaway_message. After Load+Validate the field
//     MUST still be nil (applyDefaults must NOT have materialised it). The
//     resolved value must be false (the v1 default).
//
//  2. explicit false: YAML sets log_goaway_message: false. Field must be
//     non-nil pointing to false. Resolved value must be false.
//
//  3. explicit true: YAML sets log_goaway_message: true. Field must be
//     non-nil pointing to true. Resolved value must be true.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/server"
)

// minimalWatchtowerYAML produces a complete config YAML with
// audit.watchtower disabled (so validate() skips the endpoint/auth/chain
// checks). logGoawayLine is inserted verbatim into the watchtower block,
// e.g. "  log_goaway_message: true" or "" (omitted).
func minimalWatchtowerYAML(logGoawayLine string) string {
	return `
audit:
  watchtower:
    enabled: false
` + logGoawayLine + `
`
}

// loadCfgFromYAML writes the YAML to a temp file and loads it through the
// real config.Load pipeline (applyDefaults + validate).
func loadCfgFromYAML(t *testing.T, yaml string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

// TestLogGoawayMessage_NilSurvivesLoad verifies that when the YAML omits
// log_goaway_message, the field is still nil after the full Load+Validate
// pipeline (applyDefaults MUST NOT eagerly materialise it).
//
// It also verifies that ResolveLogGoawayMessageForTest returns false (the
// v1 PRD default) for the nil case, and labels it "nil".
func TestLogGoawayMessage_NilSurvivesLoad(t *testing.T) {
	cfg := loadCfgFromYAML(t, minimalWatchtowerYAML(""))

	// LOAD-BEARING: the nil state must survive through applyDefaults.
	if cfg.Audit.Watchtower.LogGoawayMessage != nil {
		t.Fatalf("expected LogGoawayMessage to be nil after Load (applyDefaults must not materialise it), got *%v",
			*cfg.Audit.Watchtower.LogGoawayMessage)
	}

	// Resolver must return the default (false) and label "nil".
	resolved, label := server.ResolveLogGoawayMessageForTest(cfg.Audit.Watchtower)
	if resolved != false {
		t.Errorf("unset case: expected resolved=false, got %v", resolved)
	}
	if label != "nil" {
		t.Errorf("unset case: expected label=%q, got %q", "nil", label)
	}
}

// TestLogGoawayMessage_ExplicitFalse verifies that log_goaway_message: false
// in YAML produces a non-nil *bool pointing to false, and that the resolver
// returns false with label "explicit_false".
func TestLogGoawayMessage_ExplicitFalse(t *testing.T) {
	cfg := loadCfgFromYAML(t, minimalWatchtowerYAML("    log_goaway_message: false"))

	if cfg.Audit.Watchtower.LogGoawayMessage == nil {
		t.Fatal("expected LogGoawayMessage to be non-nil for explicit false")
	}
	if *cfg.Audit.Watchtower.LogGoawayMessage != false {
		t.Fatalf("expected *LogGoawayMessage=false, got %v", *cfg.Audit.Watchtower.LogGoawayMessage)
	}

	resolved, label := server.ResolveLogGoawayMessageForTest(cfg.Audit.Watchtower)
	if resolved != false {
		t.Errorf("explicit_false case: expected resolved=false, got %v", resolved)
	}
	if label != "explicit_false" {
		t.Errorf("explicit_false case: expected label=%q, got %q", "explicit_false", label)
	}
}

// TestLogGoawayMessage_ExplicitTrue verifies that log_goaway_message: true
// in YAML produces a non-nil *bool pointing to true, and that the resolver
// returns true with label "explicit_true".
func TestLogGoawayMessage_ExplicitTrue(t *testing.T) {
	cfg := loadCfgFromYAML(t, minimalWatchtowerYAML("    log_goaway_message: true"))

	if cfg.Audit.Watchtower.LogGoawayMessage == nil {
		t.Fatal("expected LogGoawayMessage to be non-nil for explicit true")
	}
	if *cfg.Audit.Watchtower.LogGoawayMessage != true {
		t.Fatalf("expected *LogGoawayMessage=true, got %v", *cfg.Audit.Watchtower.LogGoawayMessage)
	}

	resolved, label := server.ResolveLogGoawayMessageForTest(cfg.Audit.Watchtower)
	if resolved != true {
		t.Errorf("explicit_true case: expected resolved=true, got %v", resolved)
	}
	if label != "explicit_true" {
		t.Errorf("explicit_true case: expected label=%q, got %q", "explicit_true", label)
	}
}
