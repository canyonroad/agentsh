package server_test

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/server"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
)

// TestBuildWatchtowerStore_DisabledReturnsNil verifies that the disabled
// case short-circuits without errors and returns a nil store.
func TestBuildWatchtowerStore_DisabledReturnsNil(t *testing.T) {
	s, err := server.BuildWatchtowerStoreForTest(context.Background(),
		config.AuditWatchtowerConfig{Enabled: false},
		compact.StubMapper{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s != nil {
		t.Fatal("expected nil store when disabled")
	}
}

// TestBuildWatchtowerStore_RejectsInvalidConfig verifies that validation runs
// and returns an error when the chain key source is not configured.
// (The config.AuditWatchtowerConfig schema uses Chain.KeyFile/KeyEnv for the
// HMAC key — the plan's HMACSecret field does not exist in the current schema.
// An empty Chain config causes the KMS provider to fail, which surfaces as an
// error before the store is opened.)
func TestBuildWatchtowerStore_RejectsInvalidConfig(t *testing.T) {
	cfg := config.AuditWatchtowerConfig{
		Enabled:   true,
		StateDir:  t.TempDir(),
		Endpoint:  "localhost:0",
		SessionID: "s",
		// Chain.KeyFile, KeyEnv, and all cloud-KMS sub-configs are empty
		// (no key source). The KMS provider will return an error.
		Auth: config.WatchtowerAuthConfig{
			TokenEnv: "AGENTSH_TEST_WTP_TOKEN_NOT_SET",
		},
	}
	_, err := server.BuildWatchtowerStoreForTest(context.Background(),
		cfg, compact.StubMapper{})
	if err == nil {
		t.Fatal("expected error for missing chain key source")
	}
	t.Logf("got expected error: %v", err)
}
