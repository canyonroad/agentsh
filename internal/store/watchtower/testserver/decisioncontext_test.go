package testserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1"
)

// TestAssertDecisionContext verifies the AssertDecisionContext helper:
// happy-path match and mismatch on hostname.
func TestAssertDecisionContext(t *testing.T) {
	init := &wtpv1.SessionInit{
		DecisionContext: &wtpv1.DecisionContext{
			Hostname: "h", User: &wtpv1.DecisionContext_User{Value: "eran@x"},
		},
	}
	if err := testserver.AssertDecisionContext(init, "h", "eran@x"); err != nil {
		t.Fatalf("AssertDecisionContext: %v", err)
	}
	if testserver.AssertDecisionContext(init, "other", "eran@x") == nil {
		t.Errorf("expected mismatch error on hostname")
	}
}

// TestAssertDecisionContext_NilDCFails verifies that a nil
// decision_context on the SessionInit returns an error.
func TestAssertDecisionContext_NilDCFails(t *testing.T) {
	init := &wtpv1.SessionInit{DecisionContext: nil}
	if err := testserver.AssertDecisionContext(init, "h", "u"); err == nil {
		t.Error("expected error for nil DecisionContext, got nil")
	}
}

// TestAssertDecisionContext_EmptyFieldSkipped verifies that passing ""
// for wantHostname or wantUser skips that field's comparison.
func TestAssertDecisionContext_EmptyFieldSkipped(t *testing.T) {
	init := &wtpv1.SessionInit{
		DecisionContext: &wtpv1.DecisionContext{
			Hostname: "host-a",
			User:     &wtpv1.DecisionContext_User{Value: "user-b"},
		},
	}
	// Pass "" for both — should succeed even though the values are non-empty.
	if err := testserver.AssertDecisionContext(init, "", ""); err != nil {
		t.Fatalf("AssertDecisionContext with empty wants: %v", err)
	}
	// Pass "" for user only — hostname check still fires.
	if err := testserver.AssertDecisionContext(init, "host-a", ""); err != nil {
		t.Fatalf("AssertDecisionContext hostname-only: %v", err)
	}
	// Pass "" for hostname only — user check still fires.
	if err := testserver.AssertDecisionContext(init, "", "user-b"); err != nil {
		t.Fatalf("AssertDecisionContext user-only: %v", err)
	}
}

// TestDecisionContext_ReachesWireSessionInit is an end-to-end test
// that proves a resolved DecisionContext set on transport.Options flows
// through to the SessionInit frame captured by the testserver.
//
// Mirrors TestStore_TransportSessionInitUsesConfiguredAlgorithm
// (internal/store/watchtower/integrity_test.go:556) but drives
// transport.Transport directly — no watchtower.Store needed — so the
// test lives in the testserver package without importing watchtower.
func TestDecisionContext_ReachesWireSessionInit(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	t.Cleanup(srv.Close)

	dc := &wtpv1.DecisionContext{
		Hostname: "itest-host",
		User: &wtpv1.DecisionContext_User{
			Value:  "itest@user",
			Source: wtpv1.UserSource_USER_SOURCE_TAILSCALE,
		},
	}

	tr, err := transport.New(transport.Options{
		Dialer:          srv.DialerFor(),
		AgentID:         "itest-agent",
		SessionID:       "itest-session",
		DecisionContext: dc,
	})
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	runDone := make(chan error, 1)
	go func() {
		runDone <- tr.Run(ctx,
			// rdrFactory: no WAL — return a nil Reader error so the
			// transport never enters Replaying/Live. The test only
			// needs the SessionInit handshake to complete.
			func(gen uint32, start uint64) (*wal.Reader, error) {
				// Block until cancelled — this keeps the transport
				// alive long enough to capture the SessionInit.
				<-ctx.Done()
				return nil, ctx.Err()
			},
			transport.LiveOptions{
				Batcher: transport.BatcherOptions{
					MaxRecords: 100,
					MaxBytes:   1 << 16,
					MaxAge:     50 * time.Millisecond,
				},
				MaxInflight:    8,
				HeartbeatEvery: time.Second,
			},
		)
	}()

	// Wait for the server to capture the first SessionInit.
	captured, err := srv.WaitForFirstSessionInit(5 * time.Second)
	if err != nil {
		t.Fatalf("WaitForFirstSessionInit: %v", err)
	}

	// Cancel the transport and wait for Run to exit cleanly.
	cancel()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("transport.Run did not exit after ctx cancel")
	}

	// Assert the captured SessionInit carried the expected DecisionContext.
	if err := testserver.AssertDecisionContext(captured, "itest-host", "itest@user"); err != nil {
		t.Fatalf("AssertDecisionContext: %v", err)
	}
}
