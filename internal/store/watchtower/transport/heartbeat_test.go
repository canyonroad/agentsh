package transport_test

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// TestHeartbeat_FiresAfterIdleInterval verifies the heartbeat ticker
// emits a Heartbeat ClientMessage after the configured interval of
// stream silence.
func TestHeartbeat_FiresAfterIdleInterval(t *testing.T) {
	conn := newFakeConn()
	stop := make(chan struct{})
	defer close(stop)

	go transport.RunHeartbeat(context.Background(), conn, 50*time.Millisecond, stop)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	select {
	case msg := <-conn.sendCh:
		if _, ok := msg.Msg.(*wtpv1.ClientMessage_Heartbeat); !ok {
			t.Fatalf("got %T, want Heartbeat", msg.Msg)
		}
	case <-ctx.Done():
		t.Fatal("no heartbeat sent within deadline")
	}
}
