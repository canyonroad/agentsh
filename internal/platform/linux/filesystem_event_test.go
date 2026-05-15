//go:build linux

package linux

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestEventEmitterAppendEventDropsAfterChannelClosed(t *testing.T) {
	ch := make(chan platform.IOEvent, 1)
	close(ch)

	emitter := &eventEmitter{
		eventChan: ch,
		sessionID: "session-1",
	}

	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "file_stat",
		Path:      "/workspace/app.py",
		Operation: "stat",
		Policy: &types.PolicyInfo{
			Decision:          types.DecisionAudit,
			EffectiveDecision: types.DecisionAllow,
			Rule:              "audit-app-files",
		},
	}

	if err := emitter.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent returned error: %v", err)
	}
}
