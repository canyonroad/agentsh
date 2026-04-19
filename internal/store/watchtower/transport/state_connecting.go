package transport

import (
	"context"
	"fmt"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// runConnecting establishes a stream and exchanges SessionInit/SessionAck.
// On success it returns StateReplaying. On dial failure or stream error it
// returns StateConnecting (the caller's run loop is responsible for backoff).
// On a server SessionAck rejection (accepted=false) or a programming error
// (e.g. SessionInit fails local validation) it returns StateShutdown — the
// session cannot recover from these via reconnect.
func (t *Transport) runConnecting(ctx context.Context) (State, error) {
	init := t.sessionInit()
	if err := wtpv1.ValidateSessionInit(init.GetSessionInit()); err != nil {
		return StateShutdown, fmt.Errorf("invalid SessionInit: %w", err)
	}

	conn, err := t.opts.Dialer.Dial(ctx)
	if err != nil {
		return StateConnecting, fmt.Errorf("dial: %w", err)
	}
	t.conn = conn

	if err := conn.Send(init); err != nil {
		_ = conn.CloseSend()
		t.conn = nil
		return StateConnecting, fmt.Errorf("send SessionInit: %w", err)
	}

	msg, err := conn.Recv()
	if err != nil {
		_ = conn.CloseSend()
		t.conn = nil
		return StateConnecting, fmt.Errorf("recv SessionAck: %w", err)
	}

	ack := msg.GetSessionAck()
	if ack == nil {
		_ = conn.CloseSend()
		t.conn = nil
		return StateConnecting, fmt.Errorf("expected SessionAck, got %T", msg.Msg)
	}

	if !ack.GetAccepted() {
		t.rejectReason = ack.GetRejectReason()
		_ = conn.CloseSend()
		t.conn = nil
		return StateShutdown, fmt.Errorf("session rejected: %s", ack.GetRejectReason())
	}

	t.ackedSequence = ack.GetAckHighWatermarkSeq()
	t.ackedGeneration = ack.GetGeneration()
	return StateReplaying, nil
}

// RunOnce runs a single state transition for testing. Production code
// should use Run, which loops until Shutdown. The error mirrors whatever
// the per-state handler surfaced so tests can assert on failure modes.
func (t *Transport) RunOnce(ctx context.Context, st State) (State, error) {
	switch st {
	case StateConnecting:
		return t.runConnecting(ctx)
	default:
		return StateShutdown, nil
	}
}
