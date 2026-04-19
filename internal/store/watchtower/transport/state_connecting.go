package transport

import (
	"context"
	"fmt"
)

// runConnecting establishes a stream and exchanges SessionInit/SessionAck.
// On success it returns StateReplaying. On dial failure or stream error it
// returns StateConnecting (the caller's run loop is responsible for backoff).
func (t *Transport) runConnecting(ctx context.Context) (State, error) {
	conn, err := t.opts.Dialer.Dial(ctx)
	if err != nil {
		return StateConnecting, fmt.Errorf("dial: %w", err)
	}
	t.conn = conn

	if err := conn.Send(t.sessionInit()); err != nil {
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

	t.ackedSequence = ack.AckHighWatermarkSeq
	t.ackedGeneration = ack.Generation
	return StateReplaying, nil
}

// RunOnce runs a single state transition for testing. Production code
// should use Run, which loops until Shutdown.
func (t *Transport) RunOnce(ctx context.Context, st State) State {
	switch st {
	case StateConnecting:
		next, _ := t.runConnecting(ctx)
		return next
	default:
		return StateShutdown
	}
}
