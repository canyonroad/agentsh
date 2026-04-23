package transport

import (
	"context"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// runShutdown performs an orderly Live-state shutdown: pull additional
// records via TryNext up to drainDeadline, flush the batcher, and
// CloseSend the conn. It does NOT Close the conn (full teardown) —
// CloseSend signals "no more client frames" to the server so it can
// process pending acks and close the stream; the run loop's return
// path (and any subsequent Stop/cancel) owns the full teardown.
//
// Drain contract:
//   - If drainDeadline is zero or negative, no additional records are
//     pulled; the batcher is drained (any currently buffered records
//     are flushed as one final batch) and CloseSend fires immediately.
//   - Otherwise, TryNext is called in a tight loop until the deadline
//     elapses, the reader reports ok=false (caught up), the reader
//     reports an error, or adding a record to the batcher produces a
//     full batch whose Send fails. Send/encode failures during drain
//     are swallowed (the caller's intent is "best-effort flush"; a
//     broken conn cannot be fixed at this layer).
//
// runShutdown is only called from runLive — runReplaying and
// runConnecting each have their own exit paths and no buffered batcher
// to drain.
func (t *Transport) runShutdown(parent context.Context, b *Batcher, rdr *wal.Reader, drainDeadline time.Duration) {
	if drainDeadline > 0 {
		ctx, cancel := context.WithTimeout(parent, drainDeadline)
		defer cancel()
	drainLoop:
		for {
			if ctx.Err() != nil {
				break
			}
			rec, ok, err := rdr.TryNext()
			if err != nil {
				break
			}
			if !ok {
				break
			}
			if outBatch := b.Add(rec); outBatch != nil {
				msg, err := encodeBatchMessage(outBatch.Records)
				if err != nil {
					break drainLoop
				}
				if err := t.conn.Send(msg); err != nil {
					break drainLoop
				}
			}
		}
	}
	if final := b.Drain(); final != nil {
		if msg, err := encodeBatchMessage(final.Records); err == nil {
			_ = t.conn.Send(msg)
		}
	}
	_ = t.conn.CloseSend()
}
