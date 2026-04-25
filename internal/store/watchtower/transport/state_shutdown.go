package transport

import (
	"context"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// runShutdown performs a BEST-EFFORT Live-state flush before the run
// loop tears the connection down. The contract is deliberately narrow:
//
//   - If drainDeadline > 0, TryNext is called in a tight loop until
//     the deadline elapses, the reader reports ok=false (caught up),
//     the reader reports an error, or an encode/Send failure breaks
//     the loop. The batcher is then Drain'd and any final batch is
//     sent.
//   - If drainDeadline <= 0, no additional records are pulled; only
//     the already-buffered batch (if any) is flushed.
//   - CloseSend is called last so the server observes the half-close.
//
// runShutdown does NOT guarantee that the server has processed the
// drained records before the run loop's subsequent full Close of the
// conn. The server-side contract for "graceful drain" would require
// the client to wait for the server's FIN (Recv loop returning EOF)
// between CloseSend and Close; this MVP does not implement that wait
// because the recv-goroutine integration still lives outside the Run
// loop (Task 22/27). In the current wiring, runLive's stopCh arm
// calls runShutdown and then immediately full-Close's the conn, so
// the server may see an abort instead of a graceful half-close for
// frames that were still in flight when CloseSend landed.
//
// Send/encode failures during drain are swallowed: a broken conn
// cannot be fixed at this layer, and shutdown callers cannot act on
// a partial-flush diagnostic. This is a documented observability gap
// — callers wanting assured delivery must rely on the ack stream,
// not on Stop's return.
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
				msg, err := encodeBatchMessageFn(outBatch.Records)
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
		if msg, err := encodeBatchMessageFn(final.Records); err == nil {
			_ = t.conn.Send(msg)
		}
	}
	_ = t.conn.CloseSend()
}
