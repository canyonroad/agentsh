package transport

import (
	"context"
	"errors"
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
// Send/encode failures during drain are otherwise swallowed: a broken
// conn cannot be fixed at this layer, and shutdown callers cannot act
// on a partial-flush diagnostic. The ONE EXCEPTION is
// ErrRecordLossEncountered: a loss marker in the drain set means the
// session has hit the terminal pre-Task-13 sentinel; runLive must see
// it so the run loop can latch fatal instead of silently completing
// Stop with the sentinel hidden behind a CloseSend (roborev #6131
// Medium). All other errors continue to be swallowed.
//
// runShutdown is only called from runLive — runReplaying and
// runConnecting each have their own exit paths and no buffered batcher
// to drain.
func (t *Transport) runShutdown(parent context.Context, b *Batcher, rdr *wal.Reader, drainDeadline time.Duration) error {
	var lossErr error
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
					if errors.Is(err, ErrRecordLossEncountered) {
						lossErr = err
					}
					break drainLoop
				}
				if err := t.conn.Send(msg); err != nil {
					break drainLoop
				}
			}
		}
	}
	if final := b.Drain(); final != nil {
		msg, err := encodeBatchMessageFn(final.Records)
		if err != nil {
			if errors.Is(err, ErrRecordLossEncountered) && lossErr == nil {
				lossErr = err
			}
		} else {
			_ = t.conn.Send(msg)
		}
	}
	_ = t.conn.CloseSend()
	return lossErr
}
