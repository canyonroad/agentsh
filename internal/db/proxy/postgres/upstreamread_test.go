//go:build linux

package postgres

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

func TestParseCommandTag(t *testing.T) {
	cases := []struct {
		tag               string
		wantRows, wantAff *int64
	}{
		{"SELECT 7", i64ptr(7), nil},
		{"INSERT 0 5", nil, i64ptr(5)},
		{"UPDATE 3", nil, i64ptr(3)},
		{"DELETE 2", nil, i64ptr(2)},
		{"MOVE 0", nil, i64ptr(0)},
		{"COPY 4", nil, i64ptr(4)},
		{"CREATE TABLE", nil, nil},
		{"BEGIN", nil, nil},
		{"COMMIT", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.tag, func(t *testing.T) {
			gotRows, gotAff := parseCommandTag(tc.tag)
			if !i64eq(gotRows, tc.wantRows) || !i64eq(gotAff, tc.wantAff) {
				t.Fatalf("parseCommandTag(%q) = (%v, %v) want (%v, %v)",
					tc.tag, ptrToStr(gotRows), ptrToStr(gotAff), ptrToStr(tc.wantRows), ptrToStr(tc.wantAff))
			}
		})
	}
}

func i64ptr(v int64) *int64 { return &v }
func i64eq(a, b *int64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
func ptrToStr(p *int64) string {
	if p == nil {
		return "nil"
	}
	return fmt.Sprintf("%d", *p)
}

// upstreamReadFixture wires a proxyConn with both client and upstream pipes
// for testing forwardUpstreamUntilRFQ. The returned scriptFn writes a sequence
// of backend frames to the upstream-side pipe (asynchronously, so the test
// can call forwardUpstreamUntilRFQ which reads them). drainClient drains the
// client-side pipe in the background so writes don't block.
func upstreamReadFixture(t *testing.T) (pc *proxyConn, scriptUpstream func([]pgproto3.BackendMessage), clientFE *pgproto3.Frontend) {
	pc, fe, _ := newSimpleQueryFixture(t)
	clientFE = fe
	up1, up2 := net.Pipe()
	t.Cleanup(func() { _ = up1.Close(); _ = up2.Close() })
	pc.state.upstream = up2
	pc.state.upstreamFE = pgproto3.NewFrontend(up2, up2)
	scriptUpstream = func(msgs []pgproto3.BackendMessage) {
		go func() {
			be := pgproto3.NewBackend(up1, up1)
			for _, m := range msgs {
				be.Send(m)
			}
			_ = be.Flush()
		}()
	}
	return pc, scriptUpstream, clientFE
}

func TestForwardUpstreamUntilRFQ_HappyPath(t *testing.T) {
	pc, scriptUpstream, clientFE := upstreamReadFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'

	// Drain client side so backend writes from forwardUpstreamUntilRFQ unblock.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			if _, err := clientFE.Receive(); err != nil {
				return
			}
		}
	}()

	scriptUpstream([]pgproto3.BackendMessage{
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("a")}}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("1")}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("2")}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r, err := pc.forwardUpstreamUntilRFQ(ctx, time.Now(), 16)
	if err != nil {
		t.Fatalf("forwardUpstreamUntilRFQ: %v", err)
	}
	if len(r.RowsByStmt) != 1 || r.RowsByStmt[0] == nil || *r.RowsByStmt[0] != 2 {
		t.Fatalf("RowsByStmt = %v want [2]", r.RowsByStmt)
	}
	if len(r.AffectedByStmt) != 1 || r.AffectedByStmt[0] != nil {
		t.Fatalf("AffectedByStmt = %v want [nil]", r.AffectedByStmt)
	}
	if r.ErrorCode != "" {
		t.Fatalf("ErrorCode = %q want empty", r.ErrorCode)
	}
	if pc.state.smState.LastUpstreamRFQ != 'I' {
		t.Fatalf("lastUpstreamRFQ = %q want 'I'", pc.state.smState.LastUpstreamRFQ)
	}
}

func TestForwardUpstreamUntilRFQ_MultiStmt(t *testing.T) {
	pc, scriptUpstream, clientFE := upstreamReadFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'

	go func() {
		for {
			if _, err := clientFE.Receive(); err != nil {
				return
			}
		}
	}()

	scriptUpstream([]pgproto3.BackendMessage{
		&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 3")},
		&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 5")},
		&pgproto3.ReadyForQuery{TxStatus: 'T'},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r, err := pc.forwardUpstreamUntilRFQ(ctx, time.Now(), 64)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(r.AffectedByStmt) != 2 {
		t.Fatalf("AffectedByStmt = %v want 2 entries", r.AffectedByStmt)
	}
	if r.AffectedByStmt[0] == nil || *r.AffectedByStmt[0] != 3 {
		t.Fatalf("AffectedByStmt[0] = %v want 3", r.AffectedByStmt[0])
	}
	if r.AffectedByStmt[1] == nil || *r.AffectedByStmt[1] != 5 {
		t.Fatalf("AffectedByStmt[1] = %v want 5", r.AffectedByStmt[1])
	}
	if pc.state.smState.LastUpstreamRFQ != 'T' {
		t.Fatalf("lastUpstreamRFQ = %q want 'T'", pc.state.smState.LastUpstreamRFQ)
	}
}

func TestForwardUpstreamUntilRFQ_MidBatchError(t *testing.T) {
	pc, scriptUpstream, clientFE := upstreamReadFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'

	go func() {
		for {
			if _, err := clientFE.Receive(); err != nil {
				return
			}
		}
	}()

	scriptUpstream([]pgproto3.BackendMessage{
		&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 3")},
		&pgproto3.ErrorResponse{Severity: "ERROR", Code: "23505", Message: "dup key"},
		&pgproto3.ReadyForQuery{TxStatus: 'E'},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r, err := pc.forwardUpstreamUntilRFQ(ctx, time.Now(), 64)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.ErrorCode != "23505" {
		t.Fatalf("ErrorCode = %q want 23505", r.ErrorCode)
	}
	if pc.state.smState.LastUpstreamRFQ != 'E' {
		t.Fatalf("lastUpstreamRFQ = %q want 'E'", pc.state.smState.LastUpstreamRFQ)
	}
}

func TestForwardUpstreamUntilRFQ_YieldsOnCopyOutResponse(t *testing.T) {
	pc, scriptUpstream, clientFE := upstreamReadFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'

	clientGot := make(chan pgproto3.BackendMessage, 1)
	go func() {
		msg, err := clientFE.Receive()
		if err != nil {
			return
		}
		clientGot <- msg
	}()

	scriptUpstream([]pgproto3.BackendMessage{
		&pgproto3.CopyOutResponse{},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r, err := pc.forwardUpstreamUntilRFQ(ctx, time.Now(), 16)
	if err != nil {
		t.Fatalf("forwardUpstreamUntilRFQ: %v", err)
	}
	if !r.YieldedToCopyOut {
		t.Fatal("YieldedToCopyOut = false, want true")
	}
	if _, ok := (<-clientGot).(*pgproto3.CopyOutResponse); !ok {
		t.Fatal("client did not receive CopyOutResponse")
	}
}

func TestForwardUpstream_TracksTxStartedAt(t *testing.T) {
	pc, scriptUpstream, clientFE := upstreamReadFixture(t)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I'}

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			if _, err := clientFE.Receive(); err != nil {
				return
			}
		}
	}()

	scriptUpstream([]pgproto3.BackendMessage{
		&pgproto3.ReadyForQuery{TxStatus: 'T'},
	})
	if _, err := pc.forwardUpstreamUntilRFQ(context.Background(), time.Now(), 0); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if pc.state.smState.LastUpstreamRFQ != 'T' {
		t.Errorf("LastUpstreamRFQ=%q want 'T'", pc.state.smState.LastUpstreamRFQ)
	}
	if pc.state.smState.TxStartedAt.IsZero() {
		t.Error("TxStartedAt should be populated on I→T transition")
	}
	if pc.state.smState.Phase != statemachine.PhaseInTx {
		t.Errorf("Phase=%v want PhaseInTx", pc.state.smState.Phase)
	}
}

func TestForwardUpstream_TxStartedAt_PreservedOnTtoT(t *testing.T) {
	pc, scriptUpstream, clientFE := upstreamReadFixture(t)
	preserved := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	pc.state.smState = &statemachine.ConnState{
		LastUpstreamRFQ: 'T',
		Phase:           statemachine.PhaseInTx,
		TxStartedAt:     preserved,
	}

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			if _, err := clientFE.Receive(); err != nil {
				return
			}
		}
	}()

	scriptUpstream([]pgproto3.BackendMessage{
		&pgproto3.ReadyForQuery{TxStatus: 'T'},
	})
	if _, err := pc.forwardUpstreamUntilRFQ(context.Background(), time.Now(), 0); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if !pc.state.smState.TxStartedAt.Equal(preserved) {
		t.Errorf("TxStartedAt drifted on T→T: got %v want %v", pc.state.smState.TxStartedAt, preserved)
	}
}

func TestForwardUpstream_TxStartedAt_ClearedOnReturnToIdle(t *testing.T) {
	pc, scriptUpstream, clientFE := upstreamReadFixture(t)
	pc.state.smState = &statemachine.ConnState{
		LastUpstreamRFQ: 'T',
		Phase:           statemachine.PhaseInTx,
		TxStartedAt:     time.Now(),
	}

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			if _, err := clientFE.Receive(); err != nil {
				return
			}
		}
	}()

	scriptUpstream([]pgproto3.BackendMessage{
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	})
	if _, err := pc.forwardUpstreamUntilRFQ(context.Background(), time.Now(), 0); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if !pc.state.smState.TxStartedAt.IsZero() {
		t.Error("TxStartedAt should be cleared on T→I transition")
	}
	if pc.state.smState.Phase != statemachine.PhaseIdle {
		t.Errorf("Phase=%v want PhaseIdle", pc.state.smState.Phase)
	}
}
