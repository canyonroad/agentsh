//go:build linux

package postgres

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

func copyLoopFixture(t *testing.T) (*proxyConn, *pgproto3.Frontend, *pgproto3.Backend) {
	t.Helper()
	pc, clientFE, _ := newSimpleQueryFixture(t)
	upClient, upProxy := net.Pipe()
	t.Cleanup(func() { _ = upClient.Close(); _ = upProxy.Close() })
	pc.state.upstream = upProxy
	pc.state.upstreamFE = pgproto3.NewFrontend(upProxy, upProxy)
	return pc, clientFE, pgproto3.NewBackend(upClient, upClient)
}

func TestCopyLoop_BulkLoad_PassesBytesAndExitsOnCopyDone(t *testing.T) {
	pc, clientFE, upstreamBE := copyLoopFixture(t)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I', Phase: statemachine.PhaseInCopyIn}

	clientDrain := make(chan struct{})
	go func() {
		defer close(clientDrain)
		for i := 0; i < 2; i++ {
			if _, err := clientFE.Receive(); err != nil {
				return
			}
		}
	}()

	gotUpstream := make(chan []byte, 1)
	go func() {
		var got []byte
		for {
			msg, err := upstreamBE.Receive()
			if err != nil {
				return
			}
			switch m := msg.(type) {
			case *pgproto3.CopyData:
				got = append(got, m.Data...)
			case *pgproto3.CopyDone:
				upstreamBE.Send(&pgproto3.CommandComplete{CommandTag: []byte("COPY 2")})
				upstreamBE.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				_ = upstreamBE.Flush()
				gotUpstream <- got
				return
			}
		}
	}()

	go func() {
		clientFE.Send(&pgproto3.CopyData{Data: []byte("row1\n")})
		clientFE.Send(&pgproto3.CopyData{Data: []byte("row2\n")})
		clientFE.Send(&pgproto3.CopyDone{})
		_ = clientFE.Flush()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := pc.runCopyLoop(ctx, effects.BulkOpIn)
	if err != nil {
		t.Fatalf("runCopyLoop: %v", err)
	}
	if got := <-gotUpstream; !bytes.Equal(got, []byte("row1\nrow2\n")) {
		t.Fatalf("upstream CopyData = %q", got)
	}
	if result.BytesIn != int64(len("row1\nrow2\n")) {
		t.Fatalf("BytesIn=%d want %d", result.BytesIn, len("row1\nrow2\n"))
	}
	if result.AffectedByStmt[0] == nil || *result.AffectedByStmt[0] != 2 {
		t.Fatalf("AffectedByStmt=%v want COPY 2", result.AffectedByStmt)
	}
	if pc.state.smState.Phase != statemachine.PhaseIdle {
		t.Fatalf("Phase=%v want idle", pc.state.smState.Phase)
	}
	<-clientDrain
}

func TestCopyLoop_BulkExport_PassesUpstreamBytes(t *testing.T) {
	pc, clientFE, upstreamBE := copyLoopFixture(t)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I', Phase: statemachine.PhaseInCopyOut}

	gotClient := make(chan []byte, 1)
	go func() {
		var got []byte
		for i := 0; i < 4; i++ {
			msg, err := clientFE.Receive()
			if err != nil {
				return
			}
			if cd, ok := msg.(*pgproto3.CopyData); ok {
				got = append(got, cd.Data...)
			}
		}
		gotClient <- got
	}()

	go func() {
		upstreamBE.Send(&pgproto3.CopyData{Data: []byte("hello\n")})
		upstreamBE.Send(&pgproto3.CopyData{Data: []byte("world\n")})
		upstreamBE.Send(&pgproto3.CopyDone{})
		upstreamBE.Send(&pgproto3.CommandComplete{CommandTag: []byte("COPY 2")})
		upstreamBE.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = upstreamBE.Flush()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := pc.runCopyLoop(ctx, effects.BulkOpOut)
	if err != nil {
		t.Fatalf("runCopyLoop: %v", err)
	}
	if got := <-gotClient; !bytes.Equal(got, []byte("hello\nworld\n")) {
		t.Fatalf("client CopyData = %q", got)
	}
	if result.BytesOut <= int64(len("hello\nworld\n")) {
		t.Fatalf("BytesOut=%d want > copied data length", result.BytesOut)
	}
}

func TestCopyLoop_BulkLoad_ClientTerminateSendsCopyFail(t *testing.T) {
	pc, clientFE, upstreamBE := copyLoopFixture(t)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I', Phase: statemachine.PhaseInCopyIn}

	sawCopyFail := make(chan bool, 1)
	go func() {
		for {
			msg, err := upstreamBE.Receive()
			if err != nil {
				return
			}
			if _, ok := msg.(*pgproto3.CopyFail); ok {
				sawCopyFail <- true
				return
			}
		}
	}()

	go func() {
		clientFE.Send(&pgproto3.CopyData{Data: []byte("row1\n")})
		clientFE.Send(&pgproto3.Terminate{})
		_ = clientFE.Flush()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := pc.runCopyLoop(ctx, effects.BulkOpIn); err == nil {
		t.Fatal("runCopyLoop should return an error on client Terminate")
	}
	if !<-sawCopyFail {
		t.Fatal("expected CopyFail upstream")
	}
}

func TestCopyLoop_BulkExport_MidCopyErrorResponse_ExitsCleanly(t *testing.T) {
	pc, clientFE, upstreamBE := copyLoopFixture(t)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I', Phase: statemachine.PhaseInCopyOut}

	go func() {
		for i := 0; i < 3; i++ {
			if _, err := clientFE.Receive(); err != nil {
				return
			}
		}
	}()

	go func() {
		upstreamBE.Send(&pgproto3.CopyData{Data: []byte("partial")})
		upstreamBE.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "57014", Message: "canceled"})
		upstreamBE.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = upstreamBE.Flush()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := pc.runCopyLoop(ctx, effects.BulkOpOut)
	if err != nil {
		t.Fatalf("runCopyLoop: %v", err)
	}
	if result.ErrorCode != "57014" {
		t.Fatalf("ErrorCode=%q want 57014", result.ErrorCode)
	}
	if pc.state.smState.Phase != statemachine.PhaseIdle {
		t.Fatalf("Phase=%v want idle", pc.state.smState.Phase)
	}
}
