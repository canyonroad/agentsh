//go:build linux

package statemachine

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestPhase_String(t *testing.T) {
	cases := []struct {
		p    Phase
		want string
	}{
		{PhasePreAuth, "pre_auth"},
		{PhaseIdle, "idle"},
		{PhaseInQuery, "in_query"},
		{PhaseInTx, "in_tx"},
		{PhaseInTxError, "in_tx_error"},
		{PhaseInCopyIn, "in_copy_in"},
		{PhaseInCopyOut, "in_copy_out"},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("Phase(%d).String() = %q; want %q", c.p, got, c.want)
		}
	}
}

func TestConnState_ZeroValue(t *testing.T) {
	var s ConnState
	if s.Phase != PhasePreAuth {
		t.Errorf("zero Phase = %v; want PhasePreAuth", s.Phase)
	}
	if s.Absorbing {
		t.Error("zero Absorbing should be false")
	}
	if s.UpstreamDirtySinceSync {
		t.Error("zero UpstreamDirtySinceSync should be false")
	}
	if !s.TxStartedAt.IsZero() {
		t.Error("zero TxStartedAt should be zero time.Time")
	}
	var _ time.Time = s.TxStartedAt
}

// Compile-time assertions that every concrete type implements Action.
var (
	_ Action = (*ActionForward)(nil)
	_ Action = (*ActionSynthError)(nil)
	_ Action = (*ActionSynthReadyForQuery)(nil)
	_ Action = (*ActionSynthParseComplete)(nil)
	_ Action = (*ActionSynthBindComplete)(nil)
	_ Action = (*ActionSuppress)(nil)
	_ Action = (*ActionInjectRollback)(nil)
	_ Action = (*ActionDrainUntilRFQ)(nil)
	_ Action = (*ActionClose)(nil)
	_ Action = (*ActionTrackUpstreamRFQ)(nil)
)

func TestActions_DiffableByCmp(t *testing.T) {
	a := []Action{
		&ActionSynthError{SQLState: "42501", Message: "denied"},
		&ActionSynthReadyForQuery{Status: 'I'},
	}
	b := []Action{
		&ActionSynthError{SQLState: "42501", Message: "denied"},
		&ActionSynthReadyForQuery{Status: 'I'},
	}
	if diff := cmp.Diff(a, b); diff != "" {
		t.Errorf("expected equal; diff=%s", diff)
	}
	c := []Action{
		&ActionSynthError{SQLState: "42501", Message: "denied"},
		&ActionSynthReadyForQuery{Status: 'T'},
	}
	if diff := cmp.Diff(a, c); diff == "" {
		t.Errorf("expected diff; got empty")
	}
}

func TestActionTrackUpstreamRFQ_Field(t *testing.T) {
	a := &ActionTrackUpstreamRFQ{Status: 'T'}
	if a.Status != 'T' {
		t.Errorf("Status=%q want 'T'", a.Status)
	}
}

func TestFrame_Kind(t *testing.T) {
	cases := []struct {
		f    Frame
		want FrameKind
	}{
		{&QueryFrame{SQL: "SELECT 1"}, FrameKindQuery},
		{&ParseFrame{Name: "s1", SQL: "SELECT $1"}, FrameKindParse},
		{&BindFrame{Portal: "p1", Statement: "s1"}, FrameKindBind},
		{&DescribeFrame{ObjectType: 'S', Name: "s1"}, FrameKindDescribe},
		{&ExecuteFrame{Portal: "p1"}, FrameKindExecute},
		{&SyncFrame{}, FrameKindSync},
		{&FlushFrame{}, FrameKindFlush},
		{&CloseFrame{ObjectType: 'S', Name: "s1"}, FrameKindClose},
		{&TerminateFrame{}, FrameKindTerminate},
	}
	for _, c := range cases {
		if got := c.f.Kind(); got != c.want {
			t.Errorf("Kind() = %v; want %v", got, c.want)
		}
	}
}

func TestCacheView_FakeRecords(t *testing.T) {
	f := NewFakeCacheView()
	f.Put("s1", CacheValue{Verb: "SELECT"})
	v, ok := f.Get("s1")
	if !ok {
		t.Fatal("Get miss")
	}
	if v.Verb != "SELECT" {
		t.Fatalf("Verb=%q", v.Verb)
	}
	f.Delete("s1")
	if _, ok := f.Get("s1"); ok {
		t.Fatal("Get after Delete should miss")
	}
	if got := f.Recorded(); len(got) != 4 {
		t.Fatalf("Recorded len=%d want 4", len(got))
	}
}
