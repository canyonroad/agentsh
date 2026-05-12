//go:build linux

package statemachine

import (
	"testing"

	"pgregory.net/rapid"

	rootpolicy "github.com/agentsh/agentsh/internal/policy"

	"github.com/agentsh/agentsh/internal/db/policy"
)

// cachedRules is built once for property tests; rebuilding per iteration is slow.
var cachedRules *policy.RuleSet

func init() {
	src := `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
database_rules:
  - name: allow-read
    db_service: appdb
    operations: [read]
    decision: allow
  - name: block-delete
    db_service: appdb
    operations: [delete]
    decision: deny
  - name: block-delete-soft
    db_service: appdb
    operations: [modify]
    decision: deny
    deny_mode_in_tx: rollback_then_continue
`
	p, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		panic(err)
	}
	rs, _, err := policy.Decode(p)
	if err != nil {
		panic(err)
	}
	cachedRules = rs
}

// TestProperty_AbsorbingNonSyncEmitsSuppress verifies invariant: while
// Absorbing == true, every non-Sync, non-Terminate frame yields exactly one Suppress.
func TestProperty_AbsorbingNonSyncEmitsSuppress(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		frame := genAbsorbableFrame(t)
		cache := NewFakeCacheView()
		_, acts := Transition(ConnState{LastUpstreamRFQ: 'I', Absorbing: true}, frame, cache, cachedRules, "appdb")
		if len(acts) != 1 {
			t.Fatalf("len(acts)=%d want 1 for absorbing frame %T", len(acts), frame)
		}
		if _, ok := acts[0].(*ActionSuppress); !ok {
			t.Fatalf("acts[0]=%T want *ActionSuppress for frame %T", acts[0], frame)
		}
	})
}

// TestProperty_NoCloseAndRFQTogether verifies invariant: Close never coexists
// with SynthReadyForQuery in the same action list (terminate XOR continue).
func TestProperty_NoCloseAndRFQTogether(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		frame := genFrame(t)
		s := genState(t)
		cache := NewFakeCacheView()
		_, acts := Transition(s, frame, cache, cachedRules, "appdb")
		hasClose, hasRFQ := false, false
		for _, a := range acts {
			if _, ok := a.(*ActionClose); ok {
				hasClose = true
			}
			if _, ok := a.(*ActionSynthReadyForQuery); ok {
				hasRFQ = true
			}
		}
		if hasClose && hasRFQ {
			t.Fatalf("Close and SynthReadyForQuery in same action list: %#v (frame=%T, state=%#v)", acts, frame, s)
		}
	})
}

// TestProperty_InjectRollbackOnlyInTx verifies invariant: InjectRollback
// only emits when LastUpstreamRFQ is 'T' or 'E'.
func TestProperty_InjectRollbackOnlyInTx(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		frame := genFrame(t)
		s := genState(t)
		cache := NewFakeCacheView()
		_, acts := Transition(s, frame, cache, cachedRules, "appdb")
		for _, a := range acts {
			if _, ok := a.(*ActionInjectRollback); ok {
				if s.LastUpstreamRFQ != 'T' && s.LastUpstreamRFQ != 'E' {
					t.Fatalf("InjectRollback emitted while LastUpstreamRFQ=%q", s.LastUpstreamRFQ)
				}
			}
		}
	})
}

// generators -----------------------------------------------------------------

func genFrame(t *rapid.T) Frame {
	kind := rapid.IntRange(0, 8).Draw(t, "frameKind")
	switch kind {
	case 0:
		return &QueryFrame{SQL: rapid.SampledFrom([]string{"SELECT id FROM users", "DELETE FROM users", "UPDATE users SET x=1"}).Draw(t, "sql")}
	case 1:
		return &ParseFrame{
			Name: rapid.SampledFrom([]string{"", "s1", "s2"}).Draw(t, "name"),
			SQL:  rapid.SampledFrom([]string{"SELECT id FROM users", "DELETE FROM users"}).Draw(t, "sql"),
		}
	case 2:
		return &BindFrame{Portal: "p", Statement: rapid.SampledFrom([]string{"", "s1", "missing"}).Draw(t, "stmt")}
	case 3:
		return &DescribeFrame{ObjectType: 'S', Name: "s1"}
	case 4:
		return &ExecuteFrame{Portal: rapid.SampledFrom([]string{"p", "p1", "missing"}).Draw(t, "portal")}
	case 5:
		return &SyncFrame{}
	case 6:
		return &FlushFrame{}
	case 7:
		return &CloseFrame{ObjectType: 'S', Name: "s1"}
	default:
		return &TerminateFrame{}
	}
}

// genAbsorbableFrame draws a frame that should be absorbed (suppressed) when
// the connection is in Absorbing state. Sync resolves the absorbing window
// and Terminate forwards-then-closes, so neither belongs here.
func genAbsorbableFrame(t *rapid.T) Frame {
	for {
		f := genFrame(t)
		switch f.(type) {
		case *SyncFrame, *TerminateFrame:
			continue
		default:
			return f
		}
	}
}

func genState(t *rapid.T) ConnState {
	return ConnState{
		LastUpstreamRFQ:        rapid.SampledFrom([]byte{0, 'I', 'T', 'E'}).Draw(t, "rfq"),
		Absorbing:              rapid.Bool().Draw(t, "absorbing"),
		UpstreamDirtySinceSync: rapid.Bool().Draw(t, "dirty"),
	}
}
