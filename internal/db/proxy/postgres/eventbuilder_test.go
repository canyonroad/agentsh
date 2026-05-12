//go:build linux

package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func connStateForTest(svc, dialect, tlsMode string) connState {
	return connState{
		dbService:      svc,
		clientIdentity: "uid:1000",
		dbUser:         "agent",
		database:       "app",
		appName:        "tests",
		tlsMode:        tlsMode,
		smState:        &statemachine.ConnState{},
	}
}

func TestBuildStatementEvent_FullTier_VerbatimSlice(t *testing.T) {
	sql := "SELECT 1; SELECT 2"
	stmt := effects.ClassifiedStatement{
		Effects: []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}},
		SourceStart: 0, SourceEnd: 8, RawVerb: "SELECT",
	}
	parser := classify_pg.New(classify_pg.DialectPostgres)
	ev := buildStatementEvent(buildArgs{
		Stmt: stmt, StmtIndex: 0, BatchTotal: 2,
		Decision: policy.Decision{Verb: policy.VerbAllow, RuleKind: policy.RuleKindStatement, RuleName: "app-allow-read"},
		SQL: sql, Tier: policy.RedactFull,
		Conn: connStateForTest("appdb", "postgres", "terminate_reissue"),
		DenyAction: "none",
		BatchSHA: sha256Hex(sql),
		Parser: parser,
	})
	if ev.StatementText != "SELECT 1" {
		t.Fatalf("StatementText = %q want %q", ev.StatementText, "SELECT 1")
	}
	if !strings.HasPrefix(ev.StatementDigest, "sha256:") {
		t.Fatalf("StatementDigest = %q must start sha256:", ev.StatementDigest)
	}
	if ev.Decision.Verb != "allow" {
		t.Fatalf("Decision.Verb = %q want allow", ev.Decision.Verb)
	}
	if ev.TLS.Mode != "terminate_reissue" {
		t.Fatalf("TLS.Mode = %q", ev.TLS.Mode)
	}
	if ev.CommandID == "" || !strings.Contains(ev.CommandID, ":0") {
		t.Fatalf("CommandID = %q want suffix :0", ev.CommandID)
	}
}

func TestBuildStatementEvent_DigestStableAcrossTiers(t *testing.T) {
	sql := "SELECT 'hello'"
	stmt := effects.ClassifiedStatement{
		Effects:     []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}},
		SourceStart: 0, SourceEnd: int32(len(sql)),
	}
	parser := classify_pg.New(classify_pg.DialectPostgres)
	digests := map[policy.RedactionTier]string{}
	for _, tier := range []policy.RedactionTier{policy.RedactFull, policy.RedactParametersRedacted, policy.RedactNone} {
		ev := buildStatementEvent(buildArgs{
			Stmt: stmt, SQL: sql, Tier: tier,
			Conn: connStateForTest("appdb", "postgres", "terminate_reissue"),
			Decision: policy.Decision{Verb: policy.VerbAllow, RuleKind: policy.RuleKindStatement},
			DenyAction: "none",
			BatchSHA: sha256Hex(sql),
			Parser: parser,
		})
		digests[tier] = ev.StatementDigest
	}
	if digests[policy.RedactFull] != digests[policy.RedactParametersRedacted] ||
		digests[policy.RedactParametersRedacted] != digests[policy.RedactNone] {
		t.Fatalf("digests diverged across tiers: %+v", digests)
	}
}

func TestBuildStatementEvent_DeniedBySibling(t *testing.T) {
	sql := "SELECT 1; DELETE FROM t"
	parser := classify_pg.New(classify_pg.DialectPostgres)
	stmt0 := effects.ClassifiedStatement{
		Effects:     []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}},
		SourceStart: 0, SourceEnd: 8, RawVerb: "SELECT",
	}
	ev := buildStatementEvent(buildArgs{
		Stmt: stmt0, StmtIndex: 0, BatchTotal: 2,
		Decision: policy.Decision{Verb: policy.VerbDeny, RuleKind: policy.RuleKindStatement, Reason: "denied by sibling statement"},
		SQL: sql, Tier: policy.RedactParametersRedacted,
		Conn: connStateForTest("appdb", "postgres", "terminate_reissue"),
		DenyAction: "none",
		IsDeniedBySibling: true,
		BatchSHA: sha256Hex(sql),
		Parser: parser,
	})
	if ev.Decision.Verb != "deny" {
		t.Fatalf("Decision.Verb = %q want deny", ev.Decision.Verb)
	}
	if ev.Result.ErrorCode != "DENIED_BY_SIBLING" {
		t.Fatalf("Result.ErrorCode = %q want DENIED_BY_SIBLING", ev.Result.ErrorCode)
	}
	if ev.Result.RowsReturned != nil || ev.Result.RowsAffected != nil {
		t.Fatalf("Result rows must be nil: %+v", ev.Result)
	}
}

func TestBuildStatementEvent_NoneTierStripsText(t *testing.T) {
	sql := "SELECT 1"
	stmt := effects.ClassifiedStatement{
		Effects:     []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}},
		SourceStart: 0, SourceEnd: int32(len(sql)),
	}
	parser := classify_pg.New(classify_pg.DialectPostgres)
	ev := buildStatementEvent(buildArgs{
		Stmt: stmt, SQL: sql, Tier: policy.RedactNone,
		Conn: connStateForTest("appdb", "postgres", "terminate_reissue"),
		Decision: policy.Decision{Verb: policy.VerbAllow, RuleKind: policy.RuleKindStatement},
		DenyAction: "none",
		BatchSHA: sha256Hex(sql),
		Parser: parser,
	})
	if ev.StatementText != "" {
		t.Fatalf("StatementText must be empty under RedactNone: %q", ev.StatementText)
	}
	if ev.StatementDigest == "" {
		t.Fatalf("StatementDigest must be populated under RedactNone")
	}
}

func TestBuildEvent_TxStartedAt_PopulatedWhenInTx(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	conn := connStateForTest("appdb", "postgres", "terminate_reissue")
	conn.smState = &statemachine.ConnState{
		LastUpstreamRFQ: 'T',
		TxStartedAt:     now,
	}
	sql := "SELECT 1"
	stmt := effects.ClassifiedStatement{
		Effects:     []effects.Effect{{Group: effects.GroupRead}},
		SourceStart: 0, SourceEnd: int32(len(sql)),
	}
	parser := classify_pg.New(classify_pg.DialectPostgres)
	ev := buildStatementEvent(buildArgs{
		Stmt:     stmt,
		SQL:      sql,
		Tier:     policy.RedactParametersRedacted,
		Conn:     conn,
		Decision: policy.Decision{Verb: policy.VerbAllow, RuleKind: policy.RuleKindStatement},
		DenyAction: "none",
		BatchSHA: sha256Hex(sql),
		Parser:   parser,
	})
	if !ev.TxContext.InTransaction {
		t.Error("InTransaction should be true under LastUpstreamRFQ='T'")
	}
	if !ev.TxContext.TxStartedAt.Equal(now) {
		t.Errorf("TxStartedAt=%v want %v", ev.TxContext.TxStartedAt, now)
	}
}

func TestBuildEvent_DenyActionRollbackInjected(t *testing.T) {
	conn := connStateForTest("appdb", "postgres", "terminate_reissue")
	conn.smState = &statemachine.ConnState{LastUpstreamRFQ: 'T', TxStartedAt: time.Now()}
	sql := "DELETE FROM users"
	stmt := effects.ClassifiedStatement{
		Effects:     []effects.Effect{{Group: effects.GroupDelete}},
		SourceStart: 0, SourceEnd: int32(len(sql)),
	}
	parser := classify_pg.New(classify_pg.DialectPostgres)
	ev := buildStatementEvent(buildArgs{
		Stmt:     stmt,
		SQL:      sql,
		Tier:     policy.RedactParametersRedacted,
		Conn:     conn,
		Decision: policy.Decision{Verb: policy.VerbDeny, RuleName: "block-delete-soft"},
		DenyAction: "rollback_injected",
		BatchSHA: sha256Hex(sql),
		Parser:   parser,
	})
	if ev.TxContext.DenyAction != "rollback_injected" {
		t.Errorf("DenyAction=%q want rollback_injected", ev.TxContext.DenyAction)
	}
}

func TestBuildEvent_PropagatesFunctionOID(t *testing.T) {
	oid := int32(99)
	sql := "-- function call"
	stmt := effects.ClassifiedStatement{
		RawVerb: "FUNCTION_CALL",
		Effects: []effects.Effect{{
			Group:       effects.GroupProcedural,
			Subtype:     effects.SubtypeFunctionCallProtocol,
			FunctionOID: &oid,
		}},
	}
	parser := classify_pg.New(classify_pg.DialectPostgres)
	ev := buildStatementEvent(buildArgs{
		Stmt:     stmt,
		SQL:      sql,
		Tier:     policy.RedactParametersRedacted,
		Conn:     connStateForTest("appdb", "postgres", "terminate_reissue"),
		Decision: policy.Decision{Verb: policy.VerbAllow},
		DenyAction: "none",
		BatchSHA: sha256Hex(sql),
		Parser:   parser,
	})
	if len(ev.Effects) != 1 {
		t.Fatalf("len(Effects)=%d want 1", len(ev.Effects))
	}
	if ev.Effects[0].FunctionOID == nil || *ev.Effects[0].FunctionOID != 99 {
		t.Errorf("FunctionOID=%v want 99", ev.Effects[0].FunctionOID)
	}
}
