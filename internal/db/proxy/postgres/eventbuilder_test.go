//go:build linux

package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
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
