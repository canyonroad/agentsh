package policy

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/policy"
)

func loadDB(t *testing.T, src string) (*RuleSet, []Warning, error) {
	t.Helper()
	p, err := policy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	return Decode(p)
}

func TestDecode_Empty(t *testing.T) {
	rs, warns, err := loadDB(t, `version: 1
name: x
`)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(warns) != 0 {
		t.Errorf("warns = %v", warns)
	}
	if rs == nil {
		t.Fatal("nil RuleSet")
	}
	if rs.Redaction().LogStatements != RedactParametersRedacted {
		t.Errorf("default LogStatements = %v, want parameters_redacted", rs.Redaction().LogStatements)
	}
	if rs.Redaction().ApprovalStatementChars != 200 {
		t.Errorf("default ApprovalStatementChars = %d, want 200", rs.Redaction().ApprovalStatementChars)
	}
}

func TestDecode_FullPolicy(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: r1
    db_service: appdb
    operations: [READ]
    decision: allow
database_connection_rules:
  - name: c1
    db_service: appdb
    decision: allow
`
	rs, warns, err := loadDB(t, src)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(warns) != 0 {
		t.Errorf("warns = %v", warns)
	}
	svc, ok := rs.Service("appdb")
	if !ok || svc.TLSMode != "terminate_reissue" {
		t.Fatalf("Service appdb missing or wrong: %+v", svc)
	}
}

func TestDecode_CanonicalSelectors(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: canonical-read
    db_service: appdb
    operations: [READ]
    relations: ["public.users", "sales.*"]
    functions: ["public.safe_fn(integer)", "pg_catalog.*"]
    match_object_resolution: catalog_resolved
    decision: allow
`
	rs, warns, err := loadDB(t, src)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings = %+v", warns)
	}
	rules := rs.AllStatementRules()
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if got := rules[0].Relations; len(got) != 2 || got[0] != "public.users" || got[1] != "sales.*" {
		t.Fatalf("Relations = %#v", got)
	}
	if got := rules[0].Functions; len(got) != 2 || got[0] != "public.safe_fn(integer)" || got[1] != "pg_catalog.*" {
		t.Fatalf("Functions = %#v", got)
	}
}

func TestDecode_RedactionConfig(t *testing.T) {
	src := `version: 1
name: t
policies:
  db:
    log_statements: full
    approval_statement_preview: redacted
    approval_statement_preview_chars: 50
`
	rs, _, err := loadDB(t, src)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if rs.Redaction().LogStatements != RedactFull {
		t.Errorf("LogStatements = %v, want full", rs.Redaction().LogStatements)
	}
	// "redacted" is the YAML name for parameters_redacted in the
	// approval-preview field per §10.3.
	if rs.Redaction().ApprovalStatementPreview != RedactParametersRedacted {
		t.Errorf("ApprovalStatementPreview = %v, want parameters_redacted", rs.Redaction().ApprovalStatementPreview)
	}
	if rs.Redaction().ApprovalStatementChars != 50 {
		t.Errorf("ApprovalStatementChars = %d, want 50", rs.Redaction().ApprovalStatementChars)
	}
}

func TestDecode_PropagatesValidationError(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    # tls_mode missing
`
	_, _, err := loadDB(t, src)
	if err == nil || !strings.Contains(err.Error(), "service_tls_mode_required") {
		t.Fatalf("want service_tls_mode_required, got %v", err)
	}
}

func TestDecode_PropagatesGlobCompileError(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: r
    db_service: appdb
    objects: ["["]
    operations: [READ]
    decision: allow
`
	_, _, err := loadDB(t, src)
	if err == nil || !strings.Contains(err.Error(), "glob_compile") {
		t.Fatalf("want glob_compile error, got %v", err)
	}
}

func TestDecode_AuditOnDangerousWarning(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: aud
    db_service: appdb
    operations: [DROP]
    decision: audit
`
	_, warns, err := loadDB(t, src)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, w := range warns {
		if w.Code == "audit_on_dangerous" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected audit_on_dangerous warning, got %v", warns)
	}
}

func TestDecode_PoliciesDB_Unavoidability(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want service.Unavoidability
	}{
		{
			name: "missing block defaults to off",
			yaml: `version: 1
name: test
`,
			want: service.UnavoidabilityOff,
		},
		{
			name: "explicit off",
			yaml: `version: 1
name: test
policies:
  db:
    unavoidability: off
`,
			want: service.UnavoidabilityOff,
		},
		{
			name: "observe",
			yaml: `version: 1
name: test
policies:
  db:
    unavoidability: observe
`,
			want: service.UnavoidabilityObserve,
		},
		{
			name: "enforce",
			yaml: `version: 1
name: test
policies:
  db:
    unavoidability: enforce
`,
			want: service.UnavoidabilityEnforce,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rp, err := policy.LoadFromBytes([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("LoadFromBytes: %v", err)
			}
			rs, _, err := Decode(rp)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got := rs.Unavoidability(); got != tc.want {
				t.Errorf("Unavoidability() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDecode_PoliciesDB_Unavoidability_Unknown(t *testing.T) {
	yaml := `version: 1
name: test
policies:
  db:
    unavoidability: bogus
`
	rp, err := policy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if _, _, err := Decode(rp); err == nil {
		t.Fatal("Decode: expected error for unknown unavoidability value, got nil")
	}
}

func TestDecode_EscalateUnknownFunctions_DefaultFalse(t *testing.T) {
	rs, _, err := loadDB(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
`)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if rs.Redaction().EscalateUnknownFunctions {
		t.Error("default EscalateUnknownFunctions should be false")
	}
}

func TestDecode_EscalateUnknownFunctions_True(t *testing.T) {
	rs, _, err := loadDB(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
policies:
  db:
    escalate_unknown_functions: true
`)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !rs.Redaction().EscalateUnknownFunctions {
		t.Error("expected EscalateUnknownFunctions to be true")
	}
	if len(rs.Redaction().SafeFunctionAllowlist) == 0 {
		t.Error("default allowlist should be populated when escalate is true and allowlist omitted")
	}
}

func TestDecode_SafeFunctionAllowlist_Custom(t *testing.T) {
	rs, _, err := loadDB(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
policies:
  db:
    escalate_unknown_functions: true
    safe_function_allowlist: ["my_func", "schema.fn"]
`)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := []string{"my_func", "schema.fn"}
	got := rs.Redaction().SafeFunctionAllowlist
	if len(got) != len(want) {
		t.Fatalf("len(got)=%d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestDecode_ApproveDecision_NoLongerWarns(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: review-deletes
    db_service: appdb
    operations: [DELETE]
    decision: approve
`
	_, warns, err := loadDB(t, src)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	for _, w := range warns {
		if w.Code == "APPROVE_NOT_YET_SUPPORTED" && w.Rule == "review-deletes" {
			t.Fatalf("APPROVE_NOT_YET_SUPPORTED warning should no longer be emitted: %#v", w)
		}
	}
}
