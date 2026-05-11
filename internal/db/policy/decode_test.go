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

func TestDecode_WarnsOnApproveDecision(t *testing.T) {
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
	found := false
	for _, w := range warns {
		if w.Code == "APPROVE_NOT_YET_SUPPORTED" && w.Rule == "review-deletes" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected APPROVE_NOT_YET_SUPPORTED warning, got %v", warns)
	}
}
