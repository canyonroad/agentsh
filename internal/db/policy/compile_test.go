package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestCompileStatementRule_GlobMatch(t *testing.T) {
	r := &StatementRule{
		Name: "pii", Objects: []string{"pii.*", "secrets"},
		Operations: []string{"READ"}, Decision: "deny",
	}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !c.objectMatches(effects.ObjectRef{Kind: effects.ObjectTable, Name: "pii.ssns"}) {
		t.Errorf("expected pii.ssns to match pii.*")
	}
	if !c.objectMatches(effects.ObjectRef{Kind: effects.ObjectTable, Name: "secrets"}) {
		t.Errorf("expected secrets to match secrets literal")
	}
	if c.objectMatches(effects.ObjectRef{Kind: effects.ObjectTable, Name: "users"}) {
		t.Errorf("did not expect users to match")
	}
}

func TestCompileStatementRule_NoObjectsCoversAll(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"READ"}, Decision: "allow"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !c.coversAllObjects() {
		t.Errorf("expected coversAllObjects() to be true when objects: is empty")
	}
}

func TestCompileStatementRule_ExternalEndpointHostMatch(t *testing.T) {
	r := &StatementRule{Name: "endpoint", Objects: []string{"*.internal"},
		Operations: []string{"READ"}, Decision: "deny"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	obj := effects.ObjectRef{Kind: effects.ObjectExternalEndpoint, Host: "db.internal", Port: 5432}
	if !c.objectMatches(obj) {
		t.Errorf("expected db.internal to match *.internal for ObjectExternalEndpoint")
	}
}

func TestCompileStatementRule_GroupAliasExpanded(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"MUTATE"}, Decision: "allow"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	want := []effects.Group{effects.GroupWrite, effects.GroupModify, effects.GroupDelete}
	for _, g := range want {
		if _, ok := c.groups[g]; !ok {
			t.Errorf("MUTATE missing group %v", g)
		}
	}
	if _, ok := c.groups[effects.GroupRead]; ok {
		t.Errorf("MUTATE should not include GroupRead")
	}
}

func TestCompileStatementRule_MessageTemplate(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"READ"}, Decision: "deny",
		Message: "denied {{.Operation}} on {{.Object}}"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := c.renderMessage(messageContext{Operation: "read", Object: "users"})
	if got != "denied read on users" {
		t.Errorf("renderMessage = %q", got)
	}
}

func TestCompileStatementRule_BadGlob(t *testing.T) {
	r := &StatementRule{Name: "r", Objects: []string{"["}, Operations: []string{"READ"}, Decision: "allow"}
	_, err := compileStatementRule(r)
	if err == nil || !strings.Contains(err.Error(), "glob_compile") {
		t.Fatalf("want glob_compile error, got %v", err)
	}
}

func TestCompileStatementRule_BadTemplate(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"READ"}, Decision: "deny",
		Message: "{{.Unclosed"}
	_, err := compileStatementRule(r)
	if err == nil || !strings.Contains(err.Error(), "message_template_parse") {
		t.Fatalf("want message_template_parse error, got %v", err)
	}
}

func TestCompileStatementRule_DefaultApproveTimeout(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"READ"}, Decision: "approve"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if c.timeout != 60*time.Second {
		t.Errorf("default approve timeout = %v, want 60s", c.timeout)
	}
}

func TestCompileStatementRule_ResolutionMatcher(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"READ"},
		MatchObjectResolution: "qualified_syntactic", Decision: "allow"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !c.matchesResolution(effects.ResolutionQualified) {
		t.Errorf("expected qualified to match")
	}
	if c.matchesResolution(effects.ResolutionUnqualified) {
		t.Errorf("did not expect unqualified to match")
	}
}

func TestCompileStatementRule_ResolutionWildcard(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"READ"},
		MatchObjectResolution: "*", Decision: "allow"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !c.matchesResolution(effects.ResolutionUnresolved) {
		t.Errorf("* should match every resolution")
	}
}
