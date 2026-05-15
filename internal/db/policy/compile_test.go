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

func TestCompileStatementRule_CanonicalOnlyDoesNotCoverSyntacticObject(t *testing.T) {
	r := &StatementRule{
		Name:       "canonical-only",
		Operations: []string{"READ"},
		Relations:  []string{"public.users"},
		Decision:   "allow",
	}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if c.coversAllObjects() {
		t.Fatal("canonical selector-only rule should not cover all syntactic objects")
	}
	if c.objectMatches(effects.ObjectRef{Kind: effects.ObjectTable, Schema: "public", Name: "users"}) {
		t.Fatal("canonical selector-only rule should not cover a syntactic object without resolved canonical matching")
	}
}

func TestCompileStatementRule_RedirectAction(t *testing.T) {
	r := &StatementRule{
		Name:                  "redirect-users",
		Operations:            []string{"READ"},
		Relations:             []string{"public.users"},
		MatchObjectResolution: "catalog_resolved",
		Decision:              "redirect",
		Redirect:              &RedirectAction{Relation: "public.safe_users"},
	}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if c.verb != VerbRedirect {
		t.Fatalf("verb = %v, want redirect", c.verb)
	}
	if c.redirect == nil {
		t.Fatal("redirect metadata nil")
	}
	if c.redirect.SourceRelation != "public.users" {
		t.Errorf("SourceRelation = %q, want public.users", c.redirect.SourceRelation)
	}
	if c.redirect.TargetRelation != "public.safe_users" {
		t.Errorf("TargetRelation = %q, want public.safe_users", c.redirect.TargetRelation)
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

func TestCompileStatementRule_CanonicalSelectorGlobs(t *testing.T) {
	r := &StatementRule{
		Name:       "canonical",
		Operations: []string{"READ"},
		Relations:  []string{"public.users", "sales.*"},
		Functions:  []string{"public.safe_fn(integer)", "pg_catalog.*"},
		Decision:   "allow",
	}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rel := effects.ResolvedObjectRef{
		Source: effects.ResolvedObjectSourceCatalog,
		Kind:   effects.ResolvedObjectRelation,
		Schema: "public",
		Name:   "users",
	}
	if !c.relationMatches(rel) {
		t.Fatalf("public.users relation should match")
	}
	fn := effects.ResolvedObjectRef{
		Source:               effects.ResolvedObjectSourceCatalog,
		Kind:                 effects.ResolvedObjectFunction,
		Schema:               "public",
		Name:                 "safe_fn",
		FunctionIdentityArgs: "integer",
	}
	if !c.functionMatches(fn) {
		t.Fatalf("public.safe_fn(integer) function should match")
	}
}

func TestCompileStatementRule_BadCanonicalGlob(t *testing.T) {
	_, err := compileStatementRule(&StatementRule{
		Name:       "bad-relation",
		Operations: []string{"READ"},
		Relations:  []string{"["},
		Decision:   "allow",
	})
	if err == nil || !strings.Contains(err.Error(), "glob_compile") || !strings.Contains(err.Error(), "relations") {
		t.Fatalf("want relation glob_compile error, got %v", err)
	}

	_, err = compileStatementRule(&StatementRule{
		Name:       "bad-function",
		Operations: []string{"READ"},
		Functions:  []string{"["},
		Decision:   "allow",
	})
	if err == nil || !strings.Contains(err.Error(), "glob_compile") || !strings.Contains(err.Error(), "functions") {
		t.Fatalf("want function glob_compile error, got %v", err)
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
