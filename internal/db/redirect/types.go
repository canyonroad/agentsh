package redirect

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/db/effects"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

type Reason string

const (
	ReasonUnsupportedStatement    Reason = "unsupported_statement"
	ReasonMultiStatement          Reason = "multi_statement"
	ReasonNonSelectStatement      Reason = "non_select_statement"
	ReasonWriteStatement          Reason = "write_statement"
	ReasonDDLStatement            Reason = "ddl_statement"
	ReasonCopyStatement           Reason = "copy_statement"
	ReasonProceduralStatement     Reason = "procedural_statement"
	ReasonFunctionCallProtocol    Reason = "function_call_protocol"
	ReasonUnresolvedObject        Reason = "unresolved_object"
	ReasonMissingRedirectTarget   Reason = "missing_redirect_target"
	ReasonAmbiguousRedirectSource Reason = "ambiguous_redirect_source"
	ReasonSourceNotFound          Reason = "source_relation_not_found"
	ReasonDeparseFailed           Reason = "deparse_failed"
)

type Rejection struct {
	Reason Reason
	Err    error
}

func (r Rejection) Error() string {
	if r.Err != nil {
		return fmt.Sprintf("%s: %v", r.Reason, r.Err)
	}
	return string(r.Reason)
}

func (r Rejection) Unwrap() error {
	return r.Err
}

type Action struct {
	RuleName       string
	SourceRelation string
	TargetRelation string
}

type Input struct {
	SQL       string
	Statement effects.ClassifiedStatement
	Action    Action
}

type Plan struct {
	RewrittenSQL   string
	RuleName       string
	SourceRelation string
	TargetRelation string
}

type SQLBackend interface {
	Parse(sql string) (*pg_query.ParseResult, error)
	Deparse(tree *pg_query.ParseResult) (string, error)
	Backend() effects.ParserBackend
}

type Planner struct {
	Backend SQLBackend
}
