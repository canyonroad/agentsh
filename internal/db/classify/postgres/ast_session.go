// Package postgres — ast_session.go owns the session/transaction handlers
// (SET / SET LOCAL / SET ROLE / SET SESSION AUTHORIZATION / RESET / DISCARD
// / SHOW / BEGIN / COMMIT / ROLLBACK) plus the `applySession` state-evolution
// rules called by ApplyStatement.
//
// The classifier renders a SET's value list into the RawVerb (e.g.
// "SET_SEARCH_PATH=app,public"); applySession parses that string back to
// mutate SessionState. The round-trip avoids carrying structured payloads on
// effects.Effect — a deliberate Phase 1 simplification per Plan 03.
package postgres

import (
	"strconv"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// classifySet maps SET / SET LOCAL / SET SESSION AUTHORIZATION / SET ROLE.
func classifySet(cs *effects.ClassifiedStatement, s *pg_query.VariableSetStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil VariableSetStmt"
		return
	}
	name := strings.ToLower(s.Name)
	subtype, raw := mapSetSubtype(s.Kind, name, s.IsLocal)
	cs.RawVerb = raw + valueSummary(s)
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupSession,
		Subtype: subtype,
		Objects: []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: name}},
	}}
}

// mapSetSubtype picks the session subtype + RawVerb prefix for a SET-family
// statement. SET LOCAL is treated as a no-op subtype regardless of the GUC
// being set — Plan 03 §7.4 only tracks the session-scoped form.
func mapSetSubtype(k pg_query.VariableSetKind, name string, isLocal bool) (effects.Subtype, string) {
	if isLocal {
		// SET LOCAL is transaction-scoped — we tag it for diagnostics but the
		// applier ignores it. RawVerb format: "SET_LOCAL=<name>:<values>".
		return effects.SubtypeSetLocal, "SET_LOCAL=" + name + ":"
	}
	switch k {
	case pg_query.VariableSetKind_VAR_SET_VALUE,
		pg_query.VariableSetKind_VAR_SET_DEFAULT,
		pg_query.VariableSetKind_VAR_SET_CURRENT:
		switch name {
		case "search_path":
			return effects.SubtypeSetSearchPath, "SET_SEARCH_PATH="
		case "role":
			return effects.SubtypeSetRole, "SET_ROLE="
		case "session_authorization":
			return effects.SubtypeSetSessionAuthorization, "SET_SESSION_AUTHORIZATION="
		default:
			return effects.SubtypeSet, "SET="
		}
	case pg_query.VariableSetKind_VAR_SET_MULTI:
		return effects.SubtypeSet, "SET="
	case pg_query.VariableSetKind_VAR_RESET:
		if name == "all" {
			return effects.SubtypeResetAll, "RESET_ALL"
		}
		return effects.SubtypeReset, "RESET=" + name
	case pg_query.VariableSetKind_VAR_RESET_ALL:
		return effects.SubtypeResetAll, "RESET_ALL"
	}
	return effects.SubtypeSet, "SET="
}

// classifyShow — SHOW name | SHOW ALL is a read of session state.
func classifyShow(cs *effects.ClassifiedStatement) {
	cs.RawVerb = "SHOW"
	cs.Effects = []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}}
}

// classifyDiscard maps DISCARD ALL / PLANS / TEMP / SEQUENCES.
func classifyDiscard(cs *effects.ClassifiedStatement, s *pg_query.DiscardStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil DiscardStmt"
		return
	}
	switch s.Target {
	case pg_query.DiscardMode_DISCARD_ALL:
		cs.RawVerb = "DISCARD_ALL"
		cs.Effects = []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardAll}}
	case pg_query.DiscardMode_DISCARD_PLANS:
		cs.RawVerb = "DISCARD_PLANS"
		cs.Effects = []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardPlans}}
	case pg_query.DiscardMode_DISCARD_TEMP:
		cs.RawVerb = "DISCARD_TEMP"
		cs.Effects = []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardTemp}}
	case pg_query.DiscardMode_DISCARD_SEQUENCES:
		cs.RawVerb = "DISCARD_SEQUENCES"
		cs.Effects = []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardSequences}}
	default:
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: discard target"
	}
}

// classifyTransaction maps BEGIN / START / COMMIT / ROLLBACK / SAVEPOINT /
// RELEASE / ROLLBACK TO / PREPARE / COMMIT PREPARED / ROLLBACK PREPARED.
//
// pg_query's TransactionStmtKind.String() returns names like "TRANS_STMT_BEGIN";
// we strip the "TRANS_STMT_" prefix so applySession can dispatch on a clean
// token like "BEGIN".
func classifyTransaction(cs *effects.ClassifiedStatement, s *pg_query.TransactionStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil TransactionStmt"
		return
	}
	cs.RawVerb = transactionVerb(s.Kind)
	cs.Effects = []effects.Effect{{Group: effects.GroupTransaction}}
}

// transactionVerb returns the canonical RawVerb token for a TransactionStmtKind
// (e.g. TRANS_STMT_BEGIN → "BEGIN").
func transactionVerb(k pg_query.TransactionStmtKind) string {
	v := strings.ToUpper(k.String())
	v = strings.TrimPrefix(v, "TRANS_STMT_")
	return v
}

// valueSummary renders a compact representation of a SET's value list, used
// for RawVerb introspection. Best-effort — only covers literal, identifier,
// and list-of-strings cases; falls back to "?" for complex expressions.
func valueSummary(s *pg_query.VariableSetStmt) string {
	if len(s.Args) == 0 {
		return ""
	}
	parts := make([]string, 0, len(s.Args))
	for _, arg := range s.Args {
		parts = append(parts, summarizeArg(arg))
	}
	return strings.Join(parts, ",")
}

func summarizeArg(n *pg_query.Node) string {
	if n == nil {
		return ""
	}
	switch v := n.Node.(type) {
	case *pg_query.Node_AConst:
		if v.AConst == nil || v.AConst.Val == nil {
			return ""
		}
		switch c := v.AConst.Val.(type) {
		case *pg_query.A_Const_Sval:
			if c.Sval != nil {
				return c.Sval.Sval
			}
		case *pg_query.A_Const_Ival:
			if c.Ival != nil {
				return formatInt(c.Ival.Ival)
			}
		}
	case *pg_query.Node_String_:
		if v.String_ != nil {
			return v.String_.Sval
		}
	case *pg_query.Node_TypeCast:
		// e.g. SET timezone = 'UTC'::text — recurse into the underlying arg.
		if v.TypeCast != nil {
			return summarizeArg(v.TypeCast.Arg)
		}
	}
	return "?"
}

func formatInt(n int32) string {
	return strconv.FormatInt(int64(n), 10)
}

// applySession evolves SessionState after the proxy confirms upstream success.
// Pure — produces a fresh SessionState; the input is never mutated.
func applySession(s SessionState, c effects.ClassifiedStatement) SessionState {
	out := s.Clone()
	for _, e := range c.Effects {
		if e.Group != effects.GroupSession && e.Group != effects.GroupTransaction {
			// Non-session/transaction effects: only CREATE TEMP TABLE / DROP
			// TABLE mutate session state. (CREATE TEMP TABLE classification
			// lands in Task 7; this code is dormant until then.)
			applyTempLifecycle(&out, e, c.RawVerb)
			continue
		}
		applySessionEffect(&out, e, c.RawVerb)
	}
	return out
}

func applySessionEffect(s *SessionState, e effects.Effect, rawVerb string) {
	switch e.Subtype {
	case effects.SubtypeSetSearchPath:
		s.SearchPath = parseSearchPath(rawVerb)
	case effects.SubtypeSetRole:
		v := parseAfterEqual(rawVerb)
		if strings.EqualFold(v, "none") {
			s.Role = s.DefaultRole
		} else {
			s.Role = v
		}
	case effects.SubtypeSetSessionAuthorization:
		s.Role = parseAfterEqual(rawVerb)
	case effects.SubtypeReset:
		// Specific GUC reset: search_path and role resets affect tracked state.
		if hasGUC(e.Objects, "search_path") {
			s.SearchPath = append([]string(nil), s.DefaultSearchPath...)
		}
		if hasGUC(e.Objects, "role") {
			s.Role = s.DefaultRole
		}
	case effects.SubtypeResetAll, effects.SubtypeDiscardAll:
		s.SearchPath = append([]string(nil), s.DefaultSearchPath...)
		s.Role = s.DefaultRole
		s.TempTables = nil
	case effects.SubtypeDiscardTemp:
		s.TempTables = nil
	case effects.SubtypeSetLocal:
		// Tag-only; no mutation. SET LOCAL is transaction-scoped and Plan 03
		// only tracks session-scoped state.
	}

	// Transaction tracking (hint only — Plan 05 owns authoritative tx state).
	switch rawVerb {
	case "BEGIN", "START", "BEGIN_TRANSACTION":
		s.InTransaction = true
	case "COMMIT", "ROLLBACK", "END":
		s.InTransaction = false
	}
}

// applyTempLifecycle mutates TempTables on CREATE TEMP TABLE / DROP TABLE.
// Dormant until Task 7 ships CREATE TEMP TABLE classification with a RawVerb
// like "CREATE_TEMP_TABLE".
func applyTempLifecycle(s *SessionState, e effects.Effect, rawVerb string) {
	if e.Subtype == effects.SubtypeCreateTable && strings.Contains(rawVerb, "TEMP") {
		for _, o := range e.Objects {
			if o.Kind == effects.ObjectTable && o.Schema == "" {
				if s.TempTables == nil {
					s.TempTables = make(map[string]struct{})
				}
				s.TempTables[o.Name] = struct{}{}
			}
		}
	}
	if e.Subtype == effects.SubtypeDropTable {
		for _, o := range e.Objects {
			if o.Kind == effects.ObjectTable && o.Schema == "" {
				delete(s.TempTables, o.Name)
			}
		}
	}
}

func parseSearchPath(rawVerb string) []string {
	const prefix = "SET_SEARCH_PATH="
	if !strings.HasPrefix(rawVerb, prefix) {
		return nil
	}
	parts := strings.Split(rawVerb[len(prefix):], ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		p = strings.ToLower(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseAfterEqual(rawVerb string) string {
	if i := strings.Index(rawVerb, "="); i >= 0 {
		return strings.ToLower(strings.TrimSpace(rawVerb[i+1:]))
	}
	return ""
}

func hasGUC(objs []effects.ObjectRef, name string) bool {
	for _, o := range objs {
		if o.Kind == effects.ObjectGUC && o.Name == name {
			return true
		}
	}
	return false
}
