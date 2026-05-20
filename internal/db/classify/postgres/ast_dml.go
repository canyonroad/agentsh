// Package postgres — ast_dml.go owns the DML and composition handlers
// (SELECT, INSERT, UPDATE, DELETE, MERGE, EXPLAIN, PREPARE, EXECUTE,
// DEALLOCATE) plus the relation-walking helpers shared with DDL/COPY.
package postgres

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// ---- per-family handlers ----

func classifySelect(cs *effects.ClassifiedStatement, s *pg_query.SelectStmt, sess SessionState, opts Options) {
	cs.RawVerb = "SELECT"
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}}
		return
	}

	// SELECT … INTO is parsed as a SelectStmt with IntoClause set — same shape
	// CREATE TABLE AS uses. Spec §7.3 says: primary schema_create + secondary read.
	if s.IntoClause != nil {
		cs.RawVerb = "SELECT_INTO"
		target, res := extractRelation(s.IntoClause.Rel, sess, effects.ObjectTable)
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:      effects.GroupSchemaCreate,
			Subtype:    effects.SubtypeCreateTable,
			Objects:    []effects.ObjectRef{target},
			Resolution: res,
		})
	}

	// Read effect from FROM-clause, joins, sub-selects, set-ops, and CTE bodies.
	relations, res := walkSelectRelations(s, sess)
	if len(relations) > 0 || !hasSchemaCreateEffect(cs) {
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:      effects.GroupRead,
			Objects:    relations,
			Resolution: res,
		})
	}

	// WITH-CTE composition: data-modifying CTEs (DELETE/INSERT/UPDATE inside
	// WITH) propagate their effects to the outer SELECT per spec §20.
	if s.WithClause != nil {
		appendCTEEffects(cs, s.WithClause, sess, opts)
	}

	// §7.6 escalation: if any function call in the projection / WHERE is not
	// in the safe-allowlist, add a procedural effect. Walker + allowlist
	// matcher live in escalation.go.
	if opts.EscalateUnknownFunctions && collectFuncCallsAny(s, opts.SafeFunctionAllowlist) {
		cs.Effects = append(cs.Effects, effects.Effect{Group: effects.GroupProcedural})
	}

	// Detect unsafe-IO function calls (pg_read_file, lo_*, dblink) anywhere
	// inside the projection / WHERE / sub-selects. See ast_unsafe_io.go.
	appendUnsafeIO(cs, s, sess)

	if len(cs.Effects) == 0 {
		// SELECT 1 with no relations — still classify as read.
		cs.Effects = []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}}
	}
}

func classifyInsert(cs *effects.ClassifiedStatement, s *pg_query.InsertStmt, sess SessionState, opts Options) {
	cs.RawVerb = "INSERT"
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil InsertStmt"
		return
	}
	tgt, tgtRes := extractRelation(s.Relation, sess, effects.ObjectTable)
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      effects.GroupWrite,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
	})

	// INSERT … SELECT — read effect for the inner SELECT relations.
	if s.SelectStmt != nil {
		if sel, ok := s.SelectStmt.Node.(*pg_query.Node_SelectStmt); ok && sel.SelectStmt != nil {
			rels, res := walkSelectRelations(sel.SelectStmt, sess)
			if len(rels) > 0 {
				cs.Effects = append(cs.Effects, effects.Effect{
					Group:      effects.GroupRead,
					Objects:    rels,
					Resolution: res,
				})
			}
		}
	}

	// WITH-CTE composition: data-modifying CTEs add their own effects.
	if s.WithClause != nil {
		appendCTEEffects(cs, s.WithClause, sess, opts)
	}
}

func classifyUpdate(cs *effects.ClassifiedStatement, s *pg_query.UpdateStmt, sess SessionState, opts Options) {
	cs.RawVerb = "UPDATE"
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil UpdateStmt"
		return
	}
	tgt, tgtRes := extractRelation(s.Relation, sess, effects.ObjectTable)
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      effects.GroupModify,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
		HasWhere:   s.WhereClause != nil,
	})
	rels, res := walkRangeRelations(s.FromClause, sess)
	if len(rels) > 0 {
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:      effects.GroupRead,
			Objects:    rels,
			Resolution: res,
		})
	}
	if s.WithClause != nil {
		appendCTEEffects(cs, s.WithClause, sess, opts)
	}
}

func classifyDelete(cs *effects.ClassifiedStatement, s *pg_query.DeleteStmt, sess SessionState, opts Options) {
	cs.RawVerb = "DELETE"
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil DeleteStmt"
		return
	}
	tgt, tgtRes := extractRelation(s.Relation, sess, effects.ObjectTable)
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      effects.GroupDelete,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
		HasWhere:   s.WhereClause != nil,
	})
	if hasReturningList(s.ReturningList) {
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:      effects.GroupRead,
			Objects:    []effects.ObjectRef{tgt},
			Resolution: tgtRes,
		})
	}
	rels, res := walkRangeRelations(s.UsingClause, sess)
	if len(rels) > 0 {
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:      effects.GroupRead,
			Objects:    rels,
			Resolution: res,
		})
	}
	if s.WithClause != nil {
		appendCTEEffects(cs, s.WithClause, sess, opts)
	}
}

func classifyMerge(cs *effects.ClassifiedStatement, s *pg_query.MergeStmt, sess SessionState, opts Options) {
	cs.RawVerb = "MERGE"
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil MergeStmt"
		return
	}
	tgt, tgtRes := extractRelation(s.Relation, sess, effects.ObjectTable)
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      effects.GroupModify,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
	})
	if s.SourceRelation != nil {
		// SourceRelation can be a RangeVar, a RangeSubselect, or a JoinExpr in
		// principle. We collect everything via the shared walker so MERGE benefits
		// from sub-select recursion for free.
		rels, res := walkRangeRelations([]*pg_query.Node{s.SourceRelation}, sess)
		if len(rels) > 0 {
			cs.Effects = append(cs.Effects, effects.Effect{
				Group:      effects.GroupRead,
				Objects:    rels,
				Resolution: res,
			})
		}
	}
	if s.WithClause != nil {
		appendCTEEffects(cs, s.WithClause, sess, opts)
	}
}

func classifyExplain(cs *effects.ClassifiedStatement, s *pg_query.ExplainStmt, sess SessionState, opts Options) {
	cs.RawVerb = "EXPLAIN"
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}}
		return
	}
	analyze := false
	for _, opt := range s.Options {
		if opt == nil {
			continue
		}
		if dn, ok := opt.Node.(*pg_query.Node_DefElem); ok && dn.DefElem != nil {
			if dn.DefElem.Defname == "analyze" {
				analyze = true
				break
			}
		}
	}
	if analyze && s.Query != nil {
		// EXPLAIN ANALYZE <inner> matches inner statement.
		inner := classifyRawStmt(DialectPostgres, &pg_query.RawStmt{Stmt: s.Query}, sess, opts, cs.ParserBackend)
		cs.RawVerb = "EXPLAIN_ANALYZE"
		cs.Effects = inner.Effects
		// Inherit the inner statement's diagnostic Error (if any) so callers
		// see the unmapped-form message rather than a silent unknown.
		if inner.Error != "" {
			cs.Error = inner.Error
		}
		return
	}
	// Plain EXPLAIN — read.
	cs.Effects = []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}}
}

func classifyPrepare(cs *effects.ClassifiedStatement, s *pg_query.PrepareStmt, sess SessionState, opts Options) {
	cs.RawVerb = "PREPARE"
	if s == nil || s.Query == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: PREPARE without query"
		return
	}
	cs.PreparedName = s.Name
	inner := classifyRawStmt(DialectPostgres, &pg_query.RawStmt{Stmt: s.Query}, sess, opts, cs.ParserBackend)
	cs.Effects = inner.Effects
	if inner.RawVerb != "" {
		cs.RawVerb = "PREPARE_" + inner.RawVerb
	}
	if inner.Error != "" {
		cs.Error = inner.Error
	}
}

func classifyExecute(cs *effects.ClassifiedStatement, s *pg_query.ExecuteStmt, _ SessionState, _ Options) {
	// Cache lookup is owned by Plan 05 (proxy). Plan 03 returns unknown so the
	// proxy can synthesize the cache-miss deny path per spec §7.4.
	cs.RawVerb = "EXECUTE"
	if s != nil {
		cs.PreparedName = s.Name
	}
	cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
	cs.Error = "execute: cache lookup deferred to proxy (Plan 05)"
}

func classifyDeallocate(cs *effects.ClassifiedStatement, s *pg_query.DeallocateStmt) {
	cs.RawVerb = "DEALLOCATE"
	// pg_query represents DEALLOCATE ALL with an empty Name field.
	if s != nil {
		cs.PreparedName = s.Name
	}
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupSession,
		Subtype: effects.SubtypeDiscardPlans, // §7.3: DEALLOCATE → discard_plans
	}}
}

// ---- composition / extraction helpers ----

// hasSchemaCreateEffect reports whether cs already carries a schema_create
// effect — used by classifySelect to suppress the "empty read on SELECT INTO"
// edge case.
func hasSchemaCreateEffect(cs *effects.ClassifiedStatement) bool {
	for _, e := range cs.Effects {
		if e.Group == effects.GroupSchemaCreate {
			return true
		}
	}
	return false
}

// walkSelectRelations enumerates relations referenced anywhere in a SelectStmt
// (FROM, JOINs, sub-selects, set-ops, CTE bodies). The returned Resolution is
// folded across all collected relations per §6.2.
func walkSelectRelations(s *pg_query.SelectStmt, sess SessionState) ([]effects.ObjectRef, effects.Resolution) {
	if s == nil {
		return nil, effects.ResolutionQualified
	}
	objs := []effects.ObjectRef{}
	ress := []effects.Resolution{}
	collectRangeRefs(s.FromClause, sess, &objs, &ress)
	if s.WithClause != nil {
		// CTE relations themselves are not added; their bodies' relations are
		// reached via the CTE's Ctequery.
		for _, c := range s.WithClause.Ctes {
			if c == nil {
				continue
			}
			cn, ok := c.Node.(*pg_query.Node_CommonTableExpr)
			if !ok || cn.CommonTableExpr == nil || cn.CommonTableExpr.Ctequery == nil {
				continue
			}
			if inner, ok := cn.CommonTableExpr.Ctequery.Node.(*pg_query.Node_SelectStmt); ok && inner.SelectStmt != nil {
				more, mres := walkSelectRelations(inner.SelectStmt, sess)
				objs = append(objs, more...)
				ress = append(ress, mres)
			}
		}
	}
	if s.Larg != nil {
		more, mres := walkSelectRelations(s.Larg, sess)
		objs = append(objs, more...)
		ress = append(ress, mres)
	}
	if s.Rarg != nil {
		more, mres := walkSelectRelations(s.Rarg, sess)
		objs = append(objs, more...)
		ress = append(ress, mres)
	}
	return objs, effects.Fold(ress)
}

// walkRangeRelations enumerates RangeVar nodes inside a list of *pg_query.Node
// (used for FROM lists, USING lists, etc.).
func walkRangeRelations(list []*pg_query.Node, sess SessionState) ([]effects.ObjectRef, effects.Resolution) {
	objs := []effects.ObjectRef{}
	ress := []effects.Resolution{}
	collectRangeRefs(list, sess, &objs, &ress)
	return objs, effects.Fold(ress)
}

// collectRangeRefs walks a list of nodes and appends any RangeVar references
// (and recurses into JoinExpr / RangeSubselect children).
func collectRangeRefs(list []*pg_query.Node, sess SessionState, objs *[]effects.ObjectRef, ress *[]effects.Resolution) {
	for _, n := range list {
		if n == nil {
			continue
		}
		switch v := n.Node.(type) {
		case *pg_query.Node_RangeVar:
			obj, res := extractRelation(v.RangeVar, sess, effects.ObjectTable)
			*objs = append(*objs, obj)
			*ress = append(*ress, res)
		case *pg_query.Node_JoinExpr:
			if v.JoinExpr != nil {
				collectRangeRefs([]*pg_query.Node{v.JoinExpr.Larg, v.JoinExpr.Rarg}, sess, objs, ress)
			}
		case *pg_query.Node_RangeSubselect:
			if v.RangeSubselect != nil && v.RangeSubselect.Subquery != nil {
				if sel, ok := v.RangeSubselect.Subquery.Node.(*pg_query.Node_SelectStmt); ok && sel.SelectStmt != nil {
					more, mres := walkSelectRelations(sel.SelectStmt, sess)
					*objs = append(*objs, more...)
					*ress = append(*ress, mres)
				}
			}
		}
	}
}

// appendCTEEffects walks a WITH-clause and appends each CTE body's effects to
// the outer statement. Spec §20: data-modifying CTEs (INSERT/UPDATE/DELETE
// inside WITH) propagate to the outer statement.
func appendCTEEffects(cs *effects.ClassifiedStatement, with *pg_query.WithClause, sess SessionState, opts Options) {
	if with == nil {
		return
	}
	for _, c := range with.Ctes {
		if c == nil {
			continue
		}
		cn, ok := c.Node.(*pg_query.Node_CommonTableExpr)
		if !ok || cn.CommonTableExpr == nil || cn.CommonTableExpr.Ctequery == nil {
			continue
		}
		inner := classifyRawStmt(DialectPostgres, &pg_query.RawStmt{Stmt: cn.CommonTableExpr.Ctequery}, sess, opts, cs.ParserBackend)
		cs.Effects = append(cs.Effects, inner.Effects...)
	}
}

func hasReturningList(list []*pg_query.Node) bool { return len(list) > 0 }
