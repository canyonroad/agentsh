// Package postgres — ast_unsafe_io.go owns the unsafe-IO function-call walker
// per spec Appendix B. SELECT / INSERT-SELECT / UPDATE / DELETE / COPY can all
// embed FuncCall expressions whose names are server-side IO primitives
// (pg_read_file, pg_ls_dir, pg_stat_file, lo_import, lo_export, dblink*); when
// any of those appear we append an unsafe_io effect with the appropriate
// subtype and a filesystem_path object carrying the literal path argument
// (or empty path + unresolved resolution when the argument is dynamic).
//
// Phase 1 deliberately skips:
//   - xml2 / pgxml URL fetch (`xpath_table`, etc.) — deferred to Phase 2 per
//     the design doc.
//   - FDW-relation access detection — requires catalog lookup; left as a
//     TODO for Phase 2 per Task 11 Step 3 of the plan.
//
// The walker is stack-based over the relevant pg_query Node one-of variants.
// Adding new expression carriers (e.g. a new FuncCall-bearing node) means
// extending the switch in walkUnsafe; FuncCall is matched only on the Node
// type itself so a column reference named "pg_read_file" cannot trip the
// detector.
package postgres

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// unsafeIOFunctions maps lowercase Postgres function names to the unsafe_io
// subtype they emit. Schema qualifiers are stripped before lookup so e.g.
// `public.pg_read_file('/etc/passwd')` matches the same as the bare form.
//
// pathArgIndex selects which argument carries the filesystem path:
//   - lo_import('/path')       → arg index 0
//   - lo_export(oid, '/path')  → arg index 1
//   - all pg_*_file/dir/stat   → arg index 0
//   - dblink* uses connection-string semantics; Phase 1 emits an empty
//     filesystem_path so the policy can deny on the group/subtype alone.
type unsafeIOSpec struct {
	subtype      effects.Subtype
	pathArgIndex int
	// emitPath controls whether we attempt to extract a path arg at all.
	// dblink* connection strings aren't filesystem paths; Phase 1 emits
	// an empty path object so the policy still sees the unsafe_io effect.
	emitPath bool
}

var unsafeIOFunctions = map[string]unsafeIOSpec{
	"pg_read_file":        {subtype: effects.SubtypeServerFileRead, pathArgIndex: 0, emitPath: true},
	"pg_read_binary_file": {subtype: effects.SubtypeServerFileRead, pathArgIndex: 0, emitPath: true},
	"pg_ls_dir":           {subtype: effects.SubtypeServerFileRead, pathArgIndex: 0, emitPath: true},
	"pg_ls_logdir":        {subtype: effects.SubtypeServerFileRead, pathArgIndex: 0, emitPath: false},
	"pg_ls_waldir":        {subtype: effects.SubtypeServerFileRead, pathArgIndex: 0, emitPath: false},
	"pg_stat_file":        {subtype: effects.SubtypeServerFileRead, pathArgIndex: 0, emitPath: true},
	"lo_import":           {subtype: effects.SubtypeLargeObjectIO, pathArgIndex: 0, emitPath: true},
	"lo_export":           {subtype: effects.SubtypeLargeObjectIO, pathArgIndex: 1, emitPath: true},
	"dblink":              {subtype: effects.SubtypeDblinkCall, emitPath: false},
	"dblink_exec":         {subtype: effects.SubtypeDblinkCall, emitPath: false},
	"dblink_open":         {subtype: effects.SubtypeDblinkCall, emitPath: false},
	"dblink_send_query":   {subtype: effects.SubtypeDblinkCall, emitPath: false},
}

// appendUnsafeIO walks any AST subtree (typically a SelectStmt's projection,
// WHERE, JOIN-ON, sub-link, or arbitrary expression) and appends one
// unsafe_io effect per matched FuncCall. The caller is responsible for
// ordering effects via effects.Order; this function only appends.
func appendUnsafeIO(cs *effects.ClassifiedStatement, n any, _ SessionState) {
	walkUnsafe(n, func(fc *pg_query.FuncCall) {
		name := lastFuncNamePart(fc.Funcname)
		spec, ok := unsafeIOFunctions[name]
		if !ok {
			return
		}
		obj, res := pathObjectFromArg(fc.Args, spec)
		eff := effects.Effect{
			Group:      effects.GroupUnsafeIO,
			Subtype:    spec.subtype,
			Objects:    []effects.ObjectRef{obj},
			Resolution: res,
		}
		cs.Effects = append(cs.Effects, eff)
	})
}

// lastFuncNamePart returns the lowercased final element of a FuncCall's
// Funcname list (i.e. the function name without schema qualifier). Returns
// empty string if the list is empty or its tail isn't a String_ node.
func lastFuncNamePart(parts []*pg_query.Node) string {
	if len(parts) == 0 {
		return ""
	}
	tail := parts[len(parts)-1]
	if tail == nil {
		return ""
	}
	if sv, ok := tail.Node.(*pg_query.Node_String_); ok && sv.String_ != nil {
		return strings.ToLower(sv.String_.Sval)
	}
	return ""
}

// pathObjectFromArg returns the ObjectRef for an unsafe-IO call. When emitPath
// is false (e.g. dblink) we always return an empty filesystem_path with
// resolution=qualified — there's nothing dynamic to resolve, the call itself
// is the signal. When emitPath is true and the indexed argument is a string
// literal we return the literal value; otherwise the path is empty and
// resolution is unresolved (dynamic argument).
func pathObjectFromArg(args []*pg_query.Node, spec unsafeIOSpec) (effects.ObjectRef, effects.Resolution) {
	obj := effects.ObjectRef{Kind: effects.ObjectFilesystemPath}
	if !spec.emitPath {
		return obj, effects.ResolutionQualified
	}
	if spec.pathArgIndex >= len(args) {
		return obj, effects.ResolutionUnresolved
	}
	arg := args[spec.pathArgIndex]
	if arg == nil {
		return obj, effects.ResolutionUnresolved
	}
	if path, ok := stringLiteralValue(arg); ok {
		obj.Path = path
		return obj, effects.ResolutionQualified
	}
	return obj, effects.ResolutionUnresolved
}

// stringLiteralValue extracts a string literal value from an A_Const argument.
// A TypeCast wrapping the literal (e.g. 'foo'::text) is unwrapped once.
func stringLiteralValue(n *pg_query.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	switch v := n.Node.(type) {
	case *pg_query.Node_AConst:
		if v.AConst == nil {
			return "", false
		}
		if sv, ok := v.AConst.Val.(*pg_query.A_Const_Sval); ok && sv.Sval != nil {
			return sv.Sval.Sval, true
		}
	case *pg_query.Node_TypeCast:
		if v.TypeCast != nil {
			return stringLiteralValue(v.TypeCast.Arg)
		}
	}
	return "", false
}

// walkUnsafe descends through the supplied AST subtree, invoking visit for
// every *pg_query.FuncCall node it encounters. The walker is stack-based and
// covers every node variant that can carry a FuncCall in an expression
// context: SelectStmt parts, A_Expr, BoolExpr, FuncCall.Args, SubLink,
// ResTarget, RangeFunction, TypeCast, CaseExpr (and CaseWhen),
// CoalesceExpr, MinMaxExpr, ArrayExpr, A_ArrayExpr, RowExpr, NullTest,
// BooleanTest, List, JoinExpr, RangeSubselect.
//
// Unhandled node variants are leaves for our purposes — they cannot
// transitively contain unsafe-IO calls in any pattern Plan 03 needs.
func walkUnsafe(root any, visit func(*pg_query.FuncCall)) {
	type frame any
	stack := []frame{root}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if top == nil {
			continue
		}
		switch v := top.(type) {
		case []*pg_query.Node:
			for _, n := range v {
				if n != nil {
					stack = append(stack, n)
				}
			}
		case *pg_query.Node:
			if v == nil || v.Node == nil {
				continue
			}
			stack = append(stack, v.Node)

		case *pg_query.SelectStmt:
			if v == nil {
				continue
			}
			stack = append(stack, v.TargetList)
			stack = append(stack, v.FromClause)
			stack = append(stack, v.GroupClause)
			stack = append(stack, v.WindowClause)
			stack = append(stack, v.ValuesLists)
			stack = append(stack, v.SortClause)
			stack = append(stack, v.DistinctClause)
			stack = append(stack, v.LockingClause)
			if v.WhereClause != nil {
				stack = append(stack, v.WhereClause)
			}
			if v.HavingClause != nil {
				stack = append(stack, v.HavingClause)
			}
			if v.LimitOffset != nil {
				stack = append(stack, v.LimitOffset)
			}
			if v.LimitCount != nil {
				stack = append(stack, v.LimitCount)
			}
			if v.WithClause != nil {
				for _, c := range v.WithClause.Ctes {
					if c != nil {
						stack = append(stack, c)
					}
				}
			}
			if v.Larg != nil {
				stack = append(stack, v.Larg)
			}
			if v.Rarg != nil {
				stack = append(stack, v.Rarg)
			}

		// ---- one-of variants we descend into ----
		case *pg_query.Node_SelectStmt:
			if v.SelectStmt != nil {
				stack = append(stack, v.SelectStmt)
			}
		case *pg_query.Node_FuncCall:
			if v.FuncCall != nil {
				visit(v.FuncCall)
				stack = append(stack, v.FuncCall.Args)
				stack = append(stack, v.FuncCall.AggOrder)
				if v.FuncCall.AggFilter != nil {
					stack = append(stack, v.FuncCall.AggFilter)
				}
			}
		case *pg_query.Node_AExpr:
			if v.AExpr != nil {
				if v.AExpr.Lexpr != nil {
					stack = append(stack, v.AExpr.Lexpr)
				}
				if v.AExpr.Rexpr != nil {
					stack = append(stack, v.AExpr.Rexpr)
				}
			}
		case *pg_query.Node_BoolExpr:
			if v.BoolExpr != nil {
				stack = append(stack, v.BoolExpr.Args)
			}
		case *pg_query.Node_SubLink:
			if v.SubLink != nil {
				if v.SubLink.Testexpr != nil {
					stack = append(stack, v.SubLink.Testexpr)
				}
				if v.SubLink.Subselect != nil {
					stack = append(stack, v.SubLink.Subselect)
				}
			}
		case *pg_query.Node_ResTarget:
			if v.ResTarget != nil && v.ResTarget.Val != nil {
				stack = append(stack, v.ResTarget.Val)
			}
		case *pg_query.Node_RangeFunction:
			if v.RangeFunction != nil {
				stack = append(stack, v.RangeFunction.Functions)
			}
		case *pg_query.Node_TypeCast:
			if v.TypeCast != nil && v.TypeCast.Arg != nil {
				stack = append(stack, v.TypeCast.Arg)
			}
		case *pg_query.Node_CaseExpr:
			if v.CaseExpr != nil {
				if v.CaseExpr.Arg != nil {
					stack = append(stack, v.CaseExpr.Arg)
				}
				stack = append(stack, v.CaseExpr.Args)
				if v.CaseExpr.Defresult != nil {
					stack = append(stack, v.CaseExpr.Defresult)
				}
			}
		case *pg_query.Node_CaseWhen:
			if v.CaseWhen != nil {
				if v.CaseWhen.Expr != nil {
					stack = append(stack, v.CaseWhen.Expr)
				}
				if v.CaseWhen.Result != nil {
					stack = append(stack, v.CaseWhen.Result)
				}
			}
		case *pg_query.Node_CoalesceExpr:
			if v.CoalesceExpr != nil {
				stack = append(stack, v.CoalesceExpr.Args)
			}
		case *pg_query.Node_MinMaxExpr:
			if v.MinMaxExpr != nil {
				stack = append(stack, v.MinMaxExpr.Args)
			}
		case *pg_query.Node_ArrayExpr:
			if v.ArrayExpr != nil {
				stack = append(stack, v.ArrayExpr.Elements)
			}
		case *pg_query.Node_AArrayExpr:
			if v.AArrayExpr != nil {
				stack = append(stack, v.AArrayExpr.Elements)
			}
		case *pg_query.Node_RowExpr:
			if v.RowExpr != nil {
				stack = append(stack, v.RowExpr.Args)
			}
		case *pg_query.Node_NullTest:
			if v.NullTest != nil && v.NullTest.Arg != nil {
				stack = append(stack, v.NullTest.Arg)
			}
		case *pg_query.Node_BooleanTest:
			if v.BooleanTest != nil && v.BooleanTest.Arg != nil {
				stack = append(stack, v.BooleanTest.Arg)
			}
		case *pg_query.Node_List:
			if v.List != nil {
				stack = append(stack, v.List.Items)
			}
		case *pg_query.Node_JoinExpr:
			if v.JoinExpr != nil {
				if v.JoinExpr.Larg != nil {
					stack = append(stack, v.JoinExpr.Larg)
				}
				if v.JoinExpr.Rarg != nil {
					stack = append(stack, v.JoinExpr.Rarg)
				}
				if v.JoinExpr.Quals != nil {
					stack = append(stack, v.JoinExpr.Quals)
				}
			}
		case *pg_query.Node_RangeSubselect:
			if v.RangeSubselect != nil && v.RangeSubselect.Subquery != nil {
				stack = append(stack, v.RangeSubselect.Subquery)
			}
		case *pg_query.Node_CommonTableExpr:
			if v.CommonTableExpr != nil && v.CommonTableExpr.Ctequery != nil {
				stack = append(stack, v.CommonTableExpr.Ctequery)
			}
		case *pg_query.Node_NamedArgExpr:
			if v.NamedArgExpr != nil && v.NamedArgExpr.Arg != nil {
				stack = append(stack, v.NamedArgExpr.Arg)
			}
		case *pg_query.Node_SortBy:
			if v.SortBy != nil && v.SortBy.Node != nil {
				stack = append(stack, v.SortBy.Node)
			}

		// Leaf or non-FuncCall-carrying variants — intentionally ignored.
		default:
			// Unhandled node types are leaves for unsafe-IO detection. New
			// FuncCall-carrying variants would need to be added above.
		}
	}
}

// TODO Phase 2: catalog-aware FDW detection. A foreign-table reference in a
// FROM clause should classify the verb's primary group as the original verb
// plus an unsafe_io secondary per Appendix B. Phase 1 has no catalog access
// so this is left as a documented gap; corpus rows that need FDW detection
// stay in the open-questions list.
