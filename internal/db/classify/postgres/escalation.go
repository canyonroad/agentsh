// Package postgres — escalation.go owns the §7.6 "escalate unknown function
// calls" knob and the shared FuncCall AST walker used by both the escalation
// detector and the unsafe-IO detector (ast_unsafe_io.go).
//
// When Options.EscalateUnknownFunctions is true, classifySelect calls
// collectFuncCallsAny over the SELECT body. If any FuncCall's canonical
// lowercase name is NOT a member of the supplied allowlist, a secondary
// `procedural` effect (no Subtype) is appended; canonical ordering then
// promotes it ahead of `read` so callers see the elevated classification.
//
// The walker (walkFuncCalls) is stack-based over the relevant pg_query Node
// one-of variants. It is shared with appendUnsafeIO so any new FuncCall-
// bearing AST node only has to be added in one place.
package postgres

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// collectFuncCallsAny returns true if the SelectStmt contains any FuncCall
// whose canonical lowercase name is NOT in allow. A nil/empty allow map means
// every call counts as unknown (so any FuncCall trips the flag).
//
// Schema-qualified names are matched against their dotted lowercase form
// (e.g. "public.now"). Bare names are matched against the single lowercase
// element. The allowlist contract (see Options.SafeFunctionAllowlist) is
// that callers store keys in lowercase; we don't re-lowercase the lookup
// key here.
func collectFuncCallsAny(s *pg_query.SelectStmt, allow map[string]struct{}) bool {
	if s == nil {
		return false
	}
	found := false
	walkFuncCalls(s, func(fc *pg_query.FuncCall) {
		if found {
			return
		}
		name := canonicalFuncName(fc.Funcname)
		if name == "" {
			return
		}
		if _, ok := allow[name]; !ok {
			found = true
		}
	})
	return found
}

// canonicalFuncName joins a FuncCall's Funcname parts into a single
// lowercase dotted string. A bare unqualified name returns just the
// lowercased identifier; "schema.name" is preserved with both parts
// lowercased. Non-String_ nodes (which shouldn't appear in Funcname
// per pg_query's grammar) are skipped.
func canonicalFuncName(parts []*pg_query.Node) string {
	if len(parts) == 0 {
		return ""
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == nil {
			continue
		}
		if sv, ok := p.Node.(*pg_query.Node_String_); ok && sv.String_ != nil {
			out = append(out, strings.ToLower(sv.String_.Sval))
		}
	}
	return strings.Join(out, ".")
}

// walkFuncCalls descends through the supplied AST subtree, invoking visit for
// every *pg_query.FuncCall node it encounters. The walker is stack-based and
// covers every node variant that can carry a FuncCall in an expression
// context: SelectStmt parts, A_Expr, BoolExpr, FuncCall.Args, SubLink,
// ResTarget, RangeFunction, TypeCast, CaseExpr (and CaseWhen),
// CoalesceExpr, MinMaxExpr, ArrayExpr, A_ArrayExpr, RowExpr, NullTest,
// BooleanTest, List, JoinExpr, RangeSubselect, CommonTableExpr,
// NamedArgExpr, SortBy.
//
// Unhandled node variants are leaves for our purposes — they cannot
// transitively contain FuncCall nodes in any pattern Plan 03 needs. A new
// FuncCall-bearing variant must be added to the switch below.
func walkFuncCalls(root any, visit func(*pg_query.FuncCall)) {
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
			// Unhandled node types are leaves. New FuncCall-carrying variants
			// would need to be added to the switch above.
		}
	}
}
