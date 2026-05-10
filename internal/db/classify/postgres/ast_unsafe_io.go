// Package postgres — ast_unsafe_io.go owns the unsafe-IO function-call detector
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
// The shared AST walker lives in walkFuncCalls (escalation.go). Adding new
// expression carriers (e.g. a new FuncCall-bearing node) means extending the
// switch there; FuncCall is matched only on the Node type itself so a column
// reference named "pg_read_file" cannot trip the detector.
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
	walkFuncCalls(n, func(fc *pg_query.FuncCall) {
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

// TODO Phase 2: catalog-aware FDW detection. A foreign-table reference in a
// FROM clause should classify the verb's primary group as the original verb
// plus an unsafe_io secondary per Appendix B. Phase 1 has no catalog access
// so this is left as a documented gap; corpus rows that need FDW detection
// stay in the open-questions list.
