// Package postgres — ast_copy.go owns the §7.3 COPY family. COPY is unique in
// that it can carry up to three effects: a primary unsafe_io effect for the
// PATH/PROGRAM forms, a secondary bulk_load/bulk_export effect for the data
// direction, and (for COPY (query) TO STDOUT) the inner verb's effects per the
// §20 effect-set bypass. PATH attaches a filesystem_path object; PROGRAM
// attaches a program object whose Argv0 is the first whitespace-split token
// (the binary that would be exec'd before any shell pipeline).
//
// Spec table (§7.3 + Appendix B):
//
//	COPY t TO STDOUT       → bulk_export(copy_to_stdout) + read
//	COPY t FROM STDIN      → bulk_load(copy_from_stdin)
//	COPY t TO '/path'      → unsafe_io(copy_to_path) + bulk_export + read
//	COPY t FROM '/path'    → unsafe_io(copy_from_path) + bulk_load
//	COPY t TO PROGRAM 'c'  → unsafe_io(copy_to_program) + bulk_export
//	COPY t FROM PROGRAM 'c'→ unsafe_io(copy_from_program) + bulk_load
//	COPY (q) TO STDOUT     → bulk_export(copy_to_stdout) + inner verb effects
package postgres

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// classifyCopy dispatches a CopyStmt to the correct variant handler.
func classifyCopy(cs *effects.ClassifiedStatement, s *pg_query.CopyStmt, sess SessionState, opts Options) {
	cs.RawVerb = "COPY"
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CopyStmt"
		return
	}

	isFrom := s.IsFrom
	hasFile := s.Filename != "" && !s.IsProgram
	hasProgram := s.Filename != "" && s.IsProgram

	switch {
	case s.Relation != nil && hasProgram && !isFrom:
		// COPY t TO PROGRAM 'cmd'
		appendCopyEffects(cs, s, sess, effects.SubtypeCopyToProgram, effects.GroupBulkExport, "TO_PROGRAM")
	case s.Relation != nil && hasProgram && isFrom:
		// COPY t FROM PROGRAM 'cmd'
		appendCopyEffects(cs, s, sess, effects.SubtypeCopyFromProgram, effects.GroupBulkLoad, "FROM_PROGRAM")
	case s.Relation != nil && hasFile && !isFrom:
		// COPY t TO '/path'
		appendCopyEffects(cs, s, sess, effects.SubtypeCopyToPath, effects.GroupBulkExport, "TO_PATH")
	case s.Relation != nil && hasFile && isFrom:
		// COPY t FROM '/path'
		appendCopyEffects(cs, s, sess, effects.SubtypeCopyFromPath, effects.GroupBulkLoad, "FROM_PATH")
	case s.Relation != nil && !isFrom:
		// COPY t TO STDOUT
		appendCopyStdoutEffects(cs, s, sess)
		cs.BulkOp = effects.BulkOpOut
	case s.Relation != nil && isFrom:
		// COPY t FROM STDIN
		obj, res := extractRelation(s.Relation, sess, effects.ObjectTable)
		cs.RawVerb = "COPY_FROM_STDIN"
		cs.BulkOp = effects.BulkOpIn
		cs.Effects = []effects.Effect{{
			Group:      effects.GroupBulkLoad,
			Subtype:    effects.SubtypeCopyFromStdin,
			Objects:    []effects.ObjectRef{obj},
			Resolution: res,
		}}
	case s.Query != nil:
		// COPY (<query>) TO STDOUT
		appendCopyQueryEffects(cs, s, sess, opts)
		cs.BulkOp = effects.BulkOpOut
	default:
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: COPY shape not recognized"
	}
}

// appendCopyEffects builds the effect set for the four PATH/PROGRAM variants.
// All four share the same shape: primary unsafe_io effect carrying the table
// plus the path/program ObjectRef, then a secondary bulk_load or bulk_export
// effect carrying just the table. TO_PATH / TO_PROGRAM additionally append a
// read effect on the table per Appendix B (the export reads the source).
func appendCopyEffects(cs *effects.ClassifiedStatement, s *pg_query.CopyStmt, sess SessionState, sub effects.Subtype, sec effects.Group, suffix string) {
	cs.RawVerb = "COPY_" + suffix
	tgt, tgtRes := extractRelation(s.Relation, sess, effects.ObjectTable)
	primaryObjs := []effects.ObjectRef{tgt}
	switch sub {
	case effects.SubtypeCopyToPath, effects.SubtypeCopyFromPath:
		primaryObjs = append(primaryObjs, effects.ObjectRef{
			Kind: effects.ObjectFilesystemPath,
			Path: s.Filename,
		})
	case effects.SubtypeCopyToProgram, effects.SubtypeCopyFromProgram:
		primaryObjs = append(primaryObjs, effects.ObjectRef{
			Kind:  effects.ObjectProgram,
			Argv0: firstWhitespaceToken(s.Filename),
		})
	}
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      effects.GroupUnsafeIO,
		Subtype:    sub,
		Objects:    primaryObjs,
		Resolution: tgtRes,
	})
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      sec,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
	})
	if sec == effects.GroupBulkExport {
		// TO PATH / TO PROGRAM: also produces a read of the target table per Appendix B.
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:      effects.GroupRead,
			Objects:    []effects.ObjectRef{tgt},
			Resolution: tgtRes,
		})
	}
}

// appendCopyStdoutEffects handles the canonical `COPY t TO STDOUT` case:
// primary bulk_export(copy_to_stdout) + secondary read on the table.
func appendCopyStdoutEffects(cs *effects.ClassifiedStatement, s *pg_query.CopyStmt, sess SessionState) {
	cs.RawVerb = "COPY_TO_STDOUT"
	tgt, res := extractRelation(s.Relation, sess, effects.ObjectTable)
	cs.Effects = []effects.Effect{
		{
			Group:      effects.GroupBulkExport,
			Subtype:    effects.SubtypeCopyToStdout,
			Objects:    []effects.ObjectRef{tgt},
			Resolution: res,
		},
		{
			Group:      effects.GroupRead,
			Objects:    []effects.ObjectRef{tgt},
			Resolution: res,
		},
	}
}

// appendCopyQueryEffects handles `COPY (<query>) TO STDOUT`, where the inner
// query is recursively classified and its effects appended to the outer
// statement. Per spec §20 (effect-set bypass), an inner DELETE/UPDATE/INSERT
// keeps its mutation effect — the policy engine then sees both the
// bulk_export and the inner verb (e.g. delete) and denies on either.
//
// The primary bulk_export effect itself carries no Objects: each inner effect
// already references the relations it touches, and adding the wrapped query
// would double-count.
func appendCopyQueryEffects(cs *effects.ClassifiedStatement, s *pg_query.CopyStmt, sess SessionState, opts Options) {
	cs.RawVerb = "COPY_QUERY_TO_STDOUT"
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:   effects.GroupBulkExport,
		Subtype: effects.SubtypeCopyToStdout,
	})
	if s.Query == nil {
		return
	}
	inner := classifyRawStmt(DialectPostgres, &pg_query.RawStmt{Stmt: s.Query}, sess, opts, cs.ParserBackend)
	cs.Effects = append(cs.Effects, inner.Effects...)
}

// firstWhitespaceToken returns the leading non-whitespace run of s — i.e. the
// program name a shell-less PROGRAM clause would invoke. Empty input returns
// empty.
func firstWhitespaceToken(s string) string {
	for i, r := range s {
		if r == ' ' || r == '\t' || r == '\n' {
			return s[:i]
		}
	}
	return s
}
