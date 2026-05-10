// Package postgres — ast_misc.go owns the procedural/maintenance/lock/notify
// handlers. These statements have no shared structural shape with DML — each
// one maps to a single Effect with a fixed Group/Subtype, with the exception
// of LOCK (which carries ObjectTable refs from its Relations list).
//
// VACUUM and ANALYZE both arrive as Node_VacuumStmt; the IsVacuumcmd flag
// distinguishes the two for RawVerb purposes only — both classify as
// maintenance.
//
// LISTEN / NOTIFY / UNLISTEN do not yet have a dedicated channel object kind
// in Phase 1; the channel name is recorded in RawVerb so policy authors can
// inspect it without us having to mint a new ObjectKind.
package postgres

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// classifyCall — CALL my_proc(args). Procedural call to a stored procedure.
func classifyCall(cs *effects.ClassifiedStatement, _ *pg_query.CallStmt) {
	cs.RawVerb = "CALL"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupProcedural,
		Subtype: effects.SubtypeCall,
	}}
}

// classifyDo — DO $$ ... $$. Anonymous procedural block.
func classifyDo(cs *effects.ClassifiedStatement, _ *pg_query.DoStmt) {
	cs.RawVerb = "DO"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupProcedural,
		Subtype: effects.SubtypeDoOrAnon,
	}}
}

// classifyMaintenance — VACUUM / ANALYZE (both arrive as VacuumStmt).
// IsVacuumcmd distinguishes them for RawVerb only; both fall under maintenance.
func classifyMaintenance(cs *effects.ClassifiedStatement, s *pg_query.VacuumStmt) {
	if s != nil && !s.IsVacuumcmd {
		cs.RawVerb = "ANALYZE"
	} else {
		cs.RawVerb = "VACUUM"
	}
	cs.Effects = []effects.Effect{{Group: effects.GroupMaintenance}}
}

// classifyReindex — REINDEX TABLE / INDEX / SCHEMA / DATABASE. Maintenance.
func classifyReindex(cs *effects.ClassifiedStatement, _ *pg_query.ReindexStmt) {
	cs.RawVerb = "REINDEX"
	cs.Effects = []effects.Effect{{Group: effects.GroupMaintenance}}
}

// classifyCluster — CLUSTER [VERBOSE] [table [USING index]]. Maintenance.
func classifyCluster(cs *effects.ClassifiedStatement, _ *pg_query.ClusterStmt) {
	cs.RawVerb = "CLUSTER"
	cs.Effects = []effects.Effect{{Group: effects.GroupMaintenance}}
}

// classifyCheckpoint — CHECKPOINT. Maintenance.
func classifyCheckpoint(cs *effects.ClassifiedStatement) {
	cs.RawVerb = "CHECKPOINT"
	cs.Effects = []effects.Effect{{Group: effects.GroupMaintenance}}
}

// classifyLock — LOCK [TABLE] rels IN mode MODE [NOWAIT]. Single lock effect
// carrying ObjectTable refs for every relation in the list.
func classifyLock(cs *effects.ClassifiedStatement, s *pg_query.LockStmt, sess SessionState) {
	cs.RawVerb = "LOCK"
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupLock}}
		return
	}
	objs, res := walkRangeRelations(s.Relations, sess)
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupLock,
		Objects:    objs,
		Resolution: res,
	}}
}

// classifyNotify — LISTEN / NOTIFY / UNLISTEN. Phase 1 doesn't model channel
// names as a distinct ObjectKind; we surface the channel via RawVerb so policy
// authors can grep for it but the effect itself carries no Objects.
func classifyNotify(cs *effects.ClassifiedStatement, n *pg_query.Node) {
	verb := "LISTEN_OR_NOTIFY"
	if n != nil {
		switch v := n.Node.(type) {
		case *pg_query.Node_ListenStmt:
			verb = "LISTEN"
			if v.ListenStmt != nil && v.ListenStmt.Conditionname != "" {
				verb = "LISTEN=" + v.ListenStmt.Conditionname
			}
		case *pg_query.Node_NotifyStmt:
			verb = "NOTIFY"
			if v.NotifyStmt != nil && v.NotifyStmt.Conditionname != "" {
				verb = "NOTIFY=" + v.NotifyStmt.Conditionname
			}
		case *pg_query.Node_UnlistenStmt:
			verb = "UNLISTEN"
			if v.UnlistenStmt != nil && v.UnlistenStmt.Conditionname != "" {
				verb = "UNLISTEN=" + v.UnlistenStmt.Conditionname
			}
		}
	}
	cs.RawVerb = verb
	cs.Effects = []effects.Effect{{Group: effects.GroupNotify}}
}
