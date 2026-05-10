// Package postgres — ast_stubs.go contains no-op handler stubs for SQL
// families whose real implementation hasn't landed yet. Each stub writes a
// single GroupUnknown effect and a "not yet implemented" Error so the
// dispatcher's "always one effect" invariant holds. As real handlers ship in
// Tasks 6–13, the matching stub is deleted from this file.
package postgres

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func stub(cs *effects.ClassifiedStatement, family string) {
	cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
	cs.Error = "unmapped form: " + family + " not yet implemented"
}

// ---- COPY (Task 9) ----

func classifyCopy(cs *effects.ClassifiedStatement, _ *pg_query.CopyStmt, _ SessionState, _ Options) {
	stub(cs, "copy")
}

// ---- external-IO DDL (Task 10) ----

func classifyCreateSubscription(cs *effects.ClassifiedStatement, _ *pg_query.CreateSubscriptionStmt) {
	stub(cs, "create_subscription")
}
func classifyAlterSubscription(cs *effects.ClassifiedStatement, _ *pg_query.AlterSubscriptionStmt) {
	stub(cs, "alter_subscription")
}
func classifyDropSubscription(cs *effects.ClassifiedStatement, _ *pg_query.DropSubscriptionStmt) {
	stub(cs, "drop_subscription")
}
func classifyCreateServer(cs *effects.ClassifiedStatement, _ *pg_query.CreateForeignServerStmt) {
	stub(cs, "create_server")
}
func classifyAlterServer(cs *effects.ClassifiedStatement, _ *pg_query.AlterForeignServerStmt) {
	stub(cs, "alter_server")
}
func classifyCreateUserMapping(cs *effects.ClassifiedStatement, _ *pg_query.CreateUserMappingStmt) {
	stub(cs, "create_user_mapping")
}
func classifyAlterUserMapping(cs *effects.ClassifiedStatement, _ *pg_query.AlterUserMappingStmt) {
	stub(cs, "alter_user_mapping")
}
func classifyDropUserMapping(cs *effects.ClassifiedStatement, _ *pg_query.DropUserMappingStmt) {
	stub(cs, "drop_user_mapping")
}
func classifyCreateTablespace(cs *effects.ClassifiedStatement, _ *pg_query.CreateTableSpaceStmt) {
	stub(cs, "create_tablespace")
}
func classifyAlterTablespace(cs *effects.ClassifiedStatement, _ *pg_query.AlterTableSpaceOptionsStmt) {
	stub(cs, "alter_tablespace")
}

// ---- procedural / maintenance / lock / notify (Task 12) ----

func classifyCall(cs *effects.ClassifiedStatement, _ *pg_query.CallStmt) { stub(cs, "call") }
func classifyDo(cs *effects.ClassifiedStatement, _ *pg_query.DoStmt)     { stub(cs, "do") }
func classifyMaintenance(cs *effects.ClassifiedStatement, _ *pg_query.VacuumStmt) {
	stub(cs, "maintenance")
}
func classifyReindex(cs *effects.ClassifiedStatement, _ *pg_query.ReindexStmt) {
	stub(cs, "reindex")
}
func classifyCluster(cs *effects.ClassifiedStatement, _ *pg_query.ClusterStmt) {
	stub(cs, "cluster")
}
func classifyCheckpoint(cs *effects.ClassifiedStatement) { stub(cs, "checkpoint") }
func classifyLock(cs *effects.ClassifiedStatement, _ *pg_query.LockStmt, _ SessionState) {
	stub(cs, "lock")
}
func classifyNotify(cs *effects.ClassifiedStatement, _ *pg_query.Node) { stub(cs, "notify") }
