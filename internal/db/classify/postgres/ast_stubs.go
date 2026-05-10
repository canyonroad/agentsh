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

// ---- DDL (Task 7) ----

func classifyCreateTable(cs *effects.ClassifiedStatement, _ *pg_query.CreateStmt, _ SessionState) {
	stub(cs, "create_table")
}
func classifyAlter(cs *effects.ClassifiedStatement, _ *pg_query.AlterTableStmt, _ SessionState) {
	stub(cs, "alter")
}
func classifyDrop(cs *effects.ClassifiedStatement, _ *pg_query.DropStmt, _ SessionState) {
	stub(cs, "drop")
}
func classifyTruncate(cs *effects.ClassifiedStatement, _ *pg_query.TruncateStmt, _ SessionState) {
	stub(cs, "truncate")
}
func classifyCreateIndex(cs *effects.ClassifiedStatement, _ *pg_query.IndexStmt, _ SessionState) {
	stub(cs, "create_index")
}
func classifyCreateView(cs *effects.ClassifiedStatement, _ *pg_query.ViewStmt, _ SessionState) {
	stub(cs, "create_view")
}
func classifyCreateSchema(cs *effects.ClassifiedStatement, _ *pg_query.CreateSchemaStmt) {
	stub(cs, "create_schema")
}
func classifyCreateFunction(cs *effects.ClassifiedStatement, _ *pg_query.CreateFunctionStmt) {
	stub(cs, "create_function")
}
func classifyCreateExtension(cs *effects.ClassifiedStatement, _ *pg_query.CreateExtensionStmt) {
	stub(cs, "create_extension")
}
func classifyCreateDatabase(cs *effects.ClassifiedStatement, _ *pg_query.CreatedbStmt) {
	stub(cs, "create_database")
}
func classifyDropDatabase(cs *effects.ClassifiedStatement, _ *pg_query.DropdbStmt) {
	stub(cs, "drop_database")
}
func classifyCreatePublication(cs *effects.ClassifiedStatement, _ *pg_query.CreatePublicationStmt) {
	stub(cs, "create_publication")
}
func classifyAlterPublication(cs *effects.ClassifiedStatement, _ *pg_query.AlterPublicationStmt) {
	stub(cs, "alter_publication")
}

// ---- privilege (Task 8) ----

func classifyGrant(cs *effects.ClassifiedStatement, _ *pg_query.GrantStmt) { stub(cs, "grant") }
func classifyGrantRole(cs *effects.ClassifiedStatement, _ *pg_query.GrantRoleStmt) {
	stub(cs, "grant_role")
}
func classifyCreateRole(cs *effects.ClassifiedStatement, _ *pg_query.CreateRoleStmt) {
	stub(cs, "create_role")
}
func classifyAlterRole(cs *effects.ClassifiedStatement, _ *pg_query.AlterRoleStmt) {
	stub(cs, "alter_role")
}
func classifyDropRole(cs *effects.ClassifiedStatement, _ *pg_query.DropRoleStmt) {
	stub(cs, "drop_role")
}
func classifyAlterSystem(cs *effects.ClassifiedStatement, _ *pg_query.AlterSystemStmt) {
	stub(cs, "alter_system")
}
func classifySecurityLabel(cs *effects.ClassifiedStatement, _ *pg_query.SecLabelStmt) {
	stub(cs, "security_label")
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
