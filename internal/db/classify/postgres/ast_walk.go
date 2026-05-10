// Package postgres — ast_walk.go owns the central RawStmt → handler dispatch.
// Each one-of variant of pg_query.Node maps to a per-family classifier living
// in its own ast_*.go file. Handlers that haven't been implemented yet exist
// as no-op stubs in ast_stubs.go; replacing a stub with a real handler is the
// per-task contract for Tasks 6–13.
package postgres

import (
	"fmt"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// classifyRawStmt dispatches a single RawStmt to the per-family handler.
// On dispatch fall-through it emits an unknown effect with an unmapped-form
// error — this preserves the pipeline's "always one effect" invariant.
//
// Empty Effects after a handler runs is treated as a handler bug and replaced
// with the unknown sentinel + a diagnostic Error; Order canonicalises the
// resulting slice in-place before return.
func classifyRawStmt(d Dialect, raw *pg_query.RawStmt, sess SessionState, opts Options, backend effects.ParserBackend) effects.ClassifiedStatement {
	if raw == nil || raw.Stmt == nil {
		return unknownStatement(backend, "unmapped form: nil RawStmt")
	}

	cs := effects.ClassifiedStatement{ParserBackend: backend}

	switch n := raw.Stmt.Node.(type) {
	// ---- DML / composition ----
	case *pg_query.Node_SelectStmt:
		classifySelect(&cs, n.SelectStmt, sess, opts)
	case *pg_query.Node_InsertStmt:
		classifyInsert(&cs, n.InsertStmt, sess, opts)
	case *pg_query.Node_UpdateStmt:
		classifyUpdate(&cs, n.UpdateStmt, sess, opts)
	case *pg_query.Node_DeleteStmt:
		classifyDelete(&cs, n.DeleteStmt, sess, opts)
	case *pg_query.Node_MergeStmt:
		classifyMerge(&cs, n.MergeStmt, sess, opts)
	case *pg_query.Node_ExplainStmt:
		classifyExplain(&cs, n.ExplainStmt, sess, opts)
	case *pg_query.Node_PrepareStmt:
		classifyPrepare(&cs, n.PrepareStmt, sess, opts)
	case *pg_query.Node_ExecuteStmt:
		classifyExecute(&cs, n.ExecuteStmt, sess, opts)
	case *pg_query.Node_DeallocateStmt:
		classifyDeallocate(&cs, n.DeallocateStmt)

	// ---- session ----
	case *pg_query.Node_VariableSetStmt:
		classifySet(&cs, n.VariableSetStmt)
	case *pg_query.Node_VariableShowStmt:
		classifyShow(&cs)
	case *pg_query.Node_DiscardStmt:
		classifyDiscard(&cs, n.DiscardStmt)
	case *pg_query.Node_TransactionStmt:
		classifyTransaction(&cs, n.TransactionStmt)

	// ---- DDL ----
	case *pg_query.Node_CreateStmt:
		classifyCreateTable(&cs, n.CreateStmt, sess)
	case *pg_query.Node_AlterTableStmt:
		classifyAlter(&cs, n.AlterTableStmt, sess)
	case *pg_query.Node_DropStmt:
		classifyDrop(&cs, n.DropStmt, sess)
	case *pg_query.Node_TruncateStmt:
		classifyTruncate(&cs, n.TruncateStmt, sess)
	case *pg_query.Node_IndexStmt:
		classifyCreateIndex(&cs, n.IndexStmt, sess)
	case *pg_query.Node_ViewStmt:
		classifyCreateView(&cs, n.ViewStmt, sess)
	case *pg_query.Node_CreateSchemaStmt:
		classifyCreateSchema(&cs, n.CreateSchemaStmt)
	case *pg_query.Node_CreateFunctionStmt:
		classifyCreateFunction(&cs, n.CreateFunctionStmt)
	case *pg_query.Node_CreateExtensionStmt:
		classifyCreateExtension(&cs, n.CreateExtensionStmt)
	case *pg_query.Node_CreatedbStmt:
		classifyCreateDatabase(&cs, n.CreatedbStmt)
	case *pg_query.Node_DropdbStmt:
		classifyDropDatabase(&cs, n.DropdbStmt)
	case *pg_query.Node_CreatePublicationStmt:
		classifyCreatePublication(&cs, n.CreatePublicationStmt)
	case *pg_query.Node_AlterPublicationStmt:
		classifyAlterPublication(&cs, n.AlterPublicationStmt)

	// ---- privilege ----
	case *pg_query.Node_GrantStmt:
		classifyGrant(&cs, n.GrantStmt)
	case *pg_query.Node_GrantRoleStmt:
		classifyGrantRole(&cs, n.GrantRoleStmt)
	case *pg_query.Node_CreateRoleStmt:
		classifyCreateRole(&cs, n.CreateRoleStmt)
	case *pg_query.Node_AlterRoleStmt:
		classifyAlterRole(&cs, n.AlterRoleStmt)
	case *pg_query.Node_DropRoleStmt:
		classifyDropRole(&cs, n.DropRoleStmt)
	case *pg_query.Node_AlterSystemStmt:
		classifyAlterSystem(&cs, n.AlterSystemStmt)
	case *pg_query.Node_SecLabelStmt:
		classifySecurityLabel(&cs, n.SecLabelStmt)

	// ---- COPY ----
	case *pg_query.Node_CopyStmt:
		classifyCopy(&cs, n.CopyStmt, sess, opts)

	// ---- external-IO DDL ----
	case *pg_query.Node_CreateSubscriptionStmt:
		classifyCreateSubscription(&cs, n.CreateSubscriptionStmt)
	case *pg_query.Node_AlterSubscriptionStmt:
		classifyAlterSubscription(&cs, n.AlterSubscriptionStmt)
	case *pg_query.Node_DropSubscriptionStmt:
		classifyDropSubscription(&cs, n.DropSubscriptionStmt)
	case *pg_query.Node_CreateForeignServerStmt:
		classifyCreateServer(&cs, n.CreateForeignServerStmt)
	case *pg_query.Node_AlterForeignServerStmt:
		classifyAlterServer(&cs, n.AlterForeignServerStmt)
	case *pg_query.Node_CreateUserMappingStmt:
		classifyCreateUserMapping(&cs, n.CreateUserMappingStmt)
	case *pg_query.Node_AlterUserMappingStmt:
		classifyAlterUserMapping(&cs, n.AlterUserMappingStmt)
	case *pg_query.Node_DropUserMappingStmt:
		classifyDropUserMapping(&cs, n.DropUserMappingStmt)
	case *pg_query.Node_CreateTableSpaceStmt:
		classifyCreateTablespace(&cs, n.CreateTableSpaceStmt)
	case *pg_query.Node_AlterTableSpaceOptionsStmt:
		classifyAlterTablespace(&cs, n.AlterTableSpaceOptionsStmt)

	// ---- procedural / maintenance / lock / notify ----
	case *pg_query.Node_CallStmt:
		classifyCall(&cs, n.CallStmt)
	case *pg_query.Node_DoStmt:
		classifyDo(&cs, n.DoStmt)
	case *pg_query.Node_VacuumStmt:
		classifyMaintenance(&cs, n.VacuumStmt)
	case *pg_query.Node_ReindexStmt:
		classifyReindex(&cs, n.ReindexStmt)
	case *pg_query.Node_ClusterStmt:
		classifyCluster(&cs, n.ClusterStmt)
	case *pg_query.Node_CheckPointStmt:
		classifyCheckpoint(&cs)
	case *pg_query.Node_LockStmt:
		classifyLock(&cs, n.LockStmt, sess)
	case *pg_query.Node_ListenStmt, *pg_query.Node_NotifyStmt, *pg_query.Node_UnlistenStmt:
		classifyNotify(&cs, raw.Stmt)

	default:
		cs.Error = unmappedFormError(raw.Stmt)
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		return cs
	}

	// Empty Effects after dispatch indicates a handler bug; surface as unknown.
	if len(cs.Effects) == 0 {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		if cs.Error == "" {
			cs.Error = "unmapped form: handler produced no effects"
		}
	}
	effects.Order(cs.Effects)
	return cs
}

// unmappedFormError returns the Error message for an unrecognised statement.
func unmappedFormError(stmt *pg_query.Node) string {
	if stmt == nil || stmt.Node == nil {
		return "unmapped form: nil statement"
	}
	return "unmapped form: " + nodeTypeName(stmt)
}

// nodeTypeName returns the human-readable type name of a pg_query Node's
// one-of variant (e.g. "AlterEnumStmt" for *pg_query.Node_AlterEnumStmt).
func nodeTypeName(n *pg_query.Node) string {
	if n == nil || n.Node == nil {
		return "nil"
	}
	t := fmt.Sprintf("%T", n.Node)
	t = strings.TrimPrefix(t, "*pg_query.")
	t = strings.TrimPrefix(t, "Node_")
	return t
}
