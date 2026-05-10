package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestClassifyGrant_Table(t *testing.T) {
	cs := classifyOne(t, "GRANT SELECT ON customers TO bob", SessionState{})
	if cs.RawVerb != "GRANT" {
		t.Fatalf("RawVerb: got %q want GRANT", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupPrivilege {
		t.Fatalf("primary group: got %v want privilege", prim.Group)
	}
	if prim.Subtype != effects.SubtypeGrant {
		t.Fatalf("primary subtype: got %v want grant", prim.Subtype)
	}
	if len(prim.Objects) != 1 ||
		prim.Objects[0].Kind != effects.ObjectTable ||
		prim.Objects[0].Name != "customers" {
		t.Fatalf("objects: got %+v want [{table customers}]", prim.Objects)
	}
}

func TestClassifyRevoke_Table(t *testing.T) {
	cs := classifyOne(t, "REVOKE SELECT ON customers FROM bob", SessionState{})
	if cs.RawVerb != "REVOKE" {
		t.Fatalf("RawVerb: got %q want REVOKE", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupPrivilege {
		t.Fatalf("primary group: got %v want privilege", prim.Group)
	}
	if prim.Subtype != effects.SubtypeRevoke {
		t.Fatalf("primary subtype: got %v want revoke", prim.Subtype)
	}
	if len(prim.Objects) != 1 || prim.Objects[0].Name != "customers" {
		t.Fatalf("objects: got %+v want [{table customers}]", prim.Objects)
	}
}

// §20 disambiguation: GRANT pg_read_server_files TO bob is a role grant,
// not a function call. Primary group MUST be privilege.
func TestClassifyGrantRole_PrimaryIsPrivilege(t *testing.T) {
	cs := classifyOne(t, "GRANT pg_read_server_files TO bob", SessionState{})
	if cs.RawVerb != "GRANT_ROLE" {
		t.Fatalf("RawVerb: got %q want GRANT_ROLE", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupPrivilege {
		t.Fatalf("primary group: got %v want privilege", prim.Group)
	}
	if prim.Subtype != effects.SubtypeGrant {
		t.Fatalf("primary subtype: got %v want grant", prim.Subtype)
	}
}

func TestClassifyRevokeRole(t *testing.T) {
	cs := classifyOne(t, "REVOKE pg_read_server_files FROM bob", SessionState{})
	if cs.RawVerb != "REVOKE_ROLE" {
		t.Fatalf("RawVerb: got %q want REVOKE_ROLE", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeRevoke {
		t.Fatalf("primary subtype: got %v want revoke", prim.Subtype)
	}
}

func TestClassifyCreateRole(t *testing.T) {
	cs := classifyOne(t, "CREATE ROLE alice", SessionState{})
	if cs.RawVerb != "CREATE_ROLE" {
		t.Fatalf("RawVerb: got %q want CREATE_ROLE", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupPrivilege || prim.Subtype != effects.SubtypeCreateRole {
		t.Fatalf("primary: got %v/%v want privilege/create_role", prim.Group, prim.Subtype)
	}
	if len(prim.Objects) != 1 ||
		prim.Objects[0].Kind != effects.ObjectRole ||
		prim.Objects[0].Name != "alice" {
		t.Fatalf("objects: got %+v want [{role alice}]", prim.Objects)
	}
}

// CREATE USER is parsed as CreateRoleStmt with stmt_type=ROLESTMT_USER.
func TestClassifyCreateUser_NormalisesToCreateRole(t *testing.T) {
	cs := classifyOne(t, "CREATE USER bob", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupPrivilege || prim.Subtype != effects.SubtypeCreateRole {
		t.Fatalf("primary: got %v/%v want privilege/create_role", prim.Group, prim.Subtype)
	}
	if prim.Objects[0].Name != "bob" {
		t.Fatalf("role name: got %q want bob", prim.Objects[0].Name)
	}
}

func TestClassifyAlterRole(t *testing.T) {
	cs := classifyOne(t, "ALTER ROLE alice WITH PASSWORD 'x'", SessionState{})
	if cs.RawVerb != "ALTER_ROLE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupPrivilege || prim.Subtype != effects.SubtypeAlterRole {
		t.Fatalf("primary: got %v/%v want privilege/alter_role", prim.Group, prim.Subtype)
	}
	if len(prim.Objects) != 1 ||
		prim.Objects[0].Kind != effects.ObjectRole ||
		prim.Objects[0].Name != "alice" {
		t.Fatalf("objects: got %+v want [{role alice}]", prim.Objects)
	}
}

func TestClassifyDropRole(t *testing.T) {
	cs := classifyOne(t, "DROP ROLE alice", SessionState{})
	if cs.RawVerb != "DROP_ROLE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupPrivilege || prim.Subtype != effects.SubtypeDropRole {
		t.Fatalf("primary: got %v/%v want privilege/drop_role", prim.Group, prim.Subtype)
	}
	if len(prim.Objects) != 1 || prim.Objects[0].Name != "alice" {
		t.Fatalf("objects: got %+v want [{role alice}]", prim.Objects)
	}
}

// §20: ALTER SYSTEM is privilege/alter_system, NOT schema_alter.
func TestClassifyAlterSystem_PrimaryIsPrivilege(t *testing.T) {
	cs := classifyOne(t, "ALTER SYSTEM SET shared_buffers='128MB'", SessionState{})
	if cs.RawVerb != "ALTER_SYSTEM" {
		t.Fatalf("RawVerb: got %q want ALTER_SYSTEM", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupPrivilege {
		t.Fatalf("primary group: got %v want privilege", prim.Group)
	}
	if prim.Subtype != effects.SubtypeAlterSystem {
		t.Fatalf("primary subtype: got %v want alter_system", prim.Subtype)
	}
	// The GUC being set should be exposed as an ObjectGUC.
	if len(prim.Objects) == 0 ||
		prim.Objects[0].Kind != effects.ObjectGUC ||
		prim.Objects[0].Name != "shared_buffers" {
		t.Fatalf("objects: got %+v want [{guc shared_buffers}]", prim.Objects)
	}
}

func TestClassifyAlterSystem_Reset(t *testing.T) {
	cs := classifyOne(t, "ALTER SYSTEM RESET shared_buffers", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupPrivilege || prim.Subtype != effects.SubtypeAlterSystem {
		t.Fatalf("primary: got %v/%v want privilege/alter_system", prim.Group, prim.Subtype)
	}
}

func TestClassifySecurityLabel(t *testing.T) {
	cs := classifyOne(t, "SECURITY LABEL FOR provider ON COLUMN tab.col IS 'classified'", SessionState{})
	if cs.RawVerb != "SECURITY_LABEL" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupPrivilege || prim.Subtype != effects.SubtypeSecurityLabel {
		t.Fatalf("primary: got %v/%v want privilege/security_label", prim.Group, prim.Subtype)
	}
}
