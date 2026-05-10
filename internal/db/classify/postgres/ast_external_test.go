// Package postgres — ast_external_test.go covers the §7.3 external-IO DDL
// handlers (SUBSCRIPTION / SERVER / USER MAPPING / TABLESPACE). Each test
// asserts raw_verb, primary effect group/subtype, secondary effect, and the
// extracted ObjectExternalEndpoint / ObjectFilesystemPath when applicable.
package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestClassifyCreateSubscription(t *testing.T) {
	cs := classifyOne(t,
		"CREATE SUBSCRIPTION sub CONNECTION 'host=upstream.example port=5432' PUBLICATION pub",
		SessionState{},
	)
	if cs.RawVerb != "CREATE_SUBSCRIPTION" {
		t.Fatalf("RawVerb: got %q want CREATE_SUBSCRIPTION", cs.RawVerb)
	}
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d want 2: %+v", len(cs.Effects), cs.Effects)
	}
	p := cs.Effects[0]
	if p.Group != effects.GroupUnsafeIO || p.Subtype != effects.SubtypeCreateSubscription {
		t.Fatalf("primary: got %v/%v want unsafe_io/create_subscription",
			p.Group, p.Subtype)
	}
	if len(p.Objects) != 2 {
		t.Fatalf("primary objects: got %d want 2 (%+v)", len(p.Objects), p.Objects)
	}
	if p.Objects[0].Kind != effects.ObjectSubscription || p.Objects[0].Name != "sub" {
		t.Fatalf("primary obj[0]: got %+v want subscription/sub", p.Objects[0])
	}
	if p.Objects[1].Kind != effects.ObjectExternalEndpoint ||
		p.Objects[1].Host != "upstream.example" || p.Objects[1].Port != 5432 {
		t.Fatalf("primary obj[1]: got %+v want external_endpoint upstream.example:5432",
			p.Objects[1])
	}
	if cs.Effects[1].Group != effects.GroupSchemaCreate {
		t.Fatalf("secondary: got %v want schema_create", cs.Effects[1].Group)
	}
}

func TestClassifyCreateSubscription_NoConninfo(t *testing.T) {
	cs := classifyOne(t,
		"CREATE SUBSCRIPTION sub CONNECTION '' PUBLICATION pub WITH (connect = false)",
		SessionState{},
	)
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d want 2", len(cs.Effects))
	}
	p := cs.Effects[0]
	if len(p.Objects) != 1 {
		t.Fatalf("primary objects: got %d want 1 (no endpoint when conninfo empty): %+v",
			len(p.Objects), p.Objects)
	}
}

func TestClassifyAlterSubscription_Connection(t *testing.T) {
	cs := classifyOne(t,
		"ALTER SUBSCRIPTION sub CONNECTION 'host=new.example port=6543'",
		SessionState{},
	)
	if cs.RawVerb != "ALTER_SUBSCRIPTION" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d want 2", len(cs.Effects))
	}
	p := cs.Effects[0]
	if p.Group != effects.GroupUnsafeIO || p.Subtype != effects.SubtypeAlterSubscription {
		t.Fatalf("primary: got %v/%v want unsafe_io/alter_subscription",
			p.Group, p.Subtype)
	}
	if len(p.Objects) != 2 ||
		p.Objects[1].Host != "new.example" || p.Objects[1].Port != 6543 {
		t.Fatalf("primary objects: got %+v", p.Objects)
	}
	if cs.Effects[1].Group != effects.GroupSchemaAlter {
		t.Fatalf("secondary: got %v want schema_alter", cs.Effects[1].Group)
	}
}

func TestClassifyAlterSubscription_NoConn(t *testing.T) {
	cs := classifyOne(t, "ALTER SUBSCRIPTION sub REFRESH PUBLICATION", SessionState{})
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d want 2", len(cs.Effects))
	}
	p := cs.Effects[0]
	if len(p.Objects) != 1 || p.Objects[0].Name != "sub" {
		t.Fatalf("primary objects: got %+v want [subscription/sub]", p.Objects)
	}
}

func TestClassifyDropSubscription(t *testing.T) {
	cs := classifyOne(t, "DROP SUBSCRIPTION sub", SessionState{})
	if cs.RawVerb != "DROP_SUBSCRIPTION" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d want 2", len(cs.Effects))
	}
	if cs.Effects[0].Group != effects.GroupUnsafeIO ||
		cs.Effects[0].Subtype != effects.SubtypeDropSubscription {
		t.Fatalf("primary: got %v/%v", cs.Effects[0].Group, cs.Effects[0].Subtype)
	}
	if cs.Effects[1].Group != effects.GroupSchemaDestroy {
		t.Fatalf("secondary: got %v want schema_destroy", cs.Effects[1].Group)
	}
}

func TestClassifyCreateServer(t *testing.T) {
	cs := classifyOne(t,
		"CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'remote.example', port '5432')",
		SessionState{},
	)
	if cs.RawVerb != "CREATE_SERVER" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d want 2", len(cs.Effects))
	}
	p := cs.Effects[0]
	if p.Group != effects.GroupUnsafeIO || p.Subtype != effects.SubtypeCreateServer {
		t.Fatalf("primary: got %v/%v", p.Group, p.Subtype)
	}
	if len(p.Objects) != 2 {
		t.Fatalf("primary objects: got %+v", p.Objects)
	}
	if p.Objects[0].Kind != effects.ObjectServer || p.Objects[0].Name != "s" {
		t.Fatalf("obj[0]: got %+v", p.Objects[0])
	}
	if p.Objects[1].Kind != effects.ObjectExternalEndpoint ||
		p.Objects[1].Host != "remote.example" || p.Objects[1].Port != 5432 {
		t.Fatalf("obj[1]: got %+v", p.Objects[1])
	}
	if cs.Effects[1].Group != effects.GroupSchemaCreate {
		t.Fatalf("secondary: got %v", cs.Effects[1].Group)
	}
}

func TestClassifyCreateServer_NoOptions(t *testing.T) {
	cs := classifyOne(t,
		"CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw",
		SessionState{},
	)
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d", len(cs.Effects))
	}
	p := cs.Effects[0]
	if len(p.Objects) != 1 {
		t.Fatalf("expected only ObjectServer when no host/port options, got %+v", p.Objects)
	}
}

func TestClassifyAlterServer(t *testing.T) {
	cs := classifyOne(t,
		"ALTER SERVER s OPTIONS (SET host 'new.example')",
		SessionState{},
	)
	if cs.RawVerb != "ALTER_SERVER" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d", len(cs.Effects))
	}
	p := cs.Effects[0]
	if p.Group != effects.GroupUnsafeIO || p.Subtype != effects.SubtypeAlterServer {
		t.Fatalf("primary: %v/%v", p.Group, p.Subtype)
	}
	if len(p.Objects) != 2 || p.Objects[1].Host != "new.example" {
		t.Fatalf("objects: %+v", p.Objects)
	}
	if cs.Effects[1].Group != effects.GroupSchemaAlter {
		t.Fatalf("secondary: %v", cs.Effects[1].Group)
	}
}

func TestClassifyDropServer(t *testing.T) {
	cs := classifyOne(t, "DROP SERVER s", SessionState{})
	if cs.RawVerb != "DROP_SERVER" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d", len(cs.Effects))
	}
	if cs.Effects[0].Group != effects.GroupUnsafeIO ||
		cs.Effects[0].Subtype != effects.SubtypeDropServer {
		t.Fatalf("primary: %v/%v", cs.Effects[0].Group, cs.Effects[0].Subtype)
	}
	if len(cs.Effects[0].Objects) != 1 ||
		cs.Effects[0].Objects[0].Kind != effects.ObjectServer ||
		cs.Effects[0].Objects[0].Name != "s" {
		t.Fatalf("obj: %+v", cs.Effects[0].Objects)
	}
	if cs.Effects[1].Group != effects.GroupSchemaDestroy {
		t.Fatalf("secondary: %v", cs.Effects[1].Group)
	}
}

func TestClassifyCreateUserMapping(t *testing.T) {
	cs := classifyOne(t,
		"CREATE USER MAPPING FOR alice SERVER s OPTIONS (user 'remote_user', password 'remote_pw')",
		SessionState{},
	)
	if cs.RawVerb != "CREATE_USER_MAPPING" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d", len(cs.Effects))
	}
	p := cs.Effects[0]
	if p.Group != effects.GroupUnsafeIO || p.Subtype != effects.SubtypeCreateUserMapping {
		t.Fatalf("primary: %v/%v", p.Group, p.Subtype)
	}
	if len(p.Objects) != 2 {
		t.Fatalf("primary objects: %+v", p.Objects)
	}
	if p.Objects[0].Kind != effects.ObjectUserMapping || p.Objects[0].Name != "alice@s" {
		t.Fatalf("obj[0]: %+v want user_mapping/alice@s", p.Objects[0])
	}
	if p.Objects[1].Kind != effects.ObjectRole || p.Objects[1].Name != "alice" {
		t.Fatalf("obj[1]: %+v want role/alice", p.Objects[1])
	}
	if cs.Effects[1].Group != effects.GroupPrivilege {
		t.Fatalf("secondary: %v", cs.Effects[1].Group)
	}
}

func TestClassifyAlterUserMapping(t *testing.T) {
	cs := classifyOne(t,
		"ALTER USER MAPPING FOR alice SERVER s OPTIONS (SET user 'new_user')",
		SessionState{},
	)
	if cs.RawVerb != "ALTER_USER_MAPPING" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	if len(cs.Effects) != 2 ||
		cs.Effects[0].Subtype != effects.SubtypeAlterUserMapping {
		t.Fatalf("effects: %+v", cs.Effects)
	}
}

func TestClassifyDropUserMapping(t *testing.T) {
	cs := classifyOne(t, "DROP USER MAPPING FOR alice SERVER s", SessionState{})
	if cs.RawVerb != "DROP_USER_MAPPING" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	if len(cs.Effects) != 2 ||
		cs.Effects[0].Subtype != effects.SubtypeDropUserMapping ||
		cs.Effects[1].Group != effects.GroupPrivilege {
		t.Fatalf("effects: %+v", cs.Effects)
	}
}

func TestClassifyCreateTablespace(t *testing.T) {
	cs := classifyOne(t,
		"CREATE TABLESPACE ts LOCATION '/mnt/ssd'",
		SessionState{},
	)
	if cs.RawVerb != "CREATE_TABLESPACE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d", len(cs.Effects))
	}
	p := cs.Effects[0]
	if p.Group != effects.GroupUnsafeIO || p.Subtype != effects.SubtypeCreateTablespace {
		t.Fatalf("primary: %v/%v", p.Group, p.Subtype)
	}
	if len(p.Objects) != 2 {
		t.Fatalf("primary objects: %+v", p.Objects)
	}
	if p.Objects[0].Kind != effects.ObjectTablespace || p.Objects[0].Name != "ts" {
		t.Fatalf("obj[0]: %+v", p.Objects[0])
	}
	if p.Objects[1].Kind != effects.ObjectFilesystemPath || p.Objects[1].Path != "/mnt/ssd" {
		t.Fatalf("obj[1]: %+v", p.Objects[1])
	}
}

func TestClassifyAlterTablespace_SetOptions(t *testing.T) {
	cs := classifyOne(t,
		"ALTER TABLESPACE ts SET (random_page_cost = 1)",
		SessionState{},
	)
	if cs.RawVerb != "ALTER_TABLESPACE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	if len(cs.Effects) != 1 {
		t.Fatalf("effect count: got %d (expect schema_alter only): %+v",
			len(cs.Effects), cs.Effects)
	}
	if cs.Effects[0].Group != effects.GroupSchemaAlter ||
		cs.Effects[0].Subtype != effects.SubtypeAlterTablespace {
		t.Fatalf("effect: %+v", cs.Effects[0])
	}
}

func TestClassifyDropTablespace(t *testing.T) {
	cs := classifyOne(t, "DROP TABLESPACE ts", SessionState{})
	if cs.RawVerb != "DROP_TABLESPACE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	if len(cs.Effects) != 2 ||
		cs.Effects[0].Group != effects.GroupUnsafeIO ||
		cs.Effects[0].Subtype != effects.SubtypeDropTablespace ||
		cs.Effects[1].Group != effects.GroupSchemaDestroy {
		t.Fatalf("effects: %+v", cs.Effects)
	}
	if cs.Effects[0].Objects[0].Name != "ts" {
		t.Fatalf("obj: %+v", cs.Effects[0].Objects)
	}
}

func TestOptionsHostPort_StringValues(t *testing.T) {
	// Sanity: confirm helper returns expected values via a CREATE SERVER form.
	cs := classifyOne(t,
		"CREATE SERVER s2 FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'h', port '7777', dbname 'app')",
		SessionState{},
	)
	if len(cs.Effects[0].Objects) != 2 {
		t.Fatalf("objects: %+v", cs.Effects[0].Objects)
	}
	endpoint := cs.Effects[0].Objects[1]
	if endpoint.Host != "h" || endpoint.Port != 7777 {
		t.Fatalf("endpoint: %+v", endpoint)
	}
}
