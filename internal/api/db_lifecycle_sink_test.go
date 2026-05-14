package api

import (
	"context"
	"errors"
	"testing"
	"time"

	dbevents "github.com/agentsh/agentsh/internal/db/events"
	appevents "github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

type failingEventStore struct {
	err error
}

func (s failingEventStore) AppendEvent(context.Context, types.Event) error {
	return s.err
}

func (s failingEventStore) QueryEvents(context.Context, types.EventQuery) ([]types.Event, error) {
	return nil, nil
}

func (s failingEventStore) Close() error {
	return nil
}

func TestDBLifecycleToEventUsesClientIdentityWhenSessionIDEmpty(t *testing.T) {
	ev := dbLifecycleToEvent(dbevents.LifecycleEvent{
		EventID:        "evt-1",
		Timestamp:      time.Unix(123, 0).UTC(),
		Kind:           "db_handshake_fail",
		ClientIdentity: "sess-client",
	})

	if ev.SessionID != "sess-client" {
		t.Fatalf("SessionID = %q, want ClientIdentity fallback", ev.SessionID)
	}
}

func TestDBLifecycleToEventPreservesExplicitSessionID(t *testing.T) {
	ev := dbLifecycleToEvent(dbevents.LifecycleEvent{
		EventID:        "evt-1",
		Timestamp:      time.Unix(123, 0).UTC(),
		Kind:           "db_handshake_fail",
		SessionID:      "sess-explicit",
		ClientIdentity: "sess-client",
	})

	if ev.SessionID != "sess-explicit" {
		t.Fatalf("SessionID = %q, want explicit SessionID", ev.SessionID)
	}
}

func TestDBLifecycleToEventDoesNotUseUIDClientIdentityAsSessionID(t *testing.T) {
	ev := dbLifecycleToEvent(dbevents.LifecycleEvent{
		EventID:        "evt-1",
		Timestamp:      time.Unix(123, 0).UTC(),
		Kind:           "db_handshake_fail",
		ClientIdentity: "uid:1000",
	})

	if ev.SessionID != "" {
		t.Fatalf("SessionID = %q, want empty for UID client identity", ev.SessionID)
	}
}

func TestDBStatementToEventMapsNormalizedFields(t *testing.T) {
	rowsReturned := int64(3)
	rowsAffected := int64(0)
	ts := time.Unix(456, 0).UTC()

	ev := dbStatementToEvent(dbevents.DBEvent{
		EventID:            "db-evt-1",
		SessionID:          "sess-db",
		CommandID:          "cmd-db",
		Timestamp:          ts,
		DBService:          "appdb",
		DBFamily:           "postgres",
		DBDialect:          "postgres",
		DBUser:             "app",
		Database:           "app",
		ApplicationName:    "db07c",
		ClientIdentity:     "sess-db",
		OperationGroup:     "bulk_export",
		OperationGroupID:   5,
		OperationSubtype:   "copy_to",
		RawVerb:            "COPY",
		ObjectResolution:   "syntactic",
		StatementDigest:    "sha256:abc",
		StatementText:      "COPY (SELECT note FROM db07c_copy) TO STDOUT WITH CSV",
		StatementRedaction: dbevents.RedactionNone,
		Decision: dbevents.EventDecision{
			Verb:                "allow",
			RuleKind:            "statement",
			RuleName:            "allow-copy",
			MatchingEffectIndex: 0,
		},
		Result: dbevents.EventResult{
			RowsReturned: &rowsReturned,
			RowsAffected: &rowsAffected,
			BytesOut:     11,
			LatencyMs:    7,
		},
		TxContext: dbevents.EventTxContext{DenyAction: "none"},
	})

	if ev.ID != "db-evt-1" || ev.Timestamp != ts || ev.Type != "db_statement" {
		t.Fatalf("event identity = %+v", ev)
	}
	if ev.SessionID != "sess-db" || ev.CommandID != "cmd-db" || ev.Operation != "bulk_export" {
		t.Fatalf("event session/operation = %+v", ev)
	}
	if ev.Fields["db_service"] != "appdb" ||
		ev.Fields["db_family"] != "postgres" ||
		ev.Fields["db_dialect"] != "postgres" ||
		ev.Fields["db_user"] != "app" ||
		ev.Fields["database"] != "app" ||
		ev.Fields["application_name"] != "db07c" ||
		ev.Fields["client_identity"] != "sess-db" {
		t.Fatalf("metadata fields = %+v", ev.Fields)
	}
	if ev.Fields["operation_subtype"] != "copy_to" {
		t.Fatalf("operation_subtype = %#v", ev.Fields["operation_subtype"])
	}
	if ev.Fields["statement_text"] != "COPY (SELECT note FROM db07c_copy) TO STDOUT WITH CSV" {
		t.Fatalf("statement_text = %#v", ev.Fields["statement_text"])
	}
	decision, ok := ev.Fields["decision"].(map[string]any)
	if !ok || decision["verb"] != "allow" || decision["rule_name"] != "allow-copy" {
		t.Fatalf("decision field = %#v", ev.Fields["decision"])
	}
	result, ok := ev.Fields["result"].(map[string]any)
	if !ok || result["bytes_out"] != float64(11) || result["latency_ms"] != float64(7) {
		t.Fatalf("result field = %#v", ev.Fields["result"])
	}
	txContext, ok := ev.Fields["tx_context"].(map[string]any)
	if !ok || txContext["deny_action"] != "none" {
		t.Fatalf("tx_context field = %#v", ev.Fields["tx_context"])
	}
}

func TestDBStatementToEventMapsCatalogResolutionReason(t *testing.T) {
	ev := dbStatementToEvent(dbevents.DBEvent{
		EventID:                "db-resolved-api",
		SessionID:              "sess-1",
		Timestamp:              time.Unix(100, 0).UTC(),
		DBService:              "appdb",
		DBFamily:               "postgres",
		DBDialect:              "postgres",
		ObjectResolution:       "catalog_unresolved",
		ObjectResolutionReason: "missing",
	})
	if ev.Fields["object_resolution"] != "catalog_unresolved" {
		t.Fatalf("object_resolution = %#v", ev.Fields["object_resolution"])
	}
	if ev.Fields["object_resolution_reason"] != "missing" {
		t.Fatalf("object_resolution_reason = %#v", ev.Fields["object_resolution_reason"])
	}
}

func TestDBAuditSinkEmitStatementPublishesToBroker(t *testing.T) {
	broker := appevents.NewBroker()
	ch := broker.Subscribe("sess-db", 1)
	defer broker.Unsubscribe("sess-db", ch)

	sink := dbAuditSink{broker: broker}
	err := sink.EmitStatement(context.Background(), dbevents.DBEvent{
		EventID:        "db-evt-pub",
		SessionID:      "sess-db",
		CommandID:      "cmd-db",
		Timestamp:      time.Unix(789, 0).UTC(),
		DBService:      "appdb",
		DBFamily:       "postgres",
		DBDialect:      "postgres",
		OperationGroup: "session",
		Decision:       dbevents.EventDecision{Verb: "allow", RuleKind: "cancel", RuleName: "allow-app-cancel"},
		Result:         dbevents.EventResult{ErrorCode: "57014"},
	})
	if err != nil {
		t.Fatalf("EmitStatement: %v", err)
	}

	select {
	case got := <-ch:
		if got.Type != "db_statement" || got.ID != "db-evt-pub" || got.SessionID != "sess-db" {
			t.Fatalf("published event = %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("EmitStatement did not publish db_statement")
	}
}

func TestDBAuditSinkEmitStatementReturnsStoreErrorWithoutPublishing(t *testing.T) {
	sentinel := errors.New("append failed")
	broker := appevents.NewBroker()
	ch := broker.Subscribe("sess-db", 1)
	defer broker.Unsubscribe("sess-db", ch)

	sink := dbAuditSink{
		store:  composite.New(failingEventStore{err: sentinel}, nil),
		broker: broker,
	}
	err := sink.EmitStatement(context.Background(), dbevents.DBEvent{
		EventID:        "db-evt-store-fail",
		SessionID:      "sess-db",
		CommandID:      "cmd-db",
		Timestamp:      time.Unix(890, 0).UTC(),
		DBService:      "appdb",
		DBFamily:       "postgres",
		DBDialect:      "postgres",
		OperationGroup: "session",
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("EmitStatement error = %v, want sentinel", err)
	}

	select {
	case got := <-ch:
		t.Fatalf("published event after store failure = %+v", got)
	default:
	}
}
