package api

import (
	"context"
	"encoding/json"
	"strings"

	dbevents "github.com/agentsh/agentsh/internal/db/events"
	appevents "github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

type dbAuditSink struct {
	store  *composite.Store
	broker *appevents.Broker
}

func (s dbAuditSink) EmitStatement(ctx context.Context, ev dbevents.DBEvent) error {
	typesEv := dbStatementToEvent(ev)
	if s.store != nil {
		if err := s.store.AppendEvent(ctx, typesEv); err != nil {
			return err
		}
	}
	if s.broker != nil {
		s.broker.Publish(typesEv)
	}
	return nil
}

func dbStatementToEvent(ev dbevents.DBEvent) types.Event {
	fields := map[string]any{
		"db_service":               ev.DBService,
		"db_family":                ev.DBFamily,
		"db_dialect":               ev.DBDialect,
		"db_user":                  ev.DBUser,
		"database":                 ev.Database,
		"application_name":         ev.ApplicationName,
		"client_identity":          ev.ClientIdentity,
		"operation_group":          ev.OperationGroup,
		"operation_group_id":       ev.OperationGroupID,
		"operation_subtype":        ev.OperationSubtype,
		"raw_verb":                 ev.RawVerb,
		"object_resolution":        ev.ObjectResolution,
		"object_resolution_reason": ev.ObjectResolutionReason,
		"statement_digest":         ev.StatementDigest,
		"statement_text":           ev.StatementText,
		"parser_backend":           ev.ParserBackend.String(),
		"statement_redaction":      dbEventField(ev.StatementRedaction),
		"tls":                      dbEventField(ev.TLS),
		"decision":                 dbEventField(ev.Decision),
		"result":                   dbEventField(ev.Result),
		"tx_context":               dbEventField(ev.TxContext),
	}
	if len(ev.Effects) > 0 {
		fields["effects"] = dbEventField(ev.Effects)
	}
	if ev.Predicates != (dbevents.EventPredicates{}) {
		fields["predicates"] = dbEventField(ev.Predicates)
	}
	if ev.Redirected {
		fields["redirected"] = ev.Redirected
		fields["redirect_rule"] = ev.RedirectRule
		fields["rewritten_statement_digest"] = ev.RewrittenStatementDigest
		fields["redirect_source_relation"] = ev.RedirectSourceRelation
		fields["redirect_target_relation"] = ev.RedirectTargetRelation
		fields["redirect_runtime_status"] = ev.RedirectRuntimeStatus
		fields["redirect_rejection_reason"] = ev.RedirectRejectionReason
	}

	return types.Event{
		ID:        ev.EventID,
		Timestamp: ev.Timestamp,
		Type:      "db_statement",
		SessionID: ev.SessionID,
		CommandID: ev.CommandID,
		Operation: ev.OperationGroup,
		Fields:    fields,
	}
}

func dbEventField(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return v
	}
	return out
}

func (s dbAuditSink) EmitLifecycle(ctx context.Context, ev dbevents.LifecycleEvent) error {
	typesEv := dbLifecycleToEvent(ev)
	if s.store != nil {
		if err := s.store.AppendEvent(ctx, typesEv); err != nil {
			return err
		}
	}
	if s.broker != nil {
		s.broker.Publish(typesEv)
	}
	return nil
}

func dbLifecycleToEvent(ev dbevents.LifecycleEvent) types.Event {
	pid := int(ev.PeerPID)
	if pid == 0 {
		pid = ev.ProcessID
	}
	sessionID := ev.SessionID
	if sessionID == "" && clientIdentityLooksLikeSessionID(ev.ClientIdentity) {
		sessionID = ev.ClientIdentity
	}
	return types.Event{
		ID:        ev.EventID,
		Timestamp: ev.Timestamp,
		Type:      ev.Kind,
		SessionID: sessionID,
		PID:       pid,
		Fields: map[string]any{
			"kind":             ev.Kind,
			"db_service":       ev.DBService,
			"client_identity":  ev.ClientIdentity,
			"reason":           ev.Reason,
			"peer_uid":         ev.PeerUID,
			"peer_pid":         ev.PeerPID,
			"peer_session_id":  ev.PeerSessionID,
			"error_code":       ev.ErrorCode,
			"sni_hostname":     ev.SNIHostname,
			"degraded_reason":  ev.DegradedReason,
			"rule_name":        ev.RuleName,
			"bypass_mode":      ev.BypassMode,
			"destination":      ev.Destination,
			"process_id":       ev.ProcessID,
			"process_identity": ev.ProcessIdentity,
			"suppressed_count": ev.SuppressedCount,
		},
	}
}

func clientIdentityLooksLikeSessionID(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	return !strings.HasPrefix(id, "uid:")
}
