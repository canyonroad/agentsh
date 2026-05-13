package api

import (
	"context"

	dbevents "github.com/agentsh/agentsh/internal/db/events"
	appevents "github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

type dbAuditSink struct {
	store  *composite.Store
	broker *appevents.Broker
}

func (s dbAuditSink) EmitStatement(context.Context, dbevents.DBEvent) error {
	return nil
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
	return types.Event{
		ID:        ev.EventID,
		Timestamp: ev.Timestamp,
		Type:      ev.Kind,
		SessionID: ev.SessionID,
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
