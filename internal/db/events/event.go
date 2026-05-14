// internal/db/events/event.go
package events

import (
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// DBEvent is the normalized audit event emitted per database statement, per §8.
// This is the skeleton; emission lands in Plan 04. Fields here are the v0.8
// schema; additional sub-structs (decision, result, tx_context) ship in Plan 04.
// Cancel governance events also use DBEvent with decision.rule_kind="cancel",
// operation_group="session", and operation_subtype="cancel_request"; they
// include mapped database metadata when available and intentionally carry no
// statement text or digest.
type DBEvent struct {
	EventID   string    `json:"event_id"`
	SessionID string    `json:"session_id"`
	CommandID string    `json:"command_id,omitempty"`
	Timestamp time.Time `json:"ts"`

	DBService       string `json:"db_service"`
	DBFamily        string `json:"db_family"`
	DBDialect       string `json:"db_dialect"`
	DBUser          string `json:"db_user,omitempty"`
	Database        string `json:"database,omitempty"`
	ApplicationName string `json:"application_name,omitempty"`
	ClientIdentity  string `json:"client_identity,omitempty"`

	Effects []effects.Effect `json:"effects"`

	OperationGroup         string `json:"operation_group,omitempty"`
	OperationGroupID       uint8  `json:"operation_group_id,omitempty"`
	OperationSubtype       string `json:"operation_subtype,omitempty"`
	RawVerb                string `json:"raw_verb,omitempty"`
	ObjectResolution       string `json:"object_resolution,omitempty"`
	ObjectResolutionReason string `json:"object_resolution_reason,omitempty"`

	StatementDigest    string    `json:"statement_digest,omitempty"`
	StatementText      string    `json:"statement_text,omitempty"`
	StatementRedaction Redaction `json:"statement_redaction"`

	ParserBackend effects.ParserBackend `json:"parser_backend,omitempty"`

	TLS        EventTLS        `json:"tls"`
	Decision   EventDecision   `json:"decision"`
	Result     EventResult     `json:"result"`
	TxContext  EventTxContext  `json:"tx_context"`
	Predicates EventPredicates `json:"predicates,omitempty"`
}

// EventTLS mirrors spec §8 tls{}. UpstreamCertSubject is unpopulated in 04c.
type EventTLS struct {
	Mode                string `json:"mode"`
	ClientSNI           string `json:"client_sni,omitempty"`
	UpstreamCertSubject string `json:"upstream_cert_subject,omitempty"`
}

// EventDecision mirrors spec §8 decision{}. Verb is one of "allow"|"deny"|
// "approve"|"audit".
type EventDecision struct {
	Verb                   string   `json:"verb"`
	RuleKind               string   `json:"rule_kind"`
	RuleName               string   `json:"rule_name,omitempty"`
	MatchingEffectIndex    int      `json:"matching_effect_index"`
	MatchingEffectGroup    string   `json:"matching_effect_group,omitempty"`
	Reason                 string   `json:"reason,omitempty"`
	ContributingAuditRules []string `json:"contributing_audit_rules,omitempty"`
}

// EventResult mirrors spec §8 result{}. RowsReturned / RowsAffected are
// pointers so JSON wire form carries null for "not applicable".
type EventResult struct {
	RowsReturned *int64 `json:"rows_returned"`
	RowsAffected *int64 `json:"rows_affected"`
	BytesIn      int64  `json:"bytes_in"`
	BytesOut     int64  `json:"bytes_out"`
	LatencyMs    int64  `json:"latency_ms"`
	ErrorCode    string `json:"error_code,omitempty"`
}

// EventTxContext mirrors spec §8 tx_context{}. DenyAction is one of "none",
// "connection_terminated", "rollback_injected", "approval_timeout",
// "approval_denied", or "cancelled_during_approval".
type EventTxContext struct {
	InTransaction bool      `json:"in_transaction"`
	TxStartedAt   time.Time `json:"tx_started_at,omitempty"`
	DenyAction    string    `json:"deny_action"`
}

// EventPredicates mirrors spec §8 predicates{}.
type EventPredicates struct {
	HasFilter bool `json:"has_filter"`
}
