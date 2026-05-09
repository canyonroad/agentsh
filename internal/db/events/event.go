// internal/db/events/event.go
package events

import (
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// DBEvent is the normalized audit event emitted per database statement, per §8.
// This is the skeleton; emission lands in Plan 04. Fields here are the v0.8
// schema; additional sub-structs (decision, result, tx_context) ship in Plan 04.
type DBEvent struct {
	EventID   string    `json:"event_id"`
	SessionID string    `json:"session_id"`
	CommandID string    `json:"command_id,omitempty"`
	Timestamp time.Time `json:"ts"`

	DBService       string `json:"db_service"`
	DBFamily        string `json:"db_family"`
	DBDialect       string `json:"db_dialect"`
	DBUser          string `json:"db_user,omitempty"`
	ApplicationName string `json:"application_name,omitempty"`
	ClientIdentity  string `json:"client_identity,omitempty"`

	Effects []effects.Effect `json:"effects"`

	OperationGroup    string         `json:"operation_group,omitempty"`
	OperationGroupID  uint8          `json:"operation_group_id,omitempty"`
	OperationSubtype  string         `json:"operation_subtype,omitempty"`
	RawVerb           string         `json:"raw_verb,omitempty"`
	ObjectResolution  string         `json:"object_resolution,omitempty"`

	StatementDigest    string    `json:"statement_digest,omitempty"`
	StatementText      string    `json:"statement_text,omitempty"`
	StatementRedaction Redaction `json:"statement_redaction"`

	ParserBackend effects.ParserBackend `json:"parser_backend,omitempty"`
}
