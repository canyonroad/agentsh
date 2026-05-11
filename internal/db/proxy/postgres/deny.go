//go:build linux

package postgres

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/policy"
)

const (
	sqlstateInsufficientPrivilege = "42501" // statement-rule deny
	sqlstateAuthFailure           = "28000" // connection-rule deny
	sqlstateProgramLimitExceeded  = "54000" // frame budget
	sqlstateFeatureNotSupported   = "0A000" // extended query / function call
)

// synthErrorAndRFQ writes ErrorResponse + ReadyForQuery('I') to the client.
// Used when lastUpstreamRFQ in {0, 'I'} so the next 'Q' can proceed.
func (pc *proxyConn) synthErrorAndRFQ(sqlstate, message string) error {
	pc.backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: sqlstate, Message: message})
	pc.backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	return pc.backend.Flush()
}

// synthErrorOnly writes ErrorResponse with no trailing RFQ. Used for the
// in-tx deny case ({'T', 'E'}) — caller closes both conns immediately after.
// Severity is FATAL so libpq-family clients (pgx, jdbc) treat the following
// EOF as the expected fail-closed signal and surface the ErrorResponse with
// SQLSTATE intact, instead of reporting "unexpected EOF".
func (pc *proxyConn) synthErrorOnly(sqlstate, message string) error {
	pc.backend.Send(&pgproto3.ErrorResponse{
		Severity:            "FATAL",
		SeverityUnlocalized: "FATAL",
		Code:                sqlstate,
		Message:             message,
	})
	return pc.backend.Flush()
}

// pickDenySynth picks the rendered deny message and SQLSTATE for a batch.
// Iterates in order; first denying entry wins (most-restrictive is
// deterministic under §10.2 with stable rule order).
//
// SQLSTATE selection:
//
//	connection-rule deny → 28000
//	statement-rule deny  → 42501
func pickDenySynth(decisions []policy.Decision) (string, string) {
	for _, d := range decisions {
		if d.Verb != policy.VerbDeny {
			continue
		}
		sqlstate := sqlstateInsufficientPrivilege
		if d.RuleKind == policy.RuleKindConnection {
			sqlstate = sqlstateAuthFailure
		}
		return renderDenyMessage(d), sqlstate
	}
	// Defensive: caller is supposed to ensure anyDeny.
	return "denied by AgentSH policy", sqlstateInsufficientPrivilege
}

func renderDenyMessage(d policy.Decision) string {
	if d.RuleName != "" {
		return fmt.Sprintf("denied by AgentSH policy: %s", d.RuleName)
	}
	if d.Reason != "" {
		return fmt.Sprintf("denied by AgentSH policy: %s", d.Reason)
	}
	return "denied by AgentSH policy"
}
