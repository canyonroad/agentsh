//go:build linux

package statemachine

import (
	"github.com/agentsh/agentsh/internal/db/policy"
)

// DenyRoute returns the Action sequence implementing the spec §14.3 + §14.4
// deny path. Callers pass the rendered deny message (already templated) and
// the SQLSTATE chosen by the rule kind.
//
//   - Out-of-tx (lastUpstreamRFQ in {0, 'I'}) and not dirty:
//     [SynthError, SynthReadyForQuery(I)]
//   - Out-of-tx and dirty:
//     [SynthError, DrainUntilRFQ]
//   - In-tx (lastUpstreamRFQ in {'T', 'E'}), terminate (default or explicit):
//     [SynthError(Severity=FATAL), Close]
//   - In-tx, rollback_then_continue:
//     [SynthError, InjectRollback, DrainUntilRFQ, SynthReadyForQuery(I)]
func DenyRoute(s ConnState, rule policy.StatementRule, msg, sqlstate string) []Action {
	if s.LastUpstreamRFQ == 'T' || s.LastUpstreamRFQ == 'E' {
		// In-tx branch. Default terminate; soft mode if explicitly configured.
		if rule.DenyModeInTx == "rollback_then_continue" {
			return []Action{
				&ActionSynthError{SQLState: sqlstate, Message: msg},
				&ActionInjectRollback{},
				&ActionDrainUntilRFQ{},
				&ActionSynthReadyForQuery{Status: 'I'},
			}
		}
		return []Action{
			&ActionSynthError{SQLState: sqlstate, Message: msg, Severity: "FATAL"},
			&ActionClose{},
		}
	}

	// Out-of-tx branch.
	if s.UpstreamDirtySinceSync {
		return []Action{
			&ActionSynthError{SQLState: sqlstate, Message: msg},
			&ActionDrainUntilRFQ{},
		}
	}
	return []Action{
		&ActionSynthError{SQLState: sqlstate, Message: msg},
		&ActionSynthReadyForQuery{Status: 'I'},
	}
}
