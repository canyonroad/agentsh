//go:build linux

package statemachine

import (
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

// Action is a single thing the dispatcher must execute after a Transition.
// Concrete types are sealed via the private isAction() method so the dispatcher
// can rely on a closed sum type. Cache mutations are NOT Actions — Transition
// mutates the CacheView directly.
type Action interface {
	isAction()
}

// ActionForward emits the original frontend frame to upstream unchanged.
// The dispatcher reads pc.lastFrame and forwards via upstream framer.
type ActionForward struct{}

// ActionSynthError synthesizes ErrorResponse to the client. The dispatcher
// chooses Severity based on the deny path (ERROR for resumable; FATAL for
// terminate). SQLState is the §10 / §13 / §14 SQLSTATE.
type ActionSynthError struct {
	SQLState string
	Message  string
	// Severity overrides "ERROR" when non-empty. The terminate-in-tx path
	// uses Severity="FATAL" so libpq clients surface the SQLSTATE alongside
	// the EOF that follows.
	Severity string
}

// ActionSynthReadyForQuery synthesizes ReadyForQuery to the client.
type ActionSynthReadyForQuery struct {
	Status byte // 'I' | 'T' | 'E'
}

// ActionSynthParseComplete synthesizes a ParseComplete frame to the client
// (used in absorbing-window denies to satisfy clients expecting one frame
// per Parse). Plan 05a does not emit this in standard paths; reserved for
// future tightening.
type ActionSynthParseComplete struct{}

// ActionSynthBindComplete mirrors ActionSynthParseComplete for Bind.
type ActionSynthBindComplete struct{}

// ActionSuppress instructs the dispatcher to drop the current frontend
// frame without forwarding upstream and without responding to client.
// Used inside an absorbing-deny window.
type ActionSuppress struct{}

// ActionInjectRollback sends a synthetic "ROLLBACK" Simple Query upstream as
// if from the client. Used by the rollback_then_continue deny mode. The
// dispatcher composes a 'Q' frame with body "ROLLBACK".
type ActionInjectRollback struct{}

// ActionDrainUntilRFQ reads upstream frames and forwards them to the client
// (subject to the per-row demux for counters in upstreamread.go) until an
// upstream ReadyForQuery is observed. Updates LastUpstreamRFQ on the way.
type ActionDrainUntilRFQ struct{}

// ActionClose tears down both client and upstream connections. After this
// the dispatcher returns from the per-connection driver.
type ActionClose struct{}

// ActionTrackUpstreamRFQ updates ConnState.LastUpstreamRFQ and Phase to
// match Status. Emitted when the dispatcher observes an upstream 'Z' frame
// during normal forwarding.
type ActionTrackUpstreamRFQ struct {
	Status byte
}

// ActionApproverWait instructs the dispatcher to invoke the configured
// Approver and wait up to Timeout before either forwarding or routing a deny.
type ActionApproverWait struct {
	Timeout time.Duration
	Stmt    effects.ClassifiedStatement
	Rule    policy.StatementRule
}

func (*ActionForward) isAction()            {}
func (*ActionSynthError) isAction()         {}
func (*ActionSynthReadyForQuery) isAction() {}
func (*ActionSynthParseComplete) isAction() {}
func (*ActionSynthBindComplete) isAction()  {}
func (*ActionSuppress) isAction()           {}
func (*ActionInjectRollback) isAction()     {}
func (*ActionDrainUntilRFQ) isAction()      {}
func (*ActionClose) isAction()              {}
func (*ActionTrackUpstreamRFQ) isAction()   {}
func (*ActionApproverWait) isAction()       {}
