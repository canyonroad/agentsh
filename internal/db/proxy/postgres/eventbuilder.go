//go:build linux

package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
)

// buildArgs collects the inputs to buildStatementEvent. Keeping them in a
// struct avoids a 14-argument function and makes test cases readable.
type buildArgs struct {
	Stmt              effects.ClassifiedStatement
	StmtIndex         int
	BatchTotal        int
	Decision          policy.Decision
	SQL               string
	Tier              policy.RedactionTier
	Conn              connState
	BytesIn           int64
	BytesOut          int64
	LatencyMs         int64
	RowsReturned      *int64
	RowsAffected      *int64
	UpstreamErrCode   string
	DenyAction        string
	IsDeniedBySibling bool
	BatchSHA          string // sha256 hex of the full Q.String; used for command_id
	Parser            classify_pg.Parser
	Redirect          redirectEventArgs
}

type redirectEventArgs struct {
	Redirected               bool
	Rule                     string
	RewrittenSQL             string
	RewrittenStatementDigest string
	SourceRelation           string
	TargetRelation           string
	RuntimeStatus            string
	RejectionReason          string
}

// buildStatementEvent returns a fully-populated events.DBEvent. Pure function
// — no I/O, no clock, no globals beyond timeNow / newEventID.
func buildStatementEvent(a buildArgs) events.DBEvent {
	slice := perStmtSlice(a.SQL, a.Stmt)

	normalized, _ := normalizeStatement(a.Parser, slice)
	digest := statementDigest(a.Parser, slice)

	rewrittenDigest := a.Redirect.RewrittenStatementDigest
	if rewrittenDigest == "" && a.Redirect.RewrittenSQL != "" {
		rewrittenDigest = statementDigest(a.Parser, a.Redirect.RewrittenSQL)
	}

	var stmtText string
	var redaction events.Redaction
	switch a.Tier {
	case policy.RedactFull:
		stmtText = slice
		redaction = events.RedactionFull
	case policy.RedactParametersRedacted:
		stmtText = normalized
		redaction = events.RedactionParametersRedacted
	case policy.RedactNone:
		stmtText = ""
		redaction = events.RedactionNone
	default:
		stmtText = normalized
		redaction = events.RedactionParametersRedacted
	}

	dec := buildDecision(a.Decision, a.IsDeniedBySibling)

	result := events.EventResult{
		RowsReturned: a.RowsReturned,
		RowsAffected: a.RowsAffected,
		BytesIn:      a.BytesIn,
		BytesOut:     a.BytesOut,
		LatencyMs:    a.LatencyMs,
		ErrorCode:    a.UpstreamErrCode,
	}
	if a.IsDeniedBySibling {
		result = events.EventResult{
			BytesIn:   a.BytesIn,
			ErrorCode: "DENIED_BY_SIBLING",
		}
	}

	tx := events.EventTxContext{
		InTransaction: connInTx(a.Conn),
		DenyAction:    a.DenyAction,
	}
	if a.Conn.smState != nil && !a.Conn.smState.TxStartedAt.IsZero() {
		tx.TxStartedAt = a.Conn.smState.TxStartedAt
	}

	predicates := events.EventPredicates{HasFilter: hasFilter(a.Stmt)}
	opGroup, opGroupID, opSubtype := operationFromStatement(a.Stmt)

	return events.DBEvent{
		EventID:                  newEventID(),
		SessionID:                eventSessionID(a.Conn.agentSessionID, a.Conn.clientIdentity),
		CommandID:                fmt.Sprintf("%s:%d", a.BatchSHA, a.StmtIndex),
		Timestamp:                timeNow(),
		DBService:                a.Conn.dbService,
		DBFamily:                 "postgres",
		DBDialect:                "postgres",
		DBUser:                   a.Conn.dbUser,
		Database:                 a.Conn.database,
		ApplicationName:          a.Conn.appName,
		ClientIdentity:           a.Conn.clientIdentity,
		Effects:                  a.Stmt.Effects,
		OperationGroup:           opGroup,
		OperationGroupID:         opGroupID,
		OperationSubtype:         opSubtype,
		RawVerb:                  a.Stmt.RawVerb,
		ObjectResolution:         a.Stmt.FoldResolution().String(),
		ObjectResolutionReason:   firstResolutionReason(a.Stmt),
		ParserBackend:            a.Stmt.ParserBackend,
		StatementText:            stmtText,
		StatementDigest:          digest,
		StatementRedaction:       redaction,
		Redirected:               a.Redirect.Redirected,
		RedirectRule:             a.Redirect.Rule,
		RewrittenStatementDigest: rewrittenDigest,
		RedirectSourceRelation:   a.Redirect.SourceRelation,
		RedirectTargetRelation:   a.Redirect.TargetRelation,
		RedirectRuntimeStatus:    a.Redirect.RuntimeStatus,
		RedirectRejectionReason:  a.Redirect.RejectionReason,
		TLS:                      events.EventTLS{Mode: a.Conn.tlsMode, ClientSNI: a.Conn.sniHostname},
		Decision:                 dec,
		Result:                   result,
		TxContext:                tx,
		Predicates:               predicates,
	}
}

func normalizeStatement(parser classify_pg.Parser, sql string) (string, error) {
	normalized, err := parser.Normalize(sql)
	if err != nil || normalized == "" {
		normalized = strings.TrimSpace(sql)
	}
	return normalized, err
}

func statementDigest(parser classify_pg.Parser, sql string) string {
	normalized, err := normalizeStatement(parser, sql)
	if err != nil || normalized == "" {
		normalized = strings.TrimSpace(sql)
	}
	digestBytes := sha256.Sum256([]byte(normalized))
	return "sha256:" + hex.EncodeToString(digestBytes[:])
}

func buildCancelEvent(entry cancelEntry, d policy.Decision, resultErr string) events.DBEvent {
	return events.DBEvent{
		EventID:            newEventID(),
		SessionID:          eventSessionID(entry.AgentSessionID, entry.ClientIdentity),
		Timestamp:          timeNow(),
		DBService:          entry.ServiceName,
		DBFamily:           "postgres",
		DBDialect:          "postgres",
		DBUser:             entry.DBUser,
		Database:           entry.Database,
		ApplicationName:    entry.ApplicationName,
		ClientIdentity:     entry.ClientIdentity,
		Effects:            []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeCancelRequest}},
		OperationGroup:     "session",
		OperationGroupID:   effects.GroupSession.ID(),
		OperationSubtype:   "cancel_request",
		StatementRedaction: events.RedactionNone,
		Decision:           buildDecision(d, false),
		Result:             events.EventResult{ErrorCode: resultErr},
		TxContext:          events.EventTxContext{DenyAction: "none"},
	}
}

func eventSessionID(agentSessionID, clientIdentity string) string {
	if agentSessionID != "" {
		return agentSessionID
	}
	return clientIdentity
}

func operationFromStatement(stmt effects.ClassifiedStatement) (string, uint8, string) {
	primary, ok := stmt.Primary()
	if !ok {
		return "", 0, ""
	}
	return primary.Group.String(), primary.Group.ID(), primary.Subtype.String()
}

func buildDecision(d policy.Decision, deniedBySibling bool) events.EventDecision {
	if deniedBySibling {
		return events.EventDecision{
			Verb:     "deny",
			RuleKind: "statement",
			Reason:   "denied by sibling statement",
		}
	}
	verb := d.Verb.String()
	if verb == "" {
		verb = "deny"
	}
	out := events.EventDecision{
		Verb:                verb,
		RuleKind:            d.RuleKind.String(),
		RuleName:            d.RuleName,
		MatchingEffectIndex: d.MatchingEffectIndex,
		Reason:              d.Reason,
	}
	if d.MatchingEffectGroup != effects.GroupUnknown {
		out.MatchingEffectGroup = d.MatchingEffectGroup.String()
	}
	if len(d.ContributingAuditRules) > 0 {
		out.ContributingAuditRules = append([]string(nil), d.ContributingAuditRules...)
	}
	return out
}

func perStmtSlice(sql string, stmt effects.ClassifiedStatement) string {
	if stmt.SourceStart == 0 && stmt.SourceEnd == 0 {
		return strings.TrimSpace(sql)
	}
	if int(stmt.SourceEnd) > len(sql) || stmt.SourceStart < 0 || stmt.SourceStart > stmt.SourceEnd {
		return strings.TrimSpace(sql)
	}
	return sql[stmt.SourceStart:stmt.SourceEnd]
}

// hasFilter returns true when the classifier indicated a WHERE clause was
// present. Plan 04c does not surface this from the classifier yet — Plan 05
// is expected to thread a WHERE-clause flag through effects.Effect. Until
// then we conservatively return false.
func hasFilter(_ effects.ClassifiedStatement) bool {
	return false
}

func firstResolutionReason(stmt effects.ClassifiedStatement) string {
	for _, eff := range stmt.Effects {
		for _, obj := range eff.ResolvedObjects {
			if obj.UnresolvedReason != "" {
				return obj.UnresolvedReason
			}
		}
	}
	return ""
}

// connInTx returns true when the connection is currently inside an upstream
// transaction (RFQ status 'T' or 'E'). Plan 05a routes the byte through
// smState; pre-smState callers (or tests that hand-build connState without
// initializing smState) get false.
func connInTx(c connState) bool {
	if c.smState == nil {
		return false
	}
	b := c.smState.LastUpstreamRFQ
	return b == 'T' || b == 'E'
}
