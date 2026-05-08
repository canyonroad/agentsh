//go:build linux

package ptrace

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

// SocketRuleChecker matches socket(2)/socketpair(2) calls against resolved
// socket tuple rules. Rules are evaluated in configuration order so the first
// specific match wins.
type SocketRuleChecker struct {
	rules []seccomp.SocketRule
	emit  FamilyEmitter

	// tgkillFn and denySyscallFn mirror FamilyChecker's test seams.
	tgkillFn      func(tgid, tid int, sig unix.Signal) error
	denySyscallFn func(tid int, errno int) error
}

// NewSocketRuleChecker indexes socket tuple rules for ptrace enforcement.
// nil/empty input produces a checker that never matches.
func NewSocketRuleChecker(rules []seccomp.SocketRule) *SocketRuleChecker {
	return NewSocketRuleCheckerWithEmitter(rules, nil)
}

// NewSocketRuleCheckerWithEmitter wires socket tuple rules to the shared
// audit sink. Pass nil emit to skip event-store emission in tests/local use.
func NewSocketRuleCheckerWithEmitter(rules []seccomp.SocketRule, emit FamilyEmitter) *SocketRuleChecker {
	c := &SocketRuleChecker{
		emit: emit,
		tgkillFn: func(tgid, tid int, sig unix.Signal) error {
			return unix.Tgkill(tgid, tid, sig)
		},
	}
	if len(rules) > 0 {
		c.rules = cloneSocketRules(rules)
	}
	return c
}

// Check reports the first socket tuple rule matching syscall+args.
// Only SYS_SOCKET and SYS_SOCKETPAIR are eligible.
func (c *SocketRuleChecker) Check(syscall, family, typ, protocol uint64) (seccomp.SocketRule, bool) {
	if c == nil || len(c.rules) == 0 {
		return seccomp.SocketRule{}, false
	}
	switch syscall {
	case uint64(unix.SYS_SOCKET):
		for _, rule := range c.rules {
			if rule.MatchesSocket(family, typ, protocol) {
				return cloneSocketRule(rule), true
			}
		}
	case uint64(unix.SYS_SOCKETPAIR):
		for _, rule := range c.rules {
			if rule.MatchesSocketpair(family, typ, protocol) {
				return cloneSocketRule(rule), true
			}
		}
	}
	return seccomp.SocketRule{}, false
}

func cloneSocketRules(rules []seccomp.SocketRule) []seccomp.SocketRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]seccomp.SocketRule, len(rules))
	for i, rule := range rules {
		out[i] = cloneSocketRule(rule)
	}
	return out
}

func cloneSocketRule(rule seccomp.SocketRule) seccomp.SocketRule {
	if rule.Type != nil {
		typ := *rule.Type
		rule.Type = &typ
	}
	if rule.Protocol != nil {
		protocol := *rule.Protocol
		rule.Protocol = &protocol
	}
	return rule
}

// Apply executes the blocking action for a matched socket tuple rule.
// Behavior intentionally mirrors FamilyChecker.Apply so ptrace fallback
// enforces the same errno/kill/log semantics as socket-family blocking.
func (c *SocketRuleChecker) Apply(
	tid int,
	tgid int,
	tracer *Tracer,
	action seccomp.OnBlockAction,
	syscallNr int,
	rule seccomp.SocketRule,
	sessionID string,
) error {
	denySC := c.denySyscallFn
	if denySC == nil {
		denySC = func(t int, errno int) error {
			return tracer.denySyscall(t, errno)
		}
	}

	switch action {
	case seccomp.OnBlockErrno:
		if err := denySC(tid, int(unix.EAFNOSUPPORT)); err != nil {
			if errors.Is(err, unix.ESRCH) {
				return ptraceAlreadyResumed
			}
			return err
		}
		return ptraceAlreadyResumed

	case seccomp.OnBlockKill, seccomp.OnBlockLogAndKill:
		tgkill := c.tgkillFn
		if tgkill == nil {
			tgkill = func(tg, t int, sig unix.Signal) error {
				return unix.Tgkill(tg, t, sig)
			}
		}

		err := tgkill(tgid, tid, unix.SIGKILL)
		var actualOutcome string
		var retErr error

		if err == nil {
			actualOutcome = "killed"
			retErr = PtraceKillRequested
		} else if errors.Is(err, unix.ESRCH) {
			actualOutcome = "vanished"
			retErr = nil
		} else {
			if denyErr := denySC(tid, int(unix.EAFNOSUPPORT)); denyErr != nil {
				slog.Warn("ptrace: socket-rule tgkill failed and deny fallback also failed",
					"tid", tid, "rule", rule.Name, "tgkill_err", err, "deny_err", denyErr)
				actualOutcome = "deny_fallback_failed"
			} else {
				slog.Warn("ptrace: socket-rule tgkill failed; denied syscall instead",
					"tid", tid, "rule", rule.Name, "tgkill_err", err)
				actualOutcome = "denied"
			}
			retErr = ptraceAlreadyResumed
		}

		if action == seccomp.OnBlockLogAndKill {
			c.emitSocketRuleBlocked(tid, syscallNr, rule, action, sessionID, actualOutcome)
		}
		return retErr

	case seccomp.OnBlockLog:
		actualOutcome := "denied"
		if err := denySC(tid, int(unix.EAFNOSUPPORT)); err != nil {
			if errors.Is(err, unix.ESRCH) {
				actualOutcome = "vanished"
				c.emitSocketRuleBlocked(tid, syscallNr, rule, action, sessionID, actualOutcome)
				return ptraceAlreadyResumed
			}
			actualOutcome = "deny_failed"
			c.emitSocketRuleBlocked(tid, syscallNr, rule, action, sessionID, actualOutcome)
			return err
		}
		c.emitSocketRuleBlocked(tid, syscallNr, rule, action, sessionID, actualOutcome)
		return ptraceAlreadyResumed

	default:
		return nil
	}
}

func (c *SocketRuleChecker) emitSocketRuleBlocked(
	tid int,
	syscallNr int,
	rule seccomp.SocketRule,
	action seccomp.OnBlockAction,
	sessionID string,
	outcome string,
) {
	syscallName := familySyscallName(syscallNr)
	slog.Debug("ptrace: socket rule blocked",
		"session_id", sessionID,
		"rule_name", rule.Name,
		"family_name", rule.FamilyName,
		"family_number", rule.Family,
		"syscall", syscallName,
		"syscall_nr", syscallNr,
		"action", string(action),
		"outcome", outcome,
		"engine", "ptrace",
		"pid", tid,
		"arch", runtime.GOARCH,
	)
	if c == nil || c.emit == nil {
		return
	}

	fields := map[string]any{
		"rule_name":     rule.Name,
		"family_name":   rule.FamilyName,
		"family_number": rule.Family,
		"syscall":       syscallName,
		"syscall_nr":    uint32(syscallNr),
		"action":        string(action),
		"outcome":       outcome,
		"arch":          runtime.GOARCH,
		"engine":        "ptrace",
	}
	if rule.Type != nil {
		fields["type_number"] = *rule.Type
		if rule.TypeName != "" {
			fields["type_name"] = rule.TypeName
		}
	}
	if rule.Protocol != nil {
		fields["protocol_number"] = *rule.Protocol
		if rule.ProtocolName != "" {
			fields["protocol_name"] = rule.ProtocolName
		}
	}

	ev := types.Event{
		ID:        fmt.Sprintf("ptrace-%d-%d", tid, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "seccomp_socket_rule_blocked",
		SessionID: sessionID,
		Source:    "ptrace",
		PID:       tid,
		Fields:    fields,
	}
	if err := c.emit.AppendEvent(context.Background(), ev); err != nil {
		slog.Warn("ptrace socket-rule: AppendEvent failed",
			"session_id", sessionID, "tid", tid, "rule", rule.Name, "error", err)
	}
	c.emit.Publish(ev)
}
