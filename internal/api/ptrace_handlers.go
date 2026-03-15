//go:build linux

package api

import (
	"context"
	"log/slog"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/ptrace"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

// ptraceHandlerRouter routes ptrace syscall events to session-level policy
// engines. It implements all four ptrace handler interfaces.
type ptraceHandlerRouter struct {
	sessions *session.Manager
	store    *composite.Store
	broker   *events.Broker
}

var _ ptrace.ExecHandler = (*ptraceHandlerRouter)(nil)
var _ ptrace.FileHandler = (*ptraceHandlerRouter)(nil)
var _ ptrace.NetworkHandler = (*ptraceHandlerRouter)(nil)
var _ ptrace.SignalHandler = (*ptraceHandlerRouter)(nil)

func (r *ptraceHandlerRouter) HandleExecve(ctx context.Context, ec ptrace.ExecContext) ptrace.ExecResult {
	s, ok := r.sessions.Get(ec.SessionID)
	if !ok {
		slog.Warn("ptrace: unknown session for execve", "session_id", ec.SessionID, "pid", ec.PID)
		return ptrace.ExecResult{Allow: false, Action: "deny", Errno: int32(syscall.EACCES), Rule: "unknown_session"}
	}

	pe := s.PolicyEngine()
	if pe == nil {
		return ptrace.ExecResult{Allow: true, Action: "continue"}
	}

	decision := pe.CheckExecve(ec.Filename, ec.Argv, ec.Depth)

	// Emit audit event
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "ptrace_execve",
		SessionID: ec.SessionID,
		Fields: map[string]any{
			"pid":       ec.PID,
			"filename":  ec.Filename,
			"argv":      ec.Argv,
			"depth":     ec.Depth,
			"decision":  string(decision.EffectiveDecision),
			"rule":      decision.Rule,
			"truncated": ec.Truncated,
		},
	}
	_ = r.store.AppendEvent(ctx, ev)
	r.broker.Publish(ev)

	switch decision.EffectiveDecision {
	case types.DecisionDeny:
		return ptrace.ExecResult{
			Action: "deny",
			Allow:  false,
			Errno:  int32(syscall.EACCES),
			Rule:   decision.Rule,
		}
	case types.DecisionRedirect:
		if decision.Redirect != nil {
			return ptrace.ExecResult{
				Action:   "redirect",
				StubPath: decision.Redirect.Command,
				Rule:     decision.Rule,
			}
		}
		return ptrace.ExecResult{Allow: true, Action: "continue", Rule: decision.Rule}
	case types.DecisionApprove:
		// Approval-required decisions cannot be handled synchronously via ptrace.
		// Deny with a descriptive rule for audit visibility.
		return ptrace.ExecResult{
			Action: "deny",
			Allow:  false,
			Errno:  int32(syscall.EACCES),
			Rule:   decision.Rule + " (approval required, denied in ptrace mode)",
		}
	default:
		return ptrace.ExecResult{Allow: true, Action: "continue", Rule: decision.Rule}
	}
}

func (r *ptraceHandlerRouter) HandleFile(ctx context.Context, fc ptrace.FileContext) ptrace.FileResult {
	s, ok := r.sessions.Get(fc.SessionID)
	if !ok {
		slog.Warn("ptrace: unknown session for file", "session_id", fc.SessionID, "pid", fc.PID)
		return ptrace.FileResult{Allow: false, Action: "deny", Errno: int32(syscall.EACCES)}
	}

	pe := s.PolicyEngine()
	if pe == nil {
		return ptrace.FileResult{Allow: true, Action: "allow"}
	}

	decision := pe.CheckFile(fc.Path, fc.Operation)

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "ptrace_file",
		SessionID: fc.SessionID,
		Fields: map[string]any{
			"pid":       fc.PID,
			"path":      fc.Path,
			"operation": fc.Operation,
			"decision":  string(decision.EffectiveDecision),
			"rule":      decision.Rule,
		},
	}
	_ = r.store.AppendEvent(ctx, ev)
	r.broker.Publish(ev)

	switch decision.EffectiveDecision {
	case types.DecisionDeny:
		return ptrace.FileResult{
			Allow:  false,
			Action: "deny",
			Errno:  int32(syscall.EACCES),
		}
	case types.DecisionRedirect:
		if decision.FileRedirect != nil {
			return ptrace.FileResult{
				Action:       "redirect",
				RedirectPath: decision.FileRedirect.RedirectPath,
			}
		}
		return ptrace.FileResult{Allow: true, Action: "allow"}
	case types.DecisionSoftDelete:
		return ptrace.FileResult{
			Action:   "soft-delete",
			TrashDir: "", // trash dir resolved by caller
		}
	default:
		return ptrace.FileResult{Allow: true, Action: "allow"}
	}
}

func (r *ptraceHandlerRouter) HandleNetwork(ctx context.Context, nc ptrace.NetworkContext) ptrace.NetworkResult {
	s, ok := r.sessions.Get(nc.SessionID)
	if !ok {
		slog.Warn("ptrace: unknown session for network", "session_id", nc.SessionID, "pid", nc.PID)
		return ptrace.NetworkResult{Allow: false, Action: "deny", Errno: int32(syscall.EACCES)}
	}

	pe := s.PolicyEngine()
	if pe == nil {
		return ptrace.NetworkResult{Allow: true, Action: "allow"}
	}

	decision := pe.CheckNetwork(nc.Address, nc.Port)

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "ptrace_network",
		SessionID: nc.SessionID,
		Fields: map[string]any{
			"pid":       nc.PID,
			"address":   nc.Address,
			"port":      nc.Port,
			"operation": nc.Operation,
			"decision":  string(decision.EffectiveDecision),
			"rule":      decision.Rule,
		},
	}
	_ = r.store.AppendEvent(ctx, ev)
	r.broker.Publish(ev)

	switch decision.EffectiveDecision {
	case types.DecisionDeny:
		return ptrace.NetworkResult{
			Allow:  false,
			Action: "deny",
			Errno:  int32(syscall.EACCES),
		}
	default:
		return ptrace.NetworkResult{Allow: true, Action: "allow"}
	}
}

func (r *ptraceHandlerRouter) HandleSignal(ctx context.Context, sc ptrace.SignalContext) ptrace.SignalResult {
	_, ok := r.sessions.Get(sc.SessionID)
	if !ok {
		slog.Warn("ptrace: unknown session for signal", "session_id", sc.SessionID, "pid", sc.PID)
		return ptrace.SignalResult{Allow: false, Errno: int32(syscall.EACCES)}
	}

	// Signal filtering via ptrace — allow all signals for now.
	// Per-signal policy requires signal engine integration (future work).
	return ptrace.SignalResult{Allow: true}
}
