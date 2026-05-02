//go:build linux

package api

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/ptrace"
	"github.com/agentsh/agentsh/pkg/types"
)

// ptraceFamilyEmitter adapts the API's event store/broker to the
// ptrace.FamilyEmitter interface so family-block audit events reach the
// same sink as the seccomp engine's events.
type ptraceFamilyEmitter struct {
	store  eventStore
	broker eventBroker
}

func (e *ptraceFamilyEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	return e.store.AppendEvent(ctx, ev)
}

func (e *ptraceFamilyEmitter) Publish(ev types.Event) {
	e.broker.Publish(ev)
}

// initPtraceTracer initializes the ptrace tracer if configured.
// Called from NewApp on Linux when sandbox.ptrace.enabled is true.
// Always wires FamilyChecker when families are configured, regardless of which
// engine the selector reports as primary. Runtime dispatch is mutually exclusive
// (a syscall reaches at most one engine), so dual installation is safe.
func (a *App) initPtraceTracer() {
	cfg := a.cfg.Sandbox.Ptrace
	if !cfg.Enabled {
		// Even when ptrace is disabled, check if socket-family blocking is
		// configured but has no enforcement engine available, and warn.
		a.warnIfFamiliesOrphan()
		return
	}

	router := &ptraceHandlerRouter{
		sessions:           a.sessions,
		store:              a.store,
		broker:             a.broker,
		staticAllowFile:    cfg.Performance.StaticAllowFile,
		staticAllowNetwork: cfg.Performance.StaticAllowNetwork,
		trashPath:          a.cfg.Sandbox.FUSE.Audit.TrashPath,
	}

	// Socket-family blocking: resolve families once, then wire defensively.
	//
	// Always install the FamilyChecker when families are configured and the
	// ptrace tracer is being initialized.  selectFamilyBlockingEngine is used
	// only for the warn-and-continue path (familyEngineNone) and is no longer
	// load-bearing for deciding which engine enforces.  The seccomp engine has
	// its own independent wiring path (buildSeccompWrapperConfig); runtime
	// dispatch is mutually exclusive, so dual installation is safe — no
	// double-audit risk.
	emit := &ptraceFamilyEmitter{store: a.store, broker: a.broker}
	familyChecker, err := resolveFamilyCheckerForPtrace(a.cfg, emit)
	if err != nil {
		slog.Warn("initPtraceTracer: failed to resolve blocked_socket_families; socket-family blocking will not be enforced via ptrace",
			"error", err)
	} else {
		families, _ := config.ResolveBlockedFamilies(a.cfg.Sandbox.Seccomp.BlockedSocketFamilies)
		if familyChecker != nil {
			slog.Info("socket-family blocking: wired FamilyChecker on ptrace tracer",
				"families", len(families))
		}
		caps := capabilities.DetectSecurityCapabilities()
		engine := selectFamilyBlockingEngine(families, &a.cfg.Sandbox, caps)
		if engine == familyEngineNone && len(families) > 0 {
			slog.Warn("socket-family blocking is configured but no enforcement engine is available; families will not be blocked",
				"families_count", len(families))
		}
	}

	tr := ptrace.NewTracer(ptrace.TracerConfig{
		AttachMode:       cfg.AttachMode,
		TraceExecve:      cfg.Trace.Execve,
		TraceFile:        cfg.Trace.File,
		TraceNetwork:     cfg.Trace.Network,
		TraceSignal:      cfg.Trace.Signal,
		MaskTracerPid:    false, // validation rejects non-"off" values for now
		SeccompPrefilter: cfg.Performance.SeccompPrefilter,
		ArgLevelFilter:   cfg.Performance.ArgLevelFilter,
		MaxTracees:       cfg.Performance.MaxTracees,
		MaxHoldMs:        cfg.Performance.MaxHoldMs,
		OnAttachFailure:  cfg.OnAttachFailure,
		ExecHandler:      router,
		FileHandler:      router,
		NetworkHandler:   router,
		SignalHandler:    router,
		FamilyChecker:    familyChecker,
	})

	ctx, cancel := context.WithCancel(context.Background())
	a.ptraceTracer = tr
	a.ptraceCancel = cancel
	go func() {
		if err := tr.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("ptrace tracer exited unexpectedly, blocking commands (fail-closed)", "error", err)
			a.ptraceFailed.Store(true)
		}
	}()
	slog.Info("ptrace tracer started", "attach_mode", cfg.AttachMode)

	// attach_mode: "pid" — attach to the configured target so PTRACE_O_TRACEFORK
	// catches all its descendants. Without this wiring, the AttachMode field is
	// parsed and validated but the runtime never calls AttachPID — the tracer
	// runs with zero tracees and policy enforcement silently no-ops.
	//
	// Useful for hosts where the agentsh server is not the ancestor of the
	// process tree being governed (OpenComputer's osb-agent, generic Docker
	// exec setups, sidecar deployments, etc.).
	if cfg.AttachMode == "pid" {
		targetPID := cfg.TargetPID
		if targetPID == 0 && cfg.TargetPIDFile != "" {
			b, err := os.ReadFile(cfg.TargetPIDFile)
			if err != nil {
				slog.Error("ptrace: failed to read target_pid_file",
					"path", cfg.TargetPIDFile, "error", err)
				if cfg.OnAttachFailure == "fail_closed" {
					a.ptraceFailed.Store(true)
				}
			} else {
				n, parseErr := strconv.Atoi(strings.TrimSpace(string(b)))
				if parseErr != nil || n <= 0 {
					slog.Error("ptrace: target_pid_file does not contain a valid pid",
						"path", cfg.TargetPIDFile, "error", parseErr, "raw", string(b))
					if cfg.OnAttachFailure == "fail_closed" {
						a.ptraceFailed.Store(true)
					}
				} else {
					targetPID = n
				}
			}
		}
		if targetPID > 0 {
			go func(pid int) {
				if err := tr.AttachPID(pid); err != nil {
					slog.Error("ptrace: AttachPID failed", "pid", pid, "error", err)
					if cfg.OnAttachFailure == "fail_closed" {
						a.ptraceFailed.Store(true)
					}
					return
				}
				if err := tr.WaitAttached(pid); err != nil {
					slog.Error("ptrace: WaitAttached failed", "pid", pid, "error", err)
					if cfg.OnAttachFailure == "fail_closed" {
						a.ptraceFailed.Store(true)
					}
					return
				}
				slog.Info("ptrace: attached to target PID", "pid", pid)
			}(targetPID)
		}
	}
}

// resolveFamilyCheckerForPtrace resolves the FamilyChecker to install on the
// ptrace tracer for the given app config.  Returns a non-nil checker
// whenever families are configured, regardless of which engine
// selectFamilyBlockingEngine reports as primary.  The caller is responsible
// for the warn-and-continue log when the selector returns familyEngineNone.
//
// emit is wired into the checker so every family-block fires an audit event
// through the same sink as the seccomp engine.  Pass nil to skip audit
// emission (tests / cases where the emitter is not yet available).
//
// Extracted as a standalone function for testability.
func resolveFamilyCheckerForPtrace(cfg *config.Config, emit ptrace.FamilyEmitter) (*ptrace.FamilyChecker, error) {
	families, err := config.ResolveBlockedFamilies(cfg.Sandbox.Seccomp.BlockedSocketFamilies)
	if err != nil {
		return nil, err
	}
	if len(families) == 0 {
		return nil, nil
	}
	return ptrace.NewFamilyCheckerWithEmitter(families, emit), nil
}

// closePtraceTracer stops the ptrace tracer if running.
func (a *App) closePtraceTracer() {
	if a.ptraceCancel != nil {
		a.ptraceCancel()
		a.ptraceCancel = nil
	}
}

// warnIfFamiliesOrphan emits a warning when socket-family blocking is
// configured but neither seccomp nor ptrace is available/enabled.
// Called from initPtraceTracer when ptrace is disabled, to cover the
// case where seccomp is also absent.
func (a *App) warnIfFamiliesOrphan() {
	if len(a.cfg.Sandbox.Seccomp.BlockedSocketFamilies) == 0 {
		return
	}
	families, err := config.ResolveBlockedFamilies(a.cfg.Sandbox.Seccomp.BlockedSocketFamilies)
	if err != nil || len(families) == 0 {
		return
	}
	caps := capabilities.DetectSecurityCapabilities()
	if selectFamilyBlockingEngine(families, &a.cfg.Sandbox, caps) == familyEngineNone {
		slog.Warn("socket-family blocking is configured but no enforcement engine is available on this host "+
			"(seccomp and ptrace both unavailable or disabled); families will not be blocked",
			"families", len(families))
	}
}
