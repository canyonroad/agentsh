//go:build linux

package api

import (
	"context"
	"log/slog"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/ptrace"
)

// initPtraceTracer initializes the ptrace tracer if configured.
// Called from NewApp on Linux when sandbox.ptrace.enabled is true.
// Also wires FamilyChecker when ptrace is the selected enforcement engine
// for socket-family blocking (seccomp unavailable/disabled, ptrace available).
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

	// Engine selection for socket-family blocking.
	// Resolve the family list once; selectFamilyBlockingEngine decides
	// which enforcement path to use based on config + host capabilities.
	var familyChecker *ptrace.FamilyChecker
	families, err := config.ResolveBlockedFamilies(a.cfg.Sandbox.Seccomp.BlockedSocketFamilies)
	if err != nil {
		slog.Warn("initPtraceTracer: failed to resolve blocked_socket_families; socket-family blocking will not be enforced via ptrace",
			"error", err)
	} else {
		caps := capabilities.DetectSecurityCapabilities()
		switch selectFamilyBlockingEngine(families, &a.cfg.Sandbox, caps) {
		case familyEnginePtrace:
			familyChecker = ptrace.NewFamilyChecker(families)
			slog.Info("socket-family blocking: using ptrace engine",
				"families", len(families))
		case familyEngineSeccomp:
			// seccomp handles it via buildSeccompWrapperConfig; nothing to do here.
		case familyEngineNone:
			if len(families) > 0 {
				slog.Warn("socket-family blocking is configured but no enforcement engine is available on this host "+
					"(seccomp and ptrace both unavailable or disabled); families will not be blocked",
					"families", len(families))
			}
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
