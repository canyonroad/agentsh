//go:build linux

package api

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/ptrace"
)

// initPtraceTracer initializes the ptrace tracer if configured.
// Called from NewApp on Linux when sandbox.ptrace.enabled is true.
func (a *App) initPtraceTracer() {
	cfg := a.cfg.Sandbox.Ptrace
	if !cfg.Enabled {
		return
	}

	// Resolve trash directory to absolute path. The config default is relative
	// (".agentsh_trash") which must be resolved against the sessions base dir,
	// not the tracee's CWD (which varies per command).
	trashDir := a.cfg.Sandbox.FUSE.Audit.TrashPath
	if trashDir != "" && !filepath.IsAbs(trashDir) {
		trashDir = filepath.Join(a.cfg.Sessions.BaseDir, trashDir)
	}
	if trashDir != "" {
		abs, err := filepath.Abs(trashDir)
		if err != nil {
			slog.Warn("ptrace: cannot resolve trash path, soft-delete disabled", "path", trashDir, "error", err)
			trashDir = ""
		} else {
			trashDir = abs
		}
	}

	router := &ptraceHandlerRouter{
		sessions:           a.sessions,
		store:              a.store,
		broker:             a.broker,
		staticAllowFile:    cfg.Performance.StaticAllowFile,
		staticAllowNetwork: cfg.Performance.StaticAllowNetwork,
		trashDir:           trashDir,
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
