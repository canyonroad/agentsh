//go:build linux && cgo

package api

import (
	"log/slog"
	"sync"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/policy"
)

var (
	globalMountRegistry     *unixmon.MountRegistry
	globalMountRegistryOnce sync.Once
)

func getMountRegistry() *unixmon.MountRegistry {
	globalMountRegistryOnce.Do(func() {
		globalMountRegistry = unixmon.NewMountRegistry()
	})
	return globalMountRegistry
}

// filePolicyEngineWrapper adapts policy.Engine to unixmon.FilePolicyChecker.
type filePolicyEngineWrapper struct {
	engine *policy.Engine
}

func (w *filePolicyEngineWrapper) CheckFile(path, operation string) unixmon.FilePolicyDecision {
	dec := w.engine.CheckFile(path, operation)
	return unixmon.FilePolicyDecision{
		Decision:          string(dec.PolicyDecision),
		EffectiveDecision: string(dec.EffectiveDecision),
		Rule:              dec.Rule,
		Message:           dec.Message,
	}
}

// createFileHandler creates a FileHandler from configuration.
// landlockEnabled indicates whether Landlock enforcement is configured (not just kernel-available).
func createFileHandler(cfg config.SandboxSeccompFileMonitorConfig, pol *policy.Engine, emitter unixmon.Emitter, landlockEnabled bool) *unixmon.FileHandler {
	if !config.FileMonitorBoolWithDefault(cfg.Enabled, false) {
		return nil
	}

	var policyChecker unixmon.FilePolicyChecker
	if pol != nil {
		policyChecker = &filePolicyEngineWrapper{engine: pol}
	}

	registry := getMountRegistry()
	enforce := config.FileMonitorBoolWithDefault(cfg.EnforceWithoutFUSE, false)
	handler := unixmon.NewFileHandler(policyChecker, registry, emitter, enforce)

	// Enable AddFD emulation when configured and the kernel supports it.
	// IMPORTANT: emulated opens run in the supervisor's context, outside the
	// tracee's Landlock/FUSE restrictions. Only enable when seccomp-notify is
	// the sole enforcement backend (no Landlock, no FUSE).
	defaultVal := config.FileMonitorBoolWithDefault(cfg.EnforceWithoutFUSE, false)
	openatEmulation := config.FileMonitorBoolWithDefault(cfg.OpenatEmulation, defaultVal)
	if openatEmulation && enforce && unixmon.ProbeAddFDSupport() {
		landlockActive := landlockEnabled && capabilities.DetectLandlock().Available
		fuseActive := registry.HasAnyMounts()
		if !landlockActive && !fuseActive {
			handler.SetEmulateOpen(true)
		} else {
			slog.Info("seccomp openat emulation disabled: other backend active",
				"landlock", landlockActive, "fuse_mounts", fuseActive)
		}
	}

	return handler
}

// registerFUSEMount records a FUSE mount point in the global MountRegistry
// so the seccomp FileHandler defers enforcement for paths under the FUSE mount.
func registerFUSEMount(sessionID, mountPoint string) {
	getMountRegistry().Register(sessionID, mountPoint)
	slog.Debug("registered FUSE mount in MountRegistry",
		"session_id", sessionID,
		"mount_point", mountPoint)
}

// deregisterFUSEMount removes a FUSE mount point from the global MountRegistry
// during session teardown.
func deregisterFUSEMount(sessionID, mountPoint string) {
	getMountRegistry().Deregister(sessionID, mountPoint)
	slog.Debug("deregistered FUSE mount from MountRegistry",
		"session_id", sessionID,
		"mount_point", mountPoint)
}
