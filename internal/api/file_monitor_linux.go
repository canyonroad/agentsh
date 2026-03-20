//go:build linux && cgo

package api

import (
	"log/slog"
	"sync"

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
func createFileHandler(cfg config.SandboxSeccompFileMonitorConfig, pol *policy.Engine, emitter unixmon.Emitter) *unixmon.FileHandler {
	if !cfg.Enabled {
		return nil
	}

	var policyChecker unixmon.FilePolicyChecker
	if pol != nil {
		policyChecker = &filePolicyEngineWrapper{engine: pol}
	}

	registry := getMountRegistry()
	enforce := cfg.EnforceWithoutFUSE
	handler := unixmon.NewFileHandler(policyChecker, registry, emitter, enforce)

	// Enable AddFD emulation when configured. The enforce_without_fuse flag
	// signals that FUSE is not available for this deployment — trust the config
	// rather than re-detecting global state, which could be affected by
	// unrelated sessions.
	defaultVal := cfg.EnforceWithoutFUSE
	openatEmulation := config.FileMonitorBoolWithDefault(cfg.OpenatEmulation, defaultVal)
	if openatEmulation && enforce {
		handler.SetEmulateOpen(true)
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
