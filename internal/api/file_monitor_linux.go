//go:build linux && cgo

package api

import (
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
	return unixmon.NewFileHandler(policyChecker, registry, emitter, enforce)
}
