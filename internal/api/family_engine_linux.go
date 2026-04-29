//go:build linux

package api

import (
	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
)

// familyEngine describes which enforcement engine should handle socket-family
// blocking for a given configuration + capability snapshot.
type familyEngine int

const (
	familyEngineNone    familyEngine = iota // no engine available; warn if families configured
	familyEngineSeccomp                     // seccomp-bpf (primary)
	familyEnginePtrace                      // ptrace (fallback)
)

// selectFamilyBlockingEngine picks the appropriate enforcement engine for
// socket-family blocking given the resolved family list, the sandbox config,
// and the detected host capabilities.
//
// Decision order (per spec §"Engine selection"):
//  1. seccomp available + enabled in config → seccomp engine
//  2. seccomp unavailable/disabled AND ptrace available + enabled → ptrace engine
//  3. neither → familyEngineNone (caller logs a warning if families > 0)
//
// The function does NOT install anything; it only reports which engine should
// be used.  The seccomp path is wired by buildSeccompWrapperConfig; the ptrace
// path is wired by initPtraceTracer after calling this function.
func selectFamilyBlockingEngine(
	families []seccompkg.BlockedFamily,
	cfg *config.SandboxConfig,
	caps *capabilities.SecurityCapabilities,
) familyEngine {
	if len(families) == 0 {
		return familyEngineNone
	}

	seccompAvailable := caps != nil && caps.Seccomp
	seccompEnabled := cfg != nil && cfg.Seccomp.Enabled
	if seccompAvailable && seccompEnabled {
		return familyEngineSeccomp
	}

	ptraceAvailable := caps != nil && caps.Ptrace
	ptraceEnabled := cfg != nil && cfg.Ptrace.Enabled
	if ptraceAvailable && ptraceEnabled {
		return familyEnginePtrace
	}

	return familyEngineNone
}
