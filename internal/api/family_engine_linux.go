//go:build linux

package api

import (
	"os/exec"
	"strings"

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

// familyEngineLookPath is the exec.LookPath function used to check wrapper binary
// availability. Package-level variable for testability (matches wrapperLookPath
// pattern in the capabilities package).
var familyEngineLookPath = exec.LookPath

// wrapperWillRun returns true when the seccomp wrapper (agentsh-unixwrap) is
// expected to actually run for the given config.  Two conditions must hold:
//
//  1. unix_sockets is enabled in config (nil defaults to true, per applyDefaults).
//  2. The wrapper binary is present on PATH (or at the configured override path).
//
// Kernel seccomp support (caps.Seccomp) is a necessary but not sufficient
// condition: the wrapper binary must also be reachable, otherwise the seccomp
// engine commits to enforcement but installs nothing — silent fail-open.
func wrapperWillRun(cfg *config.SandboxConfig) bool {
	if cfg == nil {
		return false
	}

	// unix_sockets.enabled: nil means "defaulted to true" by applyDefaults,
	// but selectFamilyBlockingEngine may be called before defaults are applied
	// (e.g. in tests).  Treat nil as enabled, matching the runtime behaviour.
	if cfg.UnixSockets.Enabled != nil && !*cfg.UnixSockets.Enabled {
		return false
	}

	wrapperBin := strings.TrimSpace(cfg.UnixSockets.WrapperBin)
	if wrapperBin == "" {
		wrapperBin = "agentsh-unixwrap"
	}

	_, err := familyEngineLookPath(wrapperBin)
	return err == nil
}

// selectFamilyBlockingEngine reports which engine WILL primarily enforce
// socket-family blocking given the resolved family list, the sandbox config,
// and the detected host capabilities.  Used for diagnostics and the
// warn-and-continue path only — it is NOT load-bearing for which engine
// actually enforces.  Both the seccomp and ptrace engines may hold the
// FamilyChecker; runtime dispatch is mutually exclusive (a syscall reaches at
// most one engine), so dual installation is safe.
//
// Decision order (per spec §"Engine selection"):
//  1. seccomp available + enabled in config + wrapper will run → seccomp engine
//  2. seccomp unavailable/disabled OR wrapper absent AND ptrace available + enabled → ptrace engine
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
	if seccompAvailable && seccompEnabled && wrapperWillRun(cfg) {
		return familyEngineSeccomp
	}

	ptraceAvailable := caps != nil && caps.Ptrace
	ptraceEnabled := cfg != nil && cfg.Ptrace.Enabled
	if ptraceAvailable && ptraceEnabled {
		return familyEnginePtrace
	}

	return familyEngineNone
}
