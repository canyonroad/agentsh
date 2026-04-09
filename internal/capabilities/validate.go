package capabilities

import (
	"fmt"
)

// modeRank defines the security strength of each mode (higher = stronger).
var modeRank = map[string]int{
	ModeFull:         4,
	ModeLandlock:     3,
	ModeLandlockOnly: 2,
	ModeMinimal:      1,
}

// ValidateStrictMode checks that required capabilities are available for the mode.
func ValidateStrictMode(mode string, caps *SecurityCapabilities) error {
	switch mode {
	case ModeFull:
		if !caps.Seccomp {
			return fmt.Errorf("strict mode %q requires seccomp", mode)
		}
		if !caps.EBPF {
			return fmt.Errorf("strict mode %q requires eBPF", mode)
		}
		if !caps.FUSE {
			return fmt.Errorf("strict mode %q requires FUSE", mode)
		}

	case ModeLandlock:
		if !caps.Landlock {
			return fmt.Errorf("strict mode %q requires Landlock", mode)
		}
		if !caps.FUSE {
			return fmt.Errorf("strict mode %q requires FUSE", mode)
		}

	case ModeLandlockOnly:
		if !caps.Landlock {
			return fmt.Errorf("strict mode %q requires Landlock", mode)
		}

	case ModeMinimal:
		// Always passes

	default:
		return fmt.Errorf("unknown security mode: %s", mode)
	}

	return nil
}

// ValidateMinimumMode checks that the selected mode meets the minimum requirement.
func ValidateMinimumMode(selected, minimum string) error {
	if minimum == "" {
		return nil
	}

	selectedRank, ok := modeRank[selected]
	if !ok {
		return fmt.Errorf("unknown mode: %s", selected)
	}

	minimumRank, ok := modeRank[minimum]
	if !ok {
		return fmt.Errorf("unknown minimum mode: %s", minimum)
	}

	if selectedRank < minimumRank {
		return fmt.Errorf("selected mode %q does not meet minimum requirement %q", selected, minimum)
	}

	return nil
}

// PolicyWarning represents a warning about policy enforcement limitations.
type PolicyWarning struct {
	Level   string // "warn" or "info"
	Message string
}

// ValidatePolicyForMode checks if policy rules can be enforced in the current mode.
func ValidatePolicyForMode(caps *SecurityCapabilities, hasUnixSocketRules, hasSignalRules, hasNetworkRules bool) []PolicyWarning {
	var warnings []PolicyWarning

	if !caps.Seccomp && hasUnixSocketRules {
		warnings = append(warnings, PolicyWarning{
			Level:   "warn",
			Message: "Unix socket rules defined but seccomp unavailable - abstract sockets unprotected",
		})
	}

	if !caps.Seccomp && hasSignalRules {
		warnings = append(warnings, PolicyWarning{
			Level:   "warn",
			Message: "Signal rules defined but seccomp unavailable - relying on PID namespace + CAP_KILL drop",
		})
	}

	if !caps.LandlockNetwork && !caps.EBPF && hasNetworkRules {
		warnings = append(warnings, PolicyWarning{
			Level:   "warn",
			Message: "Network rules defined but no enforcement available (need eBPF or Landlock ABI v4+)",
		})
	}

	return warnings
}

// ModeDescription returns a human-readable description of the security mode.
//
// This form is kept for callers that do not have a SecurityCapabilities
// handy (e.g. config tooling). When a caps pointer is available, prefer
// ModeDescriptionWithCaps so the minimal-mode wording can reflect the
// behavioural capability-drop probe result.
func ModeDescription(mode string) string {
	switch mode {
	case ModeFull:
		return "Full security: seccomp + eBPF + FUSE (100% policy enforcement)"
	case ModeLandlock:
		return "Landlock security: Landlock + FUSE (~85% policy enforcement)"
	case ModeLandlockOnly:
		return "Landlock-only security: Landlock (~80% policy enforcement)"
	case ModeMinimal:
		// Generic wording used when the caller has no caps handle.
		// ModeDescriptionWithCaps below returns a more honest string
		// when the behavioural probe is available.
		return "Minimal security: fallback mode (~50% policy enforcement)"
	default:
		return "Unknown security mode"
	}
}

// ModeDescriptionWithCaps returns a human-readable description of the
// security mode that reflects the behavioural capability-drop probe.
//
// Before #198 the minimal mode was always described as "capability
// dropping only", which claimed privilege reduction was happening even
// on a root server that had never dropped anything. After the mechanism
// vs. active split, the minimal description is now gated on
// CapabilitiesActive so a root/no-drop process no longer gets a
// contradictory startup line (description says "capability dropping
// only" while the new capabilities_active=false log field says nothing
// is being dropped).
//
// Callers with access to the detected SecurityCapabilities (server
// startup logging, agentsh detect) should use this form; pure mode
// string consumers fall back to ModeDescription.
func ModeDescriptionWithCaps(mode string, caps *SecurityCapabilities) string {
	if mode != ModeMinimal || caps == nil {
		return ModeDescription(mode)
	}
	if caps.CapabilitiesActive {
		return "Minimal security: capability dropping only (~50% policy enforcement)"
	}
	return "Minimal security: fallback mode, no active enforcement primitives (privilege reduction inactive — process retains full Linux capabilities)"
}
