// Package kernelinstall lets the shim install seccomp + Landlock on its own
// process before execve, so the user's command inherits the filter even when
// the shim is not a child of the agentsh server (sandbox-SDK pattern).
package kernelinstall

import "fmt"

// Mode controls whether the shim attempts kernel-filter install.
// Order is meaningful: off < auto < on (lower = weaker enforcement).
type Mode int

const (
	ModeOff  Mode = iota // never install (admin opt-out)
	ModeAuto             // install when wrap-init returns a populated response
	ModeOn               // install or fail-closed
)

func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeAuto:
		return "auto"
	case ModeOn:
		return "on"
	default:
		return "unknown"
	}
}

// ResolveMode picks the effective mode from the trusted config-file value
// and the (untrusted, caller-controlled) env-var override.
//
// Trust model: /etc/agentsh/shim.conf is root-owned and admin-managed,
// so its value is authoritative. The AGENTSH_SHIM_INSTALL env var is
// readable from the caller's environment, so a malicious sandbox-SDK
// supervisor could pre-set it. To prevent silent bypass, the env var
// is honored ONLY if it would STRENGTHEN the effective mode (i.e.,
// produce a higher Mode value in the off < auto < on ordering). An
// env-var attempt to weaken is silently ignored — the config wins.
//
// Empty conf defaults to ModeAuto. Empty env is ignored.
func ResolveMode(conf, env string) (Mode, error) {
	confMode, err := parseMode(conf, ModeAuto)
	if err != nil {
		return ModeAuto, fmt.Errorf("conf: %w", err)
	}
	if env == "" {
		return confMode, nil
	}
	envMode, err := parseMode(env, confMode)
	if err != nil {
		return confMode, fmt.Errorf("env: %w", err)
	}
	// Env may only strengthen.
	if envMode > confMode {
		return envMode, nil
	}
	return confMode, nil
}

// parseMode parses a mode string. Empty string returns the supplied default.
// Unknown values return an error.
func parseMode(s string, def Mode) (Mode, error) {
	if s == "" {
		return def, nil
	}
	switch s {
	case "off":
		return ModeOff, nil
	case "auto":
		return ModeAuto, nil
	case "on":
		return ModeOn, nil
	default:
		return def, fmt.Errorf("invalid mode %q (expected auto, on, or off)", s)
	}
}
