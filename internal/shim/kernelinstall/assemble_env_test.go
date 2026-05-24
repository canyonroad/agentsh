//go:build linux

package kernelinstall

import (
	"strings"
	"testing"
)

func envCount(env []string, key string) (string, int) {
	val, n := "", 0
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if ok && k == key {
			val = v
			n++
		}
	}
	return val, n
}

// TestAssembleWrapperEnv_AppliesEnvInject is the shim-side regression guard for
// issue #374: env_inject from the wrap-init response must be overlaid onto the
// wrapper child's environment, overriding inherited values, while the internal
// AGENTSH_* markers stay authoritative.
func TestAssembleWrapperEnv_AppliesEnvInject(t *testing.T) {
	base := []string{
		"BASH_ENV=/inherited",
		"PATH=/usr/bin",
	}
	wrapperEnv := map[string]string{
		"AGENTSH_SECCOMP_CONFIG": "{}",
		signalSockFDKey:          "4", // must be stripped in shim mode
	}
	envInject := map[string]string{
		"BASH_ENV":          "/usr/lib/agentsh/bash_startup.sh",
		"OTEL_SERVICE_NAME": "agentsh-blaxel",
	}

	env := assembleWrapperEnv(base, "/bin/sh", wrapperEnv, envInject)

	if v, n := envCount(env, "BASH_ENV"); v != "/usr/lib/agentsh/bash_startup.sh" || n != 1 {
		t.Errorf("BASH_ENV = %q (count %d), want injected value exactly once", v, n)
	}
	if v, n := envCount(env, "OTEL_SERVICE_NAME"); v != "agentsh-blaxel" || n != 1 {
		t.Errorf("OTEL_SERVICE_NAME = %q (count %d), want agentsh-blaxel once", v, n)
	}
	if v, _ := envCount(env, "PATH"); v != "/usr/bin" {
		t.Errorf("PATH = %q, want untouched", v)
	}
	if v, n := envCount(env, "AGENTSH_NOTIFY_SOCK_FD"); v != "3" || n != 1 {
		t.Errorf("AGENTSH_NOTIFY_SOCK_FD = %q (count %d), want 3 once", v, n)
	}
	if v, n := envCount(env, argv0EnvKey); v != "/bin/sh" || n != 1 {
		t.Errorf("%s = %q (count %d), want /bin/sh once", argv0EnvKey, v, n)
	}
	if v, n := envCount(env, "AGENTSH_SECCOMP_CONFIG"); v != "{}" || n != 1 {
		t.Errorf("AGENTSH_SECCOMP_CONFIG = %q (count %d), want {} once", v, n)
	}
	if _, n := envCount(env, signalSockFDKey); n != 0 {
		t.Errorf("%s present %d times, want stripped in shim mode", signalSockFDKey, n)
	}
}

func TestAssembleWrapperEnv_NoArgv0_NoEnvInject(t *testing.T) {
	base := []string{"PATH=/usr/bin"}
	env := assembleWrapperEnv(base, "", map[string]string{"AGENTSH_SECCOMP_CONFIG": "{}"}, nil)

	if _, n := envCount(env, argv0EnvKey); n != 0 {
		t.Errorf("%s present %d times, want absent when argv0 empty", argv0EnvKey, n)
	}
	if v, n := envCount(env, "AGENTSH_NOTIFY_SOCK_FD"); v != "3" || n != 1 {
		t.Errorf("AGENTSH_NOTIFY_SOCK_FD = %q (count %d), want 3 once", v, n)
	}
	if v, _ := envCount(env, "PATH"); v != "/usr/bin" {
		t.Errorf("PATH = %q, want untouched", v)
	}
}
