//go:build linux && cgo

package main

import (
	"reflect"
	"testing"
)

// TestApplyArgv0Override covers the Alpine busybox regression
// (canyonroad/agentsh#270 follow-up): the shim sets
// AGENTSH_UNIXWRAP_ARGV0 so busybox-multicall binaries see the original
// invocation name (e.g. "/bin/sh") instead of the renamed
// "/bin/sh.real" — busybox uses argv[0] basename to pick its applet,
// and "sh.real" is not a known applet.
func TestApplyArgv0Override(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		override string
		want     []string
	}{
		{
			name:     "override substitutes argv[0] only",
			args:     []string{"/bin/sh.real", "-c", "echo hi"},
			override: "/bin/sh",
			want:     []string{"/bin/sh", "-c", "echo hi"},
		},
		{
			name:     "empty override leaves args unchanged",
			args:     []string{"/bin/sh.real", "-c", "echo hi"},
			override: "",
			want:     []string{"/bin/sh.real", "-c", "echo hi"},
		},
		{
			name:     "whitespace-only override is treated as empty",
			args:     []string{"/bin/sh.real", "-c", "echo hi"},
			override: "   \t\n  ",
			want:     []string{"/bin/sh.real", "-c", "echo hi"},
		},
		{
			name:     "override with surrounding whitespace is trimmed",
			args:     []string{"/bin/sh.real", "-c", "echo hi"},
			override: "  /bin/sh  ",
			want:     []string{"/bin/sh", "-c", "echo hi"},
		},
		{
			name:     "single-arg invocation still works",
			args:     []string{"/bin/sh.real"},
			override: "/bin/sh",
			want:     []string{"/bin/sh"},
		},
		{
			name:     "args with embedded whitespace and metachars preserved",
			args:     []string{"/bin/sh.real", "-c", "echo 'hello world' | tr a-z A-Z"},
			override: "/bin/sh",
			want:     []string{"/bin/sh", "-c", "echo 'hello world' | tr a-z A-Z"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := applyArgv0Override(tc.args, tc.override)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("applyArgv0Override(%v, %q) = %v, want %v", tc.args, tc.override, got, tc.want)
			}
		})
	}
}

// TestApplyArgv0Override_DoesNotMutateInput guards against an aliasing
// bug where the override path could share backing storage with the
// caller's slice and corrupt it on later mutation.
func TestApplyArgv0Override_DoesNotMutateInput(t *testing.T) {
	in := []string{"/bin/sh.real", "-c", "echo hi"}
	orig := append([]string(nil), in...)
	out := applyArgv0Override(in, "/bin/sh")

	// Mutating the output must not affect the input.
	out[0] = "/bin/zsh"
	out[1] = "-l"

	if !reflect.DeepEqual(in, orig) {
		t.Errorf("applyArgv0Override mutated input: in=%v orig=%v", in, orig)
	}
}
