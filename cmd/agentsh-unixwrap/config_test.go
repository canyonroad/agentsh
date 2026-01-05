//go:build linux && cgo

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	t.Run("default config when env not set", func(t *testing.T) {
		// Don't set env var - should get defaults
		cfg, err := loadConfig()
		require.NoError(t, err)
		require.True(t, cfg.UnixSocketEnabled)
		require.Nil(t, cfg.BlockedSyscalls)
	})

	t.Run("parses config from env", func(t *testing.T) {
		t.Setenv("AGENTSH_SECCOMP_CONFIG", `{"unix_socket_enabled":false,"blocked_syscalls":["ptrace","mount"]}`)
		cfg, err := loadConfig()
		require.NoError(t, err)
		require.False(t, cfg.UnixSocketEnabled)
		require.Equal(t, []string{"ptrace", "mount"}, cfg.BlockedSyscalls)
	})

	t.Run("error on invalid json", func(t *testing.T) {
		t.Setenv("AGENTSH_SECCOMP_CONFIG", `{invalid json}`)
		_, err := loadConfig()
		require.Error(t, err)
	})
}

func TestParseConfigJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *WrapperConfig
		wantErr bool
	}{
		{
			name:  "valid config",
			input: `{"unix_socket_enabled":true,"blocked_syscalls":["ptrace","mount"]}`,
			want:  &WrapperConfig{UnixSocketEnabled: true, BlockedSyscalls: []string{"ptrace", "mount"}},
		},
		{
			name:  "empty config",
			input: `{}`,
			want:  &WrapperConfig{},
		},
		{
			name:    "invalid json",
			input:   `{invalid}`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseConfigJSON(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, cfg)
		})
	}
}
