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
		require.False(t, cfg.ExecveEnabled)
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

func TestLoadConfig_WithExecve(t *testing.T) {
	t.Setenv("AGENTSH_SECCOMP_CONFIG", `{"unix_socket_enabled":true,"execve_enabled":true}`)

	cfg, err := loadConfig()
	require.NoError(t, err)
	require.True(t, cfg.UnixSocketEnabled)
	require.True(t, cfg.ExecveEnabled)
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
			input: `{"unix_socket_enabled":true,"blocked_syscalls":["ptrace","mount"],"write_only_opens":true}`,
			want:  &WrapperConfig{UnixSocketEnabled: true, BlockedSyscalls: []string{"ptrace", "mount"}, WriteOnlyOpens: true},
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

func TestParseConfigJSON_OnBlock(t *testing.T) {
	for _, v := range []string{"errno", "kill", "log", "log_and_kill"} {
		t.Run(v, func(t *testing.T) {
			cfg, err := parseConfigJSON(`{"on_block":"` + v + `"}`)
			require.NoError(t, err)
			require.Equal(t, v, cfg.OnBlock)
		})
	}
}

func TestWrapperConfig_WaitKillable_JSON(t *testing.T) {
	cases := []struct {
		name string
		json string
		want *bool
	}{
		{name: "absent", json: `{"unix_socket_enabled":true}`, want: nil},
		{name: "true", json: `{"unix_socket_enabled":true,"wait_killable":true}`, want: boolPtr(true)},
		{name: "false", json: `{"unix_socket_enabled":true,"wait_killable":false}`, want: boolPtr(false)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AGENTSH_SECCOMP_CONFIG", tc.json)
			cfg, err := loadConfig()
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			switch {
			case tc.want == nil && cfg.WaitKillable != nil:
				t.Fatalf("want nil, got &%v", *cfg.WaitKillable)
			case tc.want != nil && cfg.WaitKillable == nil:
				t.Fatalf("want &%v, got nil", *tc.want)
			case tc.want != nil && *cfg.WaitKillable != *tc.want:
				t.Fatalf("want %v got %v", *tc.want, *cfg.WaitKillable)
			}
		})
	}
}

func boolPtr(v bool) *bool { return &v }
