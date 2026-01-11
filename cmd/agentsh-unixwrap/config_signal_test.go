//go:build linux && cgo

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigWithSignalFilter(t *testing.T) {
	t.Run("parses signal_filter_enabled true", func(t *testing.T) {
		t.Setenv("AGENTSH_SECCOMP_CONFIG", `{"unix_socket_enabled":true,"signal_filter_enabled":true}`)
		cfg, err := loadConfig()
		require.NoError(t, err)
		require.True(t, cfg.SignalFilterEnabled)
	})

	t.Run("parses signal_filter_enabled false", func(t *testing.T) {
		t.Setenv("AGENTSH_SECCOMP_CONFIG", `{"unix_socket_enabled":true,"signal_filter_enabled":false}`)
		cfg, err := loadConfig()
		require.NoError(t, err)
		require.False(t, cfg.SignalFilterEnabled)
	})

	t.Run("defaults to false when not specified", func(t *testing.T) {
		t.Setenv("AGENTSH_SECCOMP_CONFIG", `{"unix_socket_enabled":true}`)
		cfg, err := loadConfig()
		require.NoError(t, err)
		require.False(t, cfg.SignalFilterEnabled)
	})
}
