package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestLandlockNetworkDefaults_FillsConnectTrueBindFalse(t *testing.T) {
	yamlData := []byte(`
landlock:
  enabled: true
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	require.Nil(t, cfg.Landlock.Network.AllowConnectTCP, "omitted field must parse as nil")
	require.Nil(t, cfg.Landlock.Network.AllowBindTCP, "omitted field must parse as nil")

	applyDefaults(&cfg)

	require.NotNil(t, cfg.Landlock.Network.AllowConnectTCP, "default must fill AllowConnectTCP")
	require.True(t, *cfg.Landlock.Network.AllowConnectTCP, "default AllowConnectTCP must be true")
	require.NotNil(t, cfg.Landlock.Network.AllowBindTCP, "default must fill AllowBindTCP")
	require.False(t, *cfg.Landlock.Network.AllowBindTCP, "default AllowBindTCP must be false")
}

func TestLandlockNetworkDefaults_ExplicitValuesPreserved(t *testing.T) {
	yamlData := []byte(`
landlock:
  enabled: true
  network:
    allow_connect_tcp: false
    allow_bind_tcp: true
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	applyDefaults(&cfg)

	require.NotNil(t, cfg.Landlock.Network.AllowConnectTCP)
	require.False(t, *cfg.Landlock.Network.AllowConnectTCP,
		"explicit false for allow_connect_tcp must survive applyDefaults")
	require.NotNil(t, cfg.Landlock.Network.AllowBindTCP)
	require.True(t, *cfg.Landlock.Network.AllowBindTCP,
		"explicit true for allow_bind_tcp must survive applyDefaults")
}

func TestLandlockNetworkDefaults_LandlockDisabled_StillFilled(t *testing.T) {
	yamlData := []byte(`
landlock:
  enabled: false
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	applyDefaults(&cfg)

	require.NotNil(t, cfg.Landlock.Network.AllowConnectTCP,
		"defaults filled unconditionally for diagnostic-dump stability")
	require.NotNil(t, cfg.Landlock.Network.AllowBindTCP)
}

func TestLandlockBindPortsWarning_EmitsWhenSet(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	origLogger := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(origLogger)

	yamlData := []byte(`
landlock:
  enabled: true
  network:
    bind_ports: [8080, 9090]
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	applyDefaults(&cfg)

	require.Contains(t, buf.String(), "landlock.network.bind_ports",
		"setting bind_ports must emit a warning about non-enforcement")
}

func TestLandlockBindPortsWarning_SilentWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	origLogger := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(origLogger)

	yamlData := []byte(`
landlock:
  enabled: true
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	applyDefaults(&cfg)

	require.False(t, strings.Contains(buf.String(), "bind_ports"),
		"no warning should fire when bind_ports is empty")
}

func TestLandlockValidation_ConnectFalseWithProxyEnabled_Errors(t *testing.T) {
	f := false
	cfg := Config{}
	cfg.Landlock.Enabled = true
	cfg.Landlock.Network.AllowConnectTCP = &f
	cfg.Sandbox.Network.Enabled = true
	// Fill required defaults to avoid unrelated validation errors.
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Network.InterceptMode = "all"

	err := validateConfig(&cfg)
	require.Error(t, err, "must reject connect_tcp=false while proxy enabled")
	require.Contains(t, err.Error(), "landlock.network.allow_connect_tcp")
	require.Contains(t, err.Error(), "sandbox.network.enabled")
}

func TestLandlockValidation_ConnectFalseWithProxyDisabled_OK(t *testing.T) {
	f := false
	cfg := Config{}
	cfg.Landlock.Enabled = true
	cfg.Landlock.Network.AllowConnectTCP = &f
	cfg.Sandbox.Network.Enabled = false
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Network.InterceptMode = "all"

	err := validateConfig(&cfg)
	require.NoError(t, err, "connect_tcp=false is fine when proxy is off")
}

func TestLandlockValidation_BindFalseAlwaysOK(t *testing.T) {
	tr := true
	f := false
	cfg := Config{}
	cfg.Landlock.Enabled = true
	cfg.Landlock.Network.AllowConnectTCP = &tr
	cfg.Landlock.Network.AllowBindTCP = &f
	cfg.Sandbox.Network.Enabled = true
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Network.InterceptMode = "all"

	err := validateConfig(&cfg)
	require.NoError(t, err, "allow_bind_tcp=false with proxy on is the intended secure case")
}

func TestLandlockValidation_LandlockDisabled_NoLockoutCheck(t *testing.T) {
	f := false
	cfg := Config{}
	cfg.Landlock.Enabled = false
	cfg.Landlock.Network.AllowConnectTCP = &f
	cfg.Sandbox.Network.Enabled = true
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Network.InterceptMode = "all"

	err := validateConfig(&cfg)
	require.NoError(t, err, "landlock disabled → no lockout check regardless of values")
}
