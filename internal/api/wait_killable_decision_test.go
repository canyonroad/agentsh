package api

import (
	"context"
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestDecideWaitKillable(t *testing.T) {
	tt := true
	ff := false

	probeOK := func(_ context.Context) (bool, error) { return true, nil }
	probeFail := func(_ context.Context) (bool, error) { return false, nil }
	probeErr := func(_ context.Context) (bool, error) { return false, errors.New("probe boom") }

	// Socket family via seccomp.unix_socket + file_monitor → bug-prone composition.
	compositionRisky := config.SandboxConfig{
		Seccomp: config.SandboxSeccompConfig{
			UnixSocket:  config.SandboxSeccompUnixConfig{Enabled: true},
			FileMonitor: config.SandboxSeccompFileMonitorConfig{Enabled: &tt},
		},
	}
	// Socket family via the TOP-LEVEL unix_sockets flag only (seccomp.unix_socket
	// off) + file_monitor → still bug-prone. Issue #369 Gap A: pre-fix this was
	// misclassified as safe and skipped the probe.
	compositionRiskyTopLevel := config.SandboxConfig{
		UnixSockets: config.SandboxUnixSocketsConfig{Enabled: &tt},
		Seccomp: config.SandboxSeccompConfig{
			FileMonitor: config.SandboxSeccompFileMonitorConfig{Enabled: &tt},
		},
	}
	compositionSafe := config.SandboxConfig{
		Seccomp: config.SandboxSeccompConfig{
			UnixSocket: config.SandboxSeccompUnixConfig{Enabled: true},
		},
	}

	cases := []struct {
		name           string
		cfg            config.SandboxConfig
		kernelSupports bool
		probe          func(context.Context) (bool, error)
		wantDecision   bool
		wantSource     string
	}{
		{name: "config &true wins", cfg: configWithWait(compositionRisky, &tt), kernelSupports: true, probe: probeFail, wantDecision: true, wantSource: "config"},
		{name: "config &false wins", cfg: configWithWait(compositionRisky, &ff), kernelSupports: true, probe: probeOK, wantDecision: false, wantSource: "config"},
		{name: "config beats kernel<6", cfg: configWithWait(compositionRisky, &tt), kernelSupports: false, probe: probeFail, wantDecision: true, wantSource: "config"},
		{name: "kernel <6 forces off", cfg: compositionRisky, kernelSupports: false, probe: probeOK, wantDecision: false, wantSource: "kernel_unsupported"},
		{name: "safe composition skips probe", cfg: compositionSafe, kernelSupports: true, probe: probeFail, wantDecision: true, wantSource: "filter_composition_safe"},
		{name: "probe pass", cfg: compositionRisky, kernelSupports: true, probe: probeOK, wantDecision: true, wantSource: "behavioral_probe"},
		{name: "probe fail", cfg: compositionRisky, kernelSupports: true, probe: probeFail, wantDecision: false, wantSource: "behavioral_probe"},
		{name: "probe error fails safe", cfg: compositionRisky, kernelSupports: true, probe: probeErr, wantDecision: false, wantSource: "behavioral_probe_error"},
		// #369 Gap A: top-level unix_sockets + file_monitor must reach the probe,
		// not short-circuit to filter_composition_safe.
		{name: "top-level unix_sockets reaches probe", cfg: compositionRiskyTopLevel, kernelSupports: true, probe: probeFail, wantDecision: false, wantSource: "behavioral_probe"},
		{name: "top-level unix_sockets probe pass", cfg: compositionRiskyTopLevel, kernelSupports: true, probe: probeOK, wantDecision: true, wantSource: "behavioral_probe"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotDecision, gotSource := decideWaitKillable(context.Background(), waitKillableDeps{
				cfg:            tc.cfg,
				kernelSupports: func() bool { return tc.kernelSupports },
				probe:          tc.probe,
			})
			if gotDecision != tc.wantDecision {
				t.Errorf("decision: got %v want %v", gotDecision, tc.wantDecision)
			}
			if gotSource != tc.wantSource {
				t.Errorf("source: got %q want %q", gotSource, tc.wantSource)
			}
		})
	}
}

func configWithWait(cfg config.SandboxConfig, v *bool) config.SandboxConfig {
	cfg.Seccomp.WaitKillable = v
	return cfg
}
