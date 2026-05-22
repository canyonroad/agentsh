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

	compositionRisky := config.SandboxSeccompConfig{
		UnixSocket:  config.SandboxSeccompUnixConfig{Enabled: true},
		FileMonitor: config.SandboxSeccompFileMonitorConfig{Enabled: &tt},
	}
	compositionSafe := config.SandboxSeccompConfig{
		UnixSocket: config.SandboxSeccompUnixConfig{Enabled: true},
	}

	cases := []struct {
		name           string
		cfg            config.SandboxSeccompConfig
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

func configWithWait(cfg config.SandboxSeccompConfig, v *bool) config.SandboxSeccompConfig {
	cfg.WaitKillable = v
	return cfg
}
