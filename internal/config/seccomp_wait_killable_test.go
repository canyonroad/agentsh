package config

import (
	"testing"
)

func TestWaitKillableFilterCompositionTriggersBug(t *testing.T) {
	tt := boolPtr(true)
	ff := boolPtr(false)

	cases := []struct {
		name string
		cfg  SandboxSeccompConfig
		want bool
	}{
		{
			name: "all off",
			cfg:  SandboxSeccompConfig{},
			want: false,
		},
		{
			name: "only socket family",
			cfg: SandboxSeccompConfig{
				UnixSocket: SandboxSeccompUnixConfig{Enabled: true},
			},
			want: false,
		},
		{
			name: "only file_monitor",
			cfg: SandboxSeccompConfig{
				FileMonitor: SandboxSeccompFileMonitorConfig{Enabled: tt},
			},
			want: false,
		},
		{
			name: "socket + file_monitor explicit on",
			cfg: SandboxSeccompConfig{
				UnixSocket:  SandboxSeccompUnixConfig{Enabled: true},
				FileMonitor: SandboxSeccompFileMonitorConfig{Enabled: tt},
			},
			want: true,
		},
		{
			name: "socket + file_monitor disabled but enforce_without_fuse on (intercept_metadata defaults true)",
			cfg: SandboxSeccompConfig{
				UnixSocket: SandboxSeccompUnixConfig{Enabled: true},
				FileMonitor: SandboxSeccompFileMonitorConfig{
					Enabled:            ff,
					EnforceWithoutFUSE: tt,
				},
			},
			want: true,
		},
		{
			name: "socket + file_monitor disabled, enforce_without_fuse on, intercept_metadata explicitly off",
			cfg: SandboxSeccompConfig{
				UnixSocket: SandboxSeccompUnixConfig{Enabled: true},
				FileMonitor: SandboxSeccompFileMonitorConfig{
					Enabled:            ff,
					EnforceWithoutFUSE: tt,
					InterceptMetadata:  ff,
				},
			},
			want: false,
		},
		{
			name: "socket + intercept_metadata explicit on, file_monitor explicit off",
			cfg: SandboxSeccompConfig{
				UnixSocket: SandboxSeccompUnixConfig{Enabled: true},
				FileMonitor: SandboxSeccompFileMonitorConfig{
					Enabled:           ff,
					InterceptMetadata: tt,
				},
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := WaitKillableFilterCompositionTriggersBug(tc.cfg)
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
