package config

import (
	"testing"
)

func TestWaitKillableFilterCompositionTriggersBug(t *testing.T) {
	tt := boolPtr(true)
	ff := boolPtr(false)

	// seccompComposition wraps a SandboxSeccompConfig into a SandboxConfig so the
	// existing socket-via-seccomp.unix_socket cases read unchanged.
	seccompComposition := func(s SandboxSeccompConfig) SandboxConfig {
		return SandboxConfig{Seccomp: s}
	}

	cases := []struct {
		name string
		cfg  SandboxConfig
		want bool
	}{
		{
			name: "all off",
			cfg:  SandboxConfig{},
			want: false,
		},
		{
			name: "only socket family (seccomp.unix_socket)",
			cfg: seccompComposition(SandboxSeccompConfig{
				UnixSocket: SandboxSeccompUnixConfig{Enabled: true},
			}),
			want: false,
		},
		{
			name: "only file_monitor",
			cfg: seccompComposition(SandboxSeccompConfig{
				FileMonitor: SandboxSeccompFileMonitorConfig{Enabled: tt},
			}),
			want: false,
		},
		{
			name: "socket + file_monitor explicit on",
			cfg: seccompComposition(SandboxSeccompConfig{
				UnixSocket:  SandboxSeccompUnixConfig{Enabled: true},
				FileMonitor: SandboxSeccompFileMonitorConfig{Enabled: tt},
			}),
			want: true,
		},
		{
			// Issue #369 Gap A regression: socket family comes ONLY from the
			// top-level sandbox.unix_sockets.enabled (the public surface
			// secure-sandbox emits), with seccomp.unix_socket.enabled left
			// false. Pre-fix this returned false → probe skipped.
			name: "top-level unix_sockets + file_monitor (seccomp.unix_socket off)",
			cfg: SandboxConfig{
				UnixSockets: SandboxUnixSocketsConfig{Enabled: tt},
				Seccomp: SandboxSeccompConfig{
					FileMonitor: SandboxSeccompFileMonitorConfig{Enabled: tt},
				},
			},
			want: true,
		},
		{
			name: "socket + file_monitor disabled but enforce_without_fuse on (intercept_metadata defaults true)",
			cfg: seccompComposition(SandboxSeccompConfig{
				UnixSocket: SandboxSeccompUnixConfig{Enabled: true},
				FileMonitor: SandboxSeccompFileMonitorConfig{
					Enabled:            ff,
					EnforceWithoutFUSE: tt,
				},
			}),
			want: true,
		},
		{
			name: "socket + file_monitor disabled, enforce_without_fuse on, intercept_metadata explicitly off",
			cfg: seccompComposition(SandboxSeccompConfig{
				UnixSocket: SandboxSeccompUnixConfig{Enabled: true},
				FileMonitor: SandboxSeccompFileMonitorConfig{
					Enabled:            ff,
					EnforceWithoutFUSE: tt,
					InterceptMetadata:  ff,
				},
			}),
			want: false,
		},
		{
			name: "socket + intercept_metadata explicit on, file_monitor explicit off",
			cfg: seccompComposition(SandboxSeccompConfig{
				UnixSocket: SandboxSeccompUnixConfig{Enabled: true},
				FileMonitor: SandboxSeccompFileMonitorConfig{
					Enabled:           ff,
					InterceptMetadata: tt,
				},
			}),
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

func TestUnixSocketNotifyEnabled(t *testing.T) {
	tt := boolPtr(true)
	ff := boolPtr(false)

	cases := []struct {
		name string
		cfg  SandboxConfig
		want bool
	}{
		{name: "both off", cfg: SandboxConfig{}, want: false},
		{
			name: "seccomp.unix_socket on",
			cfg:  SandboxConfig{Seccomp: SandboxSeccompConfig{UnixSocket: SandboxSeccompUnixConfig{Enabled: true}}},
			want: true,
		},
		{
			name: "top-level unix_sockets explicitly true",
			cfg:  SandboxConfig{UnixSockets: SandboxUnixSocketsConfig{Enabled: tt}},
			want: true,
		},
		{
			name: "top-level unix_sockets explicitly false, seccomp off",
			cfg:  SandboxConfig{UnixSockets: SandboxUnixSocketsConfig{Enabled: ff}},
			want: false,
		},
		{
			name: "top-level nil contributes nothing (matches wrap.go)",
			cfg:  SandboxConfig{UnixSockets: SandboxUnixSocketsConfig{Enabled: nil}},
			want: false,
		},
		{
			name: "either field true wins",
			cfg: SandboxConfig{
				UnixSockets: SandboxUnixSocketsConfig{Enabled: ff},
				Seccomp:     SandboxSeccompConfig{UnixSocket: SandboxSeccompUnixConfig{Enabled: true}},
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.UnixSocketNotifyEnabled(); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
