// internal/config/ptrace_test.go
package config

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultPtraceConfig(t *testing.T) {
	cfg := DefaultPtraceConfig()

	if cfg.Enabled {
		t.Error("ptrace should be disabled by default")
	}
	if cfg.AttachMode != "children" {
		t.Errorf("attach_mode: got %q, want %q", cfg.AttachMode, "children")
	}
	if !cfg.Trace.Execve || !cfg.Trace.File || !cfg.Trace.Network || !cfg.Trace.Signal {
		t.Error("all trace classes should be enabled by default")
	}
	if !cfg.Performance.SeccompPrefilter {
		t.Error("seccomp_prefilter should be enabled by default")
	}
	if cfg.Performance.MaxTracees != 500 {
		t.Errorf("max_tracees: got %d, want 500", cfg.Performance.MaxTracees)
	}
	if cfg.Performance.MaxHoldMs != 5000 {
		t.Errorf("max_hold_ms: got %d, want 5000", cfg.Performance.MaxHoldMs)
	}
	if cfg.Performance.ArgLevelFilter {
		t.Error("arg_level_filter should be disabled by default (opt-in)")
	}
	if cfg.MaskTracerPid != "off" {
		t.Errorf("mask_tracer_pid: got %q, want %q", cfg.MaskTracerPid, "off")
	}
	if cfg.OnAttachFailure != "fail_open" {
		t.Errorf("on_attach_failure: got %q, want %q", cfg.OnAttachFailure, "fail_open")
	}
}

func TestPtraceArgLevelFilterDefaultOnLoad(t *testing.T) {
	// Verify that ArgLevelFilter defaults to false (opt-in) when ptrace is
	// enabled but arg_level_filter is omitted from YAML.
	yamlContent := `
sandbox:
  ptrace:
    enabled: true
  unix_sockets:
    enabled: false
`
	dir := t.TempDir()
	cfgPath := dir + "/config.yaml"
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sandbox.Ptrace.Performance.ArgLevelFilter {
		t.Error("ArgLevelFilter should default to false when omitted from YAML")
	}
	if !cfg.Sandbox.Ptrace.Performance.SeccompPrefilter {
		t.Error("SeccompPrefilter should default to true when omitted from YAML")
	}
}

func TestPtraceArgLevelFilterExplicitTrue(t *testing.T) {
	// Verify that explicitly setting arg_level_filter: true in YAML works.
	yamlContent := `
sandbox:
  ptrace:
    enabled: true
    performance:
      arg_level_filter: true
  unix_sockets:
    enabled: false
`
	dir := t.TempDir()
	cfgPath := dir + "/config.yaml"
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Sandbox.Ptrace.Performance.ArgLevelFilter {
		t.Error("ArgLevelFilter should be true when explicitly set in YAML")
	}
	// SeccompPrefilter should still be true (not mentioned in YAML).
	if !cfg.Sandbox.Ptrace.Performance.SeccompPrefilter {
		t.Error("SeccompPrefilter should remain true when not mentioned in YAML")
	}
}

func TestPtraceConfig_YAMLRoundTrip(t *testing.T) {
	orig := DefaultPtraceConfig()
	orig.Enabled = true
	orig.TargetPID = 42

	data, err := yaml.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded SandboxPtraceConfig
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.TargetPID != 42 {
		t.Errorf("target_pid: got %d, want 42", decoded.TargetPID)
	}
	if !decoded.Enabled {
		t.Error("enabled not preserved")
	}
}

func TestSandboxConfig_Validate_MutualExclusion(t *testing.T) {
	boolPtr := func(v bool) *bool { return &v }

	tests := []struct {
		name    string
		cfg     SandboxConfig
		wantErr string
	}{
		{
			name: "ptrace alone is valid",
			cfg: SandboxConfig{
				Ptrace: func() SandboxPtraceConfig {
					c := DefaultPtraceConfig()
					c.Enabled = true
					return c
				}(),
			},
		},
		{
			name: "ptrace + seccomp.execve rejected",
			cfg: SandboxConfig{
				Ptrace: func() SandboxPtraceConfig {
					c := DefaultPtraceConfig()
					c.Enabled = true
					return c
				}(),
				Seccomp: SandboxSeccompConfig{
					Execve: ExecveConfig{Enabled: true},
				},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "ptrace + unix_sockets rejected",
			cfg: SandboxConfig{
				Ptrace: func() SandboxPtraceConfig {
					c := DefaultPtraceConfig()
					c.Enabled = true
					return c
				}(),
				UnixSockets: SandboxUnixSocketsConfig{Enabled: boolPtr(true)},
			},
			wantErr: "execve-only tracing",
		},
		{
			name: "ptrace execve-only + unix_sockets is valid (hybrid mode)",
			cfg: SandboxConfig{
				Ptrace: SandboxPtraceConfig{
					Enabled:    true,
					AttachMode: "children",
					Trace: PtraceTraceConfig{
						Execve:  true,
						File:    false,
						Network: false,
						Signal:  false,
					},
					Performance:     PtracePerformanceConfig{SeccompPrefilter: true, MaxTracees: 500, MaxHoldMs: 5000},
					MaskTracerPid:   "off",
					OnAttachFailure: "fail_open",
				},
				UnixSockets: SandboxUnixSocketsConfig{Enabled: boolPtr(true)},
			},
		},
		{
			name: "ptrace with file tracing + unix_sockets rejected",
			cfg: SandboxConfig{
				Ptrace: SandboxPtraceConfig{
					Enabled:    true,
					AttachMode: "children",
					Trace: PtraceTraceConfig{
						Execve:  true,
						File:    true,
						Network: false,
						Signal:  false,
					},
					Performance:     PtracePerformanceConfig{SeccompPrefilter: true, MaxTracees: 500, MaxHoldMs: 5000},
					MaskTracerPid:   "off",
					OnAttachFailure: "fail_open",
				},
				UnixSockets: SandboxUnixSocketsConfig{Enabled: boolPtr(true)},
			},
			wantErr: "execve-only tracing",
		},
		{
			name: "ptrace no-tracing + unix_sockets rejected",
			cfg: SandboxConfig{
				Ptrace: SandboxPtraceConfig{
					Enabled:    true,
					AttachMode: "children",
					Trace: PtraceTraceConfig{
						Execve:  false,
						File:    false,
						Network: false,
						Signal:  false,
					},
					Performance:     PtracePerformanceConfig{SeccompPrefilter: true, MaxTracees: 500, MaxHoldMs: 5000},
					MaskTracerPid:   "off",
					OnAttachFailure: "fail_open",
				},
				UnixSockets: SandboxUnixSocketsConfig{Enabled: boolPtr(true)},
			},
			wantErr: "execve-only tracing",
		},
		{
			name: "ptrace + unix_sockets nil is valid",
			cfg: SandboxConfig{
				Ptrace: func() SandboxPtraceConfig {
					c := DefaultPtraceConfig()
					c.Enabled = true
					return c
				}(),
				UnixSockets: SandboxUnixSocketsConfig{Enabled: nil},
			},
		},
		{
			name: "ptrace + unix_sockets false is valid",
			cfg: SandboxConfig{
				Ptrace: func() SandboxPtraceConfig {
					c := DefaultPtraceConfig()
					c.Enabled = true
					return c
				}(),
				UnixSockets: SandboxUnixSocketsConfig{Enabled: boolPtr(false)},
			},
		},
		{
			name: "ptrace disabled + seccomp.execve is valid",
			cfg: SandboxConfig{
				Seccomp: SandboxSeccompConfig{
					Execve: ExecveConfig{Enabled: true},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestPtraceConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*SandboxPtraceConfig)
		wantErr bool
	}{
		{"defaults are valid", func(c *SandboxPtraceConfig) {}, false},
		{"pid mode with target_pid", func(c *SandboxPtraceConfig) {
			c.AttachMode = "pid"
			c.TargetPID = 123
		}, false},
		{"pid mode with target_pid_file", func(c *SandboxPtraceConfig) {
			c.AttachMode = "pid"
			c.TargetPIDFile = "/shared/workload.pid"
		}, false},
		{"pid mode without target", func(c *SandboxPtraceConfig) {
			c.AttachMode = "pid"
		}, true},
		{"invalid attach_mode", func(c *SandboxPtraceConfig) {
			c.AttachMode = "sidecar"
		}, true},
		{"invalid on_attach_failure", func(c *SandboxPtraceConfig) {
			c.OnAttachFailure = "panic"
		}, true},
		{"invalid mask_tracer_pid", func(c *SandboxPtraceConfig) {
			c.MaskTracerPid = "ptrace"
		}, true},
		{"max_hold_ms zero", func(c *SandboxPtraceConfig) {
			c.Performance.MaxHoldMs = 0
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultPtraceConfig()
			cfg.Enabled = true
			tt.modify(&cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestSandboxPtraceConfig_IsExecveOnly(t *testing.T) {
	tests := []struct {
		name string
		cfg  SandboxPtraceConfig
		want bool
	}{
		{
			name: "disabled is not execve-only",
			cfg:  DefaultPtraceConfig(),
			want: false,
		},
		{
			name: "all tracing enabled is not execve-only",
			cfg: func() SandboxPtraceConfig {
				c := DefaultPtraceConfig()
				c.Enabled = true
				return c
			}(),
			want: false,
		},
		{
			name: "execve-only with file/network/signal disabled",
			cfg: SandboxPtraceConfig{
				Enabled: true,
				Trace: PtraceTraceConfig{
					Execve:  true,
					File:    false,
					Network: false,
					Signal:  false,
				},
			},
			want: true,
		},
		{
			name: "execve true but file also true",
			cfg: SandboxPtraceConfig{
				Enabled: true,
				Trace: PtraceTraceConfig{
					Execve:  true,
					File:    true,
					Network: false,
					Signal:  false,
				},
			},
			want: false,
		},
		{
			name: "enabled but execve false",
			cfg: SandboxPtraceConfig{
				Enabled: true,
				Trace: PtraceTraceConfig{
					Execve:  false,
					File:    false,
					Network: false,
					Signal:  false,
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsExecveOnly(); got != tt.want {
				t.Errorf("IsExecveOnly() = %v, want %v", got, tt.want)
			}
		})
	}
}
