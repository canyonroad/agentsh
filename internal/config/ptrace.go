// internal/config/ptrace.go
package config

import "fmt"

// SandboxPtraceConfig configures the ptrace-based syscall tracer backend.
type SandboxPtraceConfig struct {
	Enabled         bool                    `yaml:"enabled"`
	AttachMode      string                  `yaml:"attach_mode"`
	TargetPID       int                     `yaml:"target_pid"`
	TargetPIDFile   string                  `yaml:"target_pid_file"`
	Trace           PtraceTraceConfig       `yaml:"trace"`
	Performance     PtracePerformanceConfig `yaml:"performance"`
	MaskTracerPid   string                  `yaml:"mask_tracer_pid"`
	OnAttachFailure string                  `yaml:"on_attach_failure"`
}

type PtraceTraceConfig struct {
	Execve  bool `yaml:"execve"`
	File    bool `yaml:"file"`
	Network bool `yaml:"network"`
	Signal  bool `yaml:"signal"`
}

type PtracePerformanceConfig struct {
	SeccompPrefilter   bool `yaml:"seccomp_prefilter"`
	MaxTracees         int  `yaml:"max_tracees"`
	MaxHoldMs          int  `yaml:"max_hold_ms"`
	StaticAllowFile    bool `yaml:"static_allow_file"`
	StaticAllowNetwork bool `yaml:"static_allow_network"`
	ArgLevelFilter     bool `yaml:"arg_level_filter"`
}

func DefaultPtraceConfig() SandboxPtraceConfig {
	return SandboxPtraceConfig{
		Enabled:    false,
		AttachMode: "children",
		Trace: PtraceTraceConfig{
			Execve:  true,
			File:    true,
			Network: true,
			Signal:  true,
		},
		Performance: PtracePerformanceConfig{
			SeccompPrefilter: true,
			MaxTracees:       500,
			MaxHoldMs:        5000,
			ArgLevelFilter:   true,
		},
		MaskTracerPid:   "off",
		OnAttachFailure: "fail_open",
	}
}

// Validate checks that the ptrace configuration is internally consistent.
func (c *SandboxPtraceConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	switch c.AttachMode {
	case "children", "pid":
	default:
		return fmt.Errorf("sandbox.ptrace.attach_mode: invalid value %q (must be \"children\" or \"pid\")", c.AttachMode)
	}

	if c.AttachMode == "pid" && c.TargetPID <= 0 && c.TargetPIDFile == "" {
		return fmt.Errorf("sandbox.ptrace: attach_mode \"pid\" requires target_pid or target_pid_file")
	}

	switch c.OnAttachFailure {
	case "fail_open", "fail_closed":
	default:
		return fmt.Errorf("sandbox.ptrace.on_attach_failure: invalid value %q", c.OnAttachFailure)
	}

	if c.MaskTracerPid != "off" {
		return fmt.Errorf("sandbox.ptrace.mask_tracer_pid: %q not supported in this version (use \"off\")", c.MaskTracerPid)
	}

	if c.Performance.MaxHoldMs <= 0 {
		return fmt.Errorf("sandbox.ptrace.performance.max_hold_ms must be > 0")
	}

	return nil
}
