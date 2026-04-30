package api

import (
	"log/slog"
	"os"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/internal/session"
)

// seccompWrapperConfig is passed to the agentsh-unixwrap wrapper via
// AGENTSH_SECCOMP_CONFIG environment variable to configure seccomp-bpf filtering.
type seccompWrapperConfig struct {
	UnixSocketEnabled   bool                      `json:"unix_socket_enabled"`
	SignalFilterEnabled bool                      `json:"signal_filter_enabled"`
	ExecveEnabled       bool                      `json:"execve_enabled"`
	FileMonitorEnabled  bool                      `json:"file_monitor_enabled"`
	BlockedSyscalls     []string                  `json:"blocked_syscalls"`
	BlockedFamilies     []seccompkg.BlockedFamily `json:"blocked_families,omitempty"`
	OnBlock             string                    `json:"on_block,omitempty"`

	// File monitor sub-options
	InterceptMetadata bool `json:"intercept_metadata,omitempty"`
	BlockIOUring      bool `json:"block_io_uring,omitempty"`

	// Landlock filesystem restrictions
	LandlockEnabled bool     `json:"landlock_enabled,omitempty"`
	LandlockABI     int      `json:"landlock_abi,omitempty"`
	Workspace       string   `json:"workspace,omitempty"`
	AllowExecute    []string `json:"allow_execute,omitempty"`
	AllowRead       []string `json:"allow_read,omitempty"`
	AllowWrite      []string `json:"allow_write,omitempty"`
	DenyPaths       []string `json:"deny_paths,omitempty"`
	AllowNetwork    bool     `json:"allow_network,omitempty"`
	AllowBind       bool     `json:"allow_bind,omitempty"`

	// Server PID for PR_SET_PTRACER (Yama ptrace_scope=1 workaround)
	ServerPID int `json:"server_pid,omitempty"`
}

type seccompWrapperParams struct {
	UnixSocketEnabled   bool
	SignalFilterEnabled bool
	ExecveEnabled       bool
}

func (a *App) buildSeccompWrapperConfig(s *session.Session, p seccompWrapperParams) seccompWrapperConfig {
	seccompCfg := seccompWrapperConfig{
		UnixSocketEnabled:   p.UnixSocketEnabled,
		SignalFilterEnabled: p.SignalFilterEnabled,
		ExecveEnabled:       p.ExecveEnabled,
		FileMonitorEnabled:  config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.Enabled, false),
		BlockedSyscalls:     a.cfg.Sandbox.Seccomp.Syscalls.Block,
		OnBlock:             a.cfg.Sandbox.Seccomp.Syscalls.OnBlock,
		ServerPID:           os.Getpid(),
	}

	// Resolve and forward blocked socket families.
	if len(a.cfg.Sandbox.Seccomp.BlockedSocketFamilies) > 0 {
		families, err := config.ResolveBlockedFamilies(a.cfg.Sandbox.Seccomp.BlockedSocketFamilies)
		if err != nil {
			slog.Warn("seccomp: failed to resolve blocked_socket_families; families will not be blocked",
				"error", err)
		} else {
			seccompCfg.BlockedFamilies = families
		}
	}

	fmDefault := config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE, false)
	seccompCfg.InterceptMetadata = config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata, fmDefault)
	seccompCfg.BlockIOUring = config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.BlockIOUring, fmDefault)

	if a.cfg.Landlock.Enabled {
		llResult := capabilities.DetectLandlock()
		if llResult.Available {
			workspace := s.WorkspaceMountPath()
			seccompCfg.LandlockEnabled = true
			seccompCfg.LandlockABI = llResult.ABI
			seccompCfg.Workspace = workspace

			seccompCfg.AllowExecute, seccompCfg.AllowRead, seccompCfg.AllowWrite = a.deriveLandlockAllowPaths(s)
			seccompCfg.AllowExecute = append(seccompCfg.AllowExecute, a.cfg.Landlock.AllowExecute...)
			seccompCfg.AllowRead = append(seccompCfg.AllowRead, a.cfg.Landlock.AllowRead...)
			seccompCfg.AllowWrite = append(seccompCfg.AllowWrite, a.cfg.Landlock.AllowWrite...)
			seccompCfg.DenyPaths = append(seccompCfg.DenyPaths, a.cfg.Landlock.DenyPaths...)

			if a.cfg.Landlock.Network.AllowConnectTCP != nil {
				seccompCfg.AllowNetwork = *a.cfg.Landlock.Network.AllowConnectTCP
			}
			if a.cfg.Landlock.Network.AllowBindTCP != nil {
				seccompCfg.AllowBind = *a.cfg.Landlock.Network.AllowBindTCP
			}
		}
	}

	return seccompCfg
}
