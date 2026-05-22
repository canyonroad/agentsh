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
	SocketRules         []seccompkg.SocketRule    `json:"socket_rules,omitempty"`
	OnBlock             string                    `json:"on_block,omitempty"`

	// File monitor sub-options
	InterceptMetadata bool `json:"intercept_metadata,omitempty"`
	WriteOnlyOpens    bool `json:"write_only_opens,omitempty"`
	BlockIOUring      bool `json:"block_io_uring,omitempty"`

	// WaitKillable forwards the server's decision (boot-time probe +
	// optional config override) to the wrapper, which uses it in place
	// of its own ProbeWaitKillable() fallback. nil means the server made
	// no decision and the wrapper should probe locally. Issue #369.
	WaitKillable *bool `json:"wait_killable,omitempty"`

	// WaitKillableSource records why the WaitKillable decision was made
	// ("config", "kernel_unsupported", "filter_composition_safe",
	// "behavioral_probe", "behavioral_probe_error"). Forwarded so the
	// wrapper's per-exec "seccomp: filter loaded" log line can record the
	// source — one grep tells an operator why this exec saw a given flag
	// value. Issue #369.
	WaitKillableSource string `json:"wait_killable_source,omitempty"`

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
	blockedSyscalls, onBlock, err := config.EffectiveSyscallBlock(a.cfg.Sandbox.Seccomp)
	if err != nil {
		slog.Warn("seccomp: failed to resolve effective syscall block list; syscall rules will not be blocked", "error", err)
	}
	seccompCfg := seccompWrapperConfig{
		UnixSocketEnabled:   p.UnixSocketEnabled,
		SignalFilterEnabled: p.SignalFilterEnabled,
		ExecveEnabled:       p.ExecveEnabled,
		FileMonitorEnabled:  config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.Enabled, false),
		BlockedSyscalls:     blockedSyscalls,
		OnBlock:             onBlock,
		ServerPID:           os.Getpid(),
	}

	// Resolve and forward blocked socket families.
	families, err := config.ResolveEffectiveBlockedFamilies(a.cfg.Sandbox.Seccomp)
	if err != nil {
		slog.Warn("seccomp: failed to resolve blocked_socket_families; families will not be blocked", "error", err)
	} else {
		seccompCfg.BlockedFamilies = families
	}

	if rules, err := config.ResolveSocketRules(a.cfg.Sandbox.Seccomp); err != nil {
		slog.Warn("seccomp: failed to resolve socket_rules; socket rules will not be blocked", "error", err)
	} else {
		seccompCfg.SocketRules = rules
	}

	fmDefault := config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE, false)
	seccompCfg.InterceptMetadata = config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata, fmDefault)
	if seccompCfg.FileMonitorEnabled {
		seccompCfg.WriteOnlyOpens = config.FileMonitorBoolWithDefault(
			a.cfg.Sandbox.Seccomp.FileMonitor.WriteOnlyOpens,
			!seccompCfg.InterceptMetadata,
		)
	}
	seccompCfg.BlockIOUring = config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.BlockIOUring, fmDefault)

	// Pass the boot-time decision to every wrapper. The pointer is
	// per-exec; the bool storage is the server-process App field. Issue #369.
	seccompCfg.WaitKillable = &a.waitKillableDecision
	seccompCfg.WaitKillableSource = a.waitKillableSource

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
