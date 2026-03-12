//go:build linux

// Package ptrace implements a ptrace-based syscall tracer backend for agentsh.
// It provides syscall-level interception for environments where seccomp user-notify
// and eBPF are unavailable (e.g., AWS Fargate with SYS_PTRACE).
//
// The tracer intercepts four categories of syscalls:
//   - Exec: execve, execveat — command allow/deny via ExecHandler
//   - File: openat, openat2, unlinkat, renameat2, mkdirat, linkat, symlinkat,
//     fchmodat, fchmodat2, fchownat (plus legacy amd64 equivalents) — file
//     allow/deny via FileHandler with full path resolution and symlink handling
//   - Network: connect, bind — network allow/deny via NetworkHandler with
//     sockaddr parsing for AF_INET, AF_INET6, AF_UNIX, and AF_UNSPEC
//   - Signal: kill, tkill, tgkill, rt_sigqueueinfo, rt_tgsigqueueinfo —
//     signal allow/deny/redirect via SignalHandler
//
// Production hardening features:
//   - max_hold_ms timeout enforcement: parked tracees (awaiting async policy
//     approval) are automatically denied with EACCES after the configured
//     timeout. Swept every event loop iteration.
//   - Metrics interface: SetTraceeCount, IncAttachFailure, IncTimeout —
//     decoupled from observability via PtraceMetricsCollector adapter.
//     Prometheus metrics: agentsh_ptrace_tracees_active (gauge),
//     agentsh_ptrace_attach_failures_total{reason} (counter),
//     agentsh_ptrace_timeouts_total (counter).
//   - Graceful degradation: tracees that exit while parked are cleaned up,
//     resume requests for dead tracees are safely skipped, ESRCH errors in
//     allow/deny trigger cleanup instead of SIGKILL fallback.
//
// This package is Linux-only and requires the SYS_PTRACE capability.
package ptrace
