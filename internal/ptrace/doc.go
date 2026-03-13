//go:build linux

// Package ptrace implements a ptrace-based syscall tracer backend for agentsh.
// It provides syscall-level interception for environments where seccomp user-notify
// and eBPF are unavailable (e.g., AWS Fargate with SYS_PTRACE).
//
// The tracer intercepts four categories of syscalls:
//   - Exec: execve, execveat — command allow/deny/redirect via ExecHandler
//   - File: openat, openat2, unlinkat, renameat2, mkdirat, linkat, symlinkat,
//     fchmodat, fchmodat2, fchownat (plus legacy amd64 equivalents) — file
//     allow/deny/redirect/soft-delete via FileHandler with full path resolution
//     and symlink handling
//   - Network: connect, bind — network allow/deny/redirect via NetworkHandler
//     with sockaddr parsing for AF_INET, AF_INET6, AF_UNIX, and AF_UNSPEC
//   - Signal: kill, tkill, tgkill, rt_sigqueueinfo, rt_tgsigqueueinfo —
//     signal allow/deny/redirect via SignalHandler
//
// Syscall steering (redirect/rewrite):
//
// The tracer includes a syscall injection engine that can execute arbitrary
// syscalls inside a stopped tracee by saving registers, rewriting the
// instruction pointer to a syscall gadget, doing two-phase PtraceSyscall,
// and restoring state. This enables four steering actions:
//
//   - Exec redirect: redirects execve/execveat to a stub binary via fd
//     injection (pidfd_open + pidfd_getfd + dup3) and filename rewrite.
//     Supports in-place overwrite when the stub path fits, with fallback
//     to scratch page allocation. Handles fd displacement (saves/restores
//     pre-existing fds at the stub fd slot). Works for both execve and
//     execveat (normalizes to execve with the stub path).
//   - File path redirect: rewrites the path argument of any file syscall
//     to a different path. Uses scratch page allocation (per-TGID mmap'd
//     memory with bump allocator) when the redirect path is longer than
//     the original.
//   - Soft-delete: intercepts unlinkat/unlink, denies the original syscall,
//     and injects mkdirat + renameat2 to move the file to a trash directory
//     instead. The tracee sees unlink succeed (return 0).
//   - Connect redirect: rewrites the sockaddr in tracee memory to redirect
//     a connect() to a different address/port. Supports IPv4 and IPv6 with
//     in-place overwrite (fixed-size sockaddr structs always fit).
//
// Architecture support: amd64 and arm64. The syscall gadget is discovered
// by subtracting the syscall instruction size (2 bytes on amd64, 4 on arm64)
// from the instruction pointer at a syscall stop. Legacy (non-at) file
// syscalls (SYS_OPEN, SYS_UNLINK, etc.) are supported on amd64 only.
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
