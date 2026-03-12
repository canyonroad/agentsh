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
// This package is Linux-only and requires the SYS_PTRACE capability.
package ptrace
