//go:build linux

// Package ptrace implements a ptrace-based syscall tracer backend for agentsh.
// It provides syscall-level interception for environments where seccomp user-notify
// and eBPF are unavailable (e.g., AWS Fargate with SYS_PTRACE).
//
// This package is Linux-only and requires the SYS_PTRACE capability.
package ptrace
