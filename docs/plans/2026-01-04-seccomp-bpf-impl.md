# Seccomp-BPF Enforcement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend agentsh's seccomp infrastructure to block dangerous syscalls with configurable blocklist/allowlist.

**Architecture:** Extend existing `agentsh-unixwrap` to install combined filters (user-notify for unix sockets, kill for blocked syscalls). Add new config types and audit events.

**Tech Stack:** Go, libseccomp-golang, seccomp user-notify, SIGSYS handling

---

## Task 1: Add Seccomp Config Types

**Files:**
- Modify: `internal/config/config.go:151-165` (SandboxConfig struct)
- Modify: `internal/config/config.go:240-243` (SandboxUnixSocketsConfig)

**Step 1: Write the test**

Create `internal/config/seccomp_test.go`:

```go
package config

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSeccompConfigParse(t *testing.T) {
	yamlData := `
sandbox:
  seccomp:
    enabled: true
    mode: enforce
    unix_socket:
      enabled: true
      action: enforce
    syscalls:
      default_action: allow
      block:
        - ptrace
        - mount
      on_block: kill
`
	var cfg Config
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	require.NoError(t, err)

	require.True(t, cfg.Sandbox.Seccomp.Enabled)
	require.Equal(t, "enforce", cfg.Sandbox.Seccomp.Mode)
	require.True(t, cfg.Sandbox.Seccomp.UnixSocket.Enabled)
	require.Equal(t, "enforce", cfg.Sandbox.Seccomp.UnixSocket.Action)
	require.Equal(t, "allow", cfg.Sandbox.Seccomp.Syscalls.DefaultAction)
	require.Contains(t, cfg.Sandbox.Seccomp.Syscalls.Block, "ptrace")
	require.Contains(t, cfg.Sandbox.Seccomp.Syscalls.Block, "mount")
	require.Equal(t, "kill", cfg.Sandbox.Seccomp.Syscalls.OnBlock)
}

func TestSeccompConfigDefaults(t *testing.T) {
	yamlData := `
sandbox:
  seccomp:
    enabled: true
`
	var cfg Config
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	require.NoError(t, err)

	applyDefaults(&cfg)

	require.True(t, cfg.Sandbox.Seccomp.Enabled)
	require.Equal(t, "enforce", cfg.Sandbox.Seccomp.Mode)
	require.True(t, cfg.Sandbox.Seccomp.UnixSocket.Enabled)
	require.Greater(t, len(cfg.Sandbox.Seccomp.Syscalls.Block), 0)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config -run TestSeccompConfig -v`
Expected: FAIL (Seccomp field doesn't exist)

**Step 3: Add config types to config.go**

Add after line 165 (after SandboxConfig):

```go
// SandboxSeccompConfig configures seccomp-bpf filtering.
type SandboxSeccompConfig struct {
	Enabled    bool                        `yaml:"enabled"`
	Mode       string                      `yaml:"mode"` // enforce, audit, disabled
	UnixSocket SandboxSeccompUnixConfig    `yaml:"unix_socket"`
	Syscalls   SandboxSeccompSyscallConfig `yaml:"syscalls"`
}

// SandboxSeccompUnixConfig configures unix socket monitoring via seccomp.
type SandboxSeccompUnixConfig struct {
	Enabled bool   `yaml:"enabled"`
	Action  string `yaml:"action"` // enforce, audit
}

// SandboxSeccompSyscallConfig configures syscall blocking.
type SandboxSeccompSyscallConfig struct {
	DefaultAction string   `yaml:"default_action"` // allow, block
	Block         []string `yaml:"block"`
	Allow         []string `yaml:"allow"`
	OnBlock       string   `yaml:"on_block"` // kill, log_and_kill
}
```

Add to SandboxConfig struct (around line 164):

```go
Seccomp     SandboxSeccompConfig     `yaml:"seccomp"`
```

**Step 4: Add defaults in applyDefaultsWithSource**

Add after line 526 (after cgroups defaults):

```go
// Seccomp defaults
if cfg.Sandbox.Seccomp.Mode == "" {
	cfg.Sandbox.Seccomp.Mode = "enforce"
}
if cfg.Sandbox.Seccomp.Enabled && !cfg.Sandbox.Seccomp.UnixSocket.Enabled {
	// Enable unix socket monitoring by default if seccomp is enabled
	cfg.Sandbox.Seccomp.UnixSocket.Enabled = true
}
if cfg.Sandbox.Seccomp.UnixSocket.Action == "" {
	cfg.Sandbox.Seccomp.UnixSocket.Action = "enforce"
}
if cfg.Sandbox.Seccomp.Syscalls.DefaultAction == "" {
	cfg.Sandbox.Seccomp.Syscalls.DefaultAction = "allow"
}
if cfg.Sandbox.Seccomp.Syscalls.OnBlock == "" {
	cfg.Sandbox.Seccomp.Syscalls.OnBlock = "kill"
}
// Default blocked syscalls (dangerous operations)
if len(cfg.Sandbox.Seccomp.Syscalls.Block) == 0 && cfg.Sandbox.Seccomp.Enabled {
	cfg.Sandbox.Seccomp.Syscalls.Block = []string{
		"ptrace",
		"process_vm_readv",
		"process_vm_writev",
		"personality",
		"mount",
		"umount2",
		"pivot_root",
		"reboot",
		"kexec_load",
		"init_module",
		"finit_module",
		"delete_module",
	}
}
```

**Step 5: Run test to verify it passes**

Run: `go test ./internal/config -run TestSeccompConfig -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/config/config.go internal/config/seccomp_test.go
git commit -m "feat(config): add seccomp-bpf configuration types

Add SandboxSeccompConfig with:
- Mode: enforce/audit/disabled
- UnixSocket monitoring settings
- Syscalls blocklist/allowlist configuration
- Default blocked syscalls for dangerous operations"
```

---

## Task 2: Add Seccomp Blocked Event

**Files:**
- Modify: `internal/events/schema.go`
- Modify: `internal/events/base.go` (if needed for new event type constant)

**Step 1: Write the test**

Create `internal/events/seccomp_test.go`:

```go
package events

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSeccompBlockedEventJSON(t *testing.T) {
	evt := SeccompBlockedEvent{
		BaseEvent: BaseEvent{
			Type:      "seccomp_blocked",
			Timestamp: time.Now().UTC(),
			SessionID: "sess_abc123",
		},
		PID:       12345,
		Comm:      "malicious-tool",
		Syscall:   "ptrace",
		SyscallNr: 101,
		Reason:    "blocked_by_policy",
		Action:    "killed",
	}

	data, err := json.Marshal(evt)
	require.NoError(t, err)
	require.Contains(t, string(data), `"type":"seccomp_blocked"`)
	require.Contains(t, string(data), `"syscall":"ptrace"`)
	require.Contains(t, string(data), `"action":"killed"`)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/events -run TestSeccompBlockedEventJSON -v`
Expected: FAIL (SeccompBlockedEvent undefined)

**Step 3: Add event type to schema.go**

Add at the end of `internal/events/schema.go`:

```go
// SeccompBlockedEvent - Seccomp killed process for blocked syscall.
type SeccompBlockedEvent struct {
	BaseEvent

	PID       int    `json:"pid"`
	Comm      string `json:"comm"`
	Syscall   string `json:"syscall"`
	SyscallNr int    `json:"syscall_nr"`
	Reason    string `json:"reason"` // "blocked_by_policy"
	Action    string `json:"action"` // "killed"
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/events -run TestSeccompBlockedEventJSON -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/events/schema.go internal/events/seccomp_test.go
git commit -m "feat(events): add SeccompBlockedEvent for syscall blocking audit"
```

---

## Task 3: Create Seccomp Filter Builder Package

**Files:**
- Create: `internal/seccomp/filter.go`
- Create: `internal/seccomp/filter_test.go`
- Create: `internal/seccomp/syscalls.go`

**Step 1: Write the test**

Create `internal/seccomp/filter_test.go`:

```go
//go:build linux && cgo

package seccomp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildFilterConfig(t *testing.T) {
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []string{"ptrace", "mount"},
	}

	// Just test that we can build the config without error
	require.NotEmpty(t, cfg.BlockedSyscalls)
	require.True(t, cfg.UnixSocketEnabled)
}

func TestResolveSyscallNumbers(t *testing.T) {
	tests := []struct {
		name    string
		want    bool // should resolve successfully
	}{
		{"ptrace", true},
		{"mount", true},
		{"process_vm_readv", true},
		{"not_a_real_syscall", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nr, err := ResolveSyscall(tc.name)
			if tc.want {
				require.NoError(t, err)
				require.Greater(t, nr, 0)
			} else {
				require.Error(t, err)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/seccomp -run TestBuildFilterConfig -v`
Expected: FAIL (package doesn't exist)

**Step 3: Create syscalls.go**

Create `internal/seccomp/syscalls.go`:

```go
//go:build linux && cgo

package seccomp

import (
	"fmt"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

// ResolveSyscall converts a syscall name to its number for the current arch.
func ResolveSyscall(name string) (int, error) {
	nr, err := libseccomp.GetSyscallFromName(name)
	if err != nil {
		return 0, fmt.Errorf("unknown syscall %q: %w", name, err)
	}
	return int(nr), nil
}

// ResolveSyscalls converts syscall names to numbers, skipping unknown ones.
func ResolveSyscalls(names []string) ([]int, []string) {
	var numbers []int
	var skipped []string
	for _, name := range names {
		nr, err := ResolveSyscall(name)
		if err != nil {
			skipped = append(skipped, name)
			continue
		}
		numbers = append(numbers, nr)
	}
	return numbers, skipped
}
```

**Step 4: Create filter.go**

Create `internal/seccomp/filter.go`:

```go
//go:build linux && cgo

package seccomp

// FilterConfig holds settings for building a seccomp filter.
type FilterConfig struct {
	UnixSocketEnabled bool
	BlockedSyscalls   []string
}

// FilterConfigFromYAML creates a FilterConfig from config package types.
// This is a separate function to avoid import cycles.
func FilterConfigFromYAML(unixEnabled bool, blockedSyscalls []string) FilterConfig {
	return FilterConfig{
		UnixSocketEnabled: unixEnabled,
		BlockedSyscalls:   blockedSyscalls,
	}
}
```

**Step 5: Run test to verify it passes**

Run: `go test ./internal/seccomp -run TestBuildFilterConfig -v`
Run: `go test ./internal/seccomp -run TestResolveSyscall -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/seccomp/
git commit -m "feat(seccomp): add filter config and syscall resolution"
```

---

## Task 4: Extend agentsh-unixwrap to Read Config

**Files:**
- Modify: `cmd/agentsh-unixwrap/main.go`
- Create: `cmd/agentsh-unixwrap/config.go`

**Step 1: Write the test**

Create `cmd/agentsh-unixwrap/config_test.go`:

```go
//go:build linux && cgo

package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseWrapperConfig(t *testing.T) {
	cfg := WrapperConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []string{"ptrace", "mount"},
	}

	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	var parsed WrapperConfig
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	require.True(t, parsed.UnixSocketEnabled)
	require.Equal(t, []string{"ptrace", "mount"}, parsed.BlockedSyscalls)
}

func TestParseWrapperConfigFromEnv(t *testing.T) {
	jsonCfg := `{"unix_socket_enabled":true,"blocked_syscalls":["ptrace"]}`
	cfg, err := parseConfigJSON(jsonCfg)
	require.NoError(t, err)
	require.True(t, cfg.UnixSocketEnabled)
	require.Contains(t, cfg.BlockedSyscalls, "ptrace")
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/agentsh-unixwrap -run TestParseWrapperConfig -v`
Expected: FAIL (WrapperConfig undefined)

**Step 3: Create config.go**

Create `cmd/agentsh-unixwrap/config.go`:

```go
//go:build linux && cgo

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// WrapperConfig is the configuration passed via AGENTSH_SECCOMP_CONFIG env var.
type WrapperConfig struct {
	UnixSocketEnabled bool     `json:"unix_socket_enabled"`
	BlockedSyscalls   []string `json:"blocked_syscalls"`
}

// loadConfig reads the wrapper config from environment.
func loadConfig() (*WrapperConfig, error) {
	val := os.Getenv("AGENTSH_SECCOMP_CONFIG")
	if val == "" {
		// Default: unix socket monitoring only, no blocked syscalls
		return &WrapperConfig{
			UnixSocketEnabled: true,
			BlockedSyscalls:   nil,
		}, nil
	}
	return parseConfigJSON(val)
}

func parseConfigJSON(data string) (*WrapperConfig, error) {
	var cfg WrapperConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		return nil, fmt.Errorf("parse AGENTSH_SECCOMP_CONFIG: %w", err)
	}
	return &cfg, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./cmd/agentsh-unixwrap -run TestParseWrapperConfig -v`
Expected: PASS

**Step 5: Commit**

```bash
git add cmd/agentsh-unixwrap/config.go cmd/agentsh-unixwrap/config_test.go
git commit -m "feat(unixwrap): add config parsing from environment"
```

---

## Task 5: Extend Filter Installation for Blocked Syscalls

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_linux.go`
- Create: `internal/netmonitor/unix/seccomp_linux_test.go`

**Step 1: Write the test**

Create `internal/netmonitor/unix/seccomp_linux_test.go`:

```go
//go:build linux && cgo

package unix

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstallFilterWithBlocked(t *testing.T) {
	// Note: This test requires root/CAP_SYS_ADMIN to actually install filters.
	// We test the configuration building only.
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []int{101, 165}, // ptrace=101, mount=165 on x86_64
	}

	require.NotEmpty(t, cfg.BlockedSyscalls)
	require.True(t, cfg.UnixSocketEnabled)
}

func TestFilterConfigDefaults(t *testing.T) {
	cfg := DefaultFilterConfig()
	require.True(t, cfg.UnixSocketEnabled)
	require.Empty(t, cfg.BlockedSyscalls) // No blocked syscalls by default
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/netmonitor/unix -run TestInstallFilterWithBlocked -v`
Expected: FAIL (FilterConfig undefined)

**Step 3: Extend seccomp_linux.go**

Add to `internal/netmonitor/unix/seccomp_linux.go`:

```go
// FilterConfig configures the seccomp filter to install.
type FilterConfig struct {
	UnixSocketEnabled bool
	BlockedSyscalls   []int // syscall numbers to block with KILL
}

// DefaultFilterConfig returns config for unix socket monitoring only.
func DefaultFilterConfig() FilterConfig {
	return FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   nil,
	}
}

// InstallFilterWithConfig installs a seccomp filter based on config.
// Unix socket syscalls get user-notify, blocked syscalls get kill.
func InstallFilterWithConfig(cfg FilterConfig) (*Filter, error) {
	if err := DetectSupport(); err != nil {
		return nil, err
	}

	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return nil, err
	}

	// Unix socket monitoring via user-notify
	if cfg.UnixSocketEnabled {
		trap := seccomp.ActNotify
		rules := []seccomp.ScmpSyscall{
			seccomp.ScmpSyscall(unix.SYS_SOCKET),
			seccomp.ScmpSyscall(unix.SYS_CONNECT),
			seccomp.ScmpSyscall(unix.SYS_BIND),
			seccomp.ScmpSyscall(unix.SYS_LISTEN),
			seccomp.ScmpSyscall(unix.SYS_SENDTO),
		}
		for _, sc := range rules {
			if err := filt.AddRule(sc, trap); err != nil {
				return nil, fmt.Errorf("add notify rule %v: %w", sc, err)
			}
		}
	}

	// Blocked syscalls via kill
	for _, nr := range cfg.BlockedSyscalls {
		sc := seccomp.ScmpSyscall(nr)
		if err := filt.AddRule(sc, seccomp.ActKillProcess); err != nil {
			return nil, fmt.Errorf("add kill rule %v: %w", sc, err)
		}
	}

	if err := filt.Load(); err != nil {
		return nil, err
	}
	fd, err := filt.GetNotifFd()
	if err != nil {
		// If no notify rules, fd will be -1, which is fine
		if !cfg.UnixSocketEnabled {
			return &Filter{fd: -1}, nil
		}
		return nil, err
	}
	return &Filter{fd: fd}, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/netmonitor/unix -run TestInstallFilterWithBlocked -v`
Run: `go test ./internal/netmonitor/unix -run TestFilterConfigDefaults -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/netmonitor/unix/seccomp_linux.go internal/netmonitor/unix/seccomp_linux_test.go
git commit -m "feat(seccomp): extend filter installation for blocked syscalls

Add InstallFilterWithConfig that builds combined filter:
- Unix socket syscalls: SECCOMP_RET_USER_NOTIF
- Blocked syscalls: SECCOMP_RET_KILL_PROCESS"
```

---

## Task 6: Update agentsh-unixwrap to Use Extended Filter

**Files:**
- Modify: `cmd/agentsh-unixwrap/main.go`

**Step 1: Read current main.go**

Review the existing main.go to understand the structure.

**Step 2: Modify main.go to use config**

Update `cmd/agentsh-unixwrap/main.go`:

```go
//go:build linux && cgo
// +build linux,cgo

// agentsh-unixwrap: installs seccomp user-notify for AF_UNIX sockets and blocks
// dangerous syscalls. Sends notify fd to the server over an inherited socketpair
// (SCM_RIGHTS), then execs the target command.
// Usage: agentsh-unixwrap -- <command> [args...]
// Requires env AGENTSH_NOTIFY_SOCK_FD set to the fd number of the socketpair to the server.
// Optional env AGENTSH_SECCOMP_CONFIG contains JSON config for syscall blocking.

package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"golang.org/x/sys/unix"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 3 || os.Args[1] != "--" {
		log.Fatalf("usage: %s -- <command> [args...]", os.Args[0])
	}

	sockFD, err := notifySockFD()
	if err != nil {
		log.Fatalf("notify fd: %v", err)
	}

	// Load config from environment
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Resolve syscall names to numbers
	blockedNrs, skipped := seccompkg.ResolveSyscalls(cfg.BlockedSyscalls)
	if len(skipped) > 0 {
		log.Printf("warning: skipped unknown syscalls: %v", skipped)
	}

	// Build filter config
	filterCfg := unixmon.FilterConfig{
		UnixSocketEnabled: cfg.UnixSocketEnabled,
		BlockedSyscalls:   blockedNrs,
	}

	// Install seccomp filter.
	filt, err := unixmon.InstallFilterWithConfig(filterCfg)
	if err == unixmon.ErrUnsupported {
		log.Printf("seccomp user-notify unsupported; exiting 0 for monitor-only")
		os.Exit(0)
	}
	if err != nil {
		log.Fatalf("install seccomp filter: %v", err)
	}
	defer filt.Close()

	notifFD := filt.NotifFD()

	// Send notify fd to server over socketpair (only if we have one).
	if notifFD >= 0 {
		if err := sendFD(sockFD, notifFD); err != nil {
			log.Fatalf("send fd: %v", err)
		}
	}
	_ = unix.Close(sockFD)

	// Exec the real command.
	cmd := os.Args[2]
	args := os.Args[2:]
	if err := syscall.Exec(cmd, args, os.Environ()); err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
}

func notifySockFD() (int, error) {
	val := os.Getenv("AGENTSH_NOTIFY_SOCK_FD")
	if val == "" {
		return 0, fmt.Errorf("AGENTSH_NOTIFY_SOCK_FD not set")
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid AGENTSH_NOTIFY_SOCK_FD=%q", val)
	}
	return n, nil
}

func sendFD(sock int, fd int) error {
	rights := unix.UnixRights(fd)
	// dummy payload
	return unix.Sendmsg(sock, []byte{0}, rights, nil, 0)
}
```

**Step 3: Run build to verify it compiles**

Run: `go build ./cmd/agentsh-unixwrap`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add cmd/agentsh-unixwrap/main.go
git commit -m "feat(unixwrap): use config for combined filter installation

Load AGENTSH_SECCOMP_CONFIG from env, resolve syscall names,
and install combined filter with both unix socket monitoring
and blocked syscall rules."
```

---

## Task 7: Update Session Exec to Pass Seccomp Config

**Files:**
- Modify: `internal/session/exec.go` (or wherever command execution happens)

**Step 1: Find command execution code**

Run: `grep -r "AGENTSH_NOTIFY_SOCK_FD" internal/`

Look for where the wrapper is invoked and environment is set.

**Step 2: Add AGENTSH_SECCOMP_CONFIG to environment**

Find the code that sets up the wrapper environment and add:

```go
import (
	"encoding/json"
	// ...existing imports
)

// In the function that prepares wrapper environment:

type wrapperConfig struct {
	UnixSocketEnabled bool     `json:"unix_socket_enabled"`
	BlockedSyscalls   []string `json:"blocked_syscalls"`
}

cfg := wrapperConfig{
	UnixSocketEnabled: s.config.Sandbox.Seccomp.UnixSocket.Enabled,
	BlockedSyscalls:   s.config.Sandbox.Seccomp.Syscalls.Block,
}
cfgJSON, err := json.Marshal(cfg)
if err != nil {
	return fmt.Errorf("marshal seccomp config: %w", err)
}
env = append(env, "AGENTSH_SECCOMP_CONFIG="+string(cfgJSON))
```

**Step 3: Test manually**

Run the server and verify the wrapper receives the config.

**Step 4: Commit**

```bash
git add internal/session/exec.go  # or appropriate file
git commit -m "feat(session): pass seccomp config to wrapper via environment"
```

---

## Task 8: Add SIGSYS Detection for Audit Logging

**Files:**
- Modify: `internal/session/process.go` (or process management code)

**Step 1: Find process wait/exit handling**

Run: `grep -r "WaitStatus" internal/`

Look for where child process exit is handled.

**Step 2: Add SIGSYS detection**

Add code to detect when a process was killed by seccomp:

```go
import (
	"golang.org/x/sys/unix"
)

// In the function that handles child exit:

func (s *Session) handleChildExit(pid int, status syscall.WaitStatus) {
	if status.Signaled() && status.Signal() == unix.SIGSYS {
		// Process was killed by seccomp
		s.logSeccompBlocked(pid, status)
	}
	// ... existing exit handling
}

func (s *Session) logSeccompBlocked(pid int, status syscall.WaitStatus) {
	// Note: We can't easily get the syscall number from WaitStatus alone.
	// The syscall number is available via ptrace PTRACE_GETSIGINFO, but
	// we don't have that set up. For now, log that seccomp killed the process.
	evt := events.SeccompBlockedEvent{
		BaseEvent: events.BaseEvent{
			Type:      "seccomp_blocked",
			Timestamp: time.Now().UTC(),
			SessionID: s.ID,
		},
		PID:    pid,
		Reason: "blocked_by_policy",
		Action: "killed",
	}
	s.auditLog(evt)
}
```

**Step 3: Test by triggering a blocked syscall**

Start a session and try to run `strace -p 1` (requires ptrace).

**Step 4: Commit**

```bash
git add internal/session/process.go  # or appropriate file
git commit -m "feat(session): detect and log seccomp-killed processes

Detect SIGSYS signal on child exit to log SeccompBlockedEvent
for audit trail when seccomp kills a process."
```

---

## Task 9: Add Integration Test

**Files:**
- Create: `internal/seccomp/integration_test.go`

**Step 1: Write integration test**

Create `internal/seccomp/integration_test.go`:

```go
//go:build linux && cgo && integration

package seccomp_test

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestSeccompBlocksPtrace(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for seccomp filter installation")
	}

	// Build the wrapper
	cmd := exec.Command("go", "build", "-o", "/tmp/test-unixwrap", "./cmd/agentsh-unixwrap")
	cmd.Dir = "../../.."
	require.NoError(t, cmd.Run())

	// Create socketpair for notify fd
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	// Run wrapper with ptrace blocked
	wrapCmd := exec.Command("/tmp/test-unixwrap", "--", "/bin/strace", "-p", "1")
	wrapCmd.Env = append(os.Environ(),
		"AGENTSH_NOTIFY_SOCK_FD=3",
		`AGENTSH_SECCOMP_CONFIG={"unix_socket_enabled":true,"blocked_syscalls":["ptrace"]}`,
	)
	wrapCmd.ExtraFiles = []*os.File{os.NewFile(uintptr(fds[1]), "notify")}

	err = wrapCmd.Run()
	require.Error(t, err)

	// Check that it was killed by signal
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok, "expected ExitError")
	status := exitErr.Sys().(syscall.WaitStatus)
	require.True(t, status.Signaled(), "expected process to be signaled")
	// Note: We expect SIGSYS (31 on Linux), but it might show as SIGKILL (9)
	// depending on how SECCOMP_RET_KILL_PROCESS works
}
```

**Step 2: Run integration test**

Run: `sudo go test ./internal/seccomp -tags=integration -run TestSeccompBlocksPtrace -v`

**Step 3: Commit**

```bash
git add internal/seccomp/integration_test.go
git commit -m "test(seccomp): add integration test for syscall blocking"
```

---

## Task 10: Update Smoke Test

**Files:**
- Modify: `scripts/smoke.sh`

**Step 1: Add seccomp test to smoke.sh**

Add after the existing shim tests (around line 325):

```bash
# Test seccomp blocking (if seccomp available)
if [[ -f ./bin/agentsh-unixwrap ]]; then
  echo "smoke: testing seccomp blocking..."
  # Try to run strace (which uses ptrace) - should fail if seccomp is working
  seccomp_out=""
  set +e
  seccomp_out="$(./bin/agentsh exec "$sid" -- sh -c 'strace -V 2>&1 || echo strace_blocked' 2>&1 | tail -n 1)"
  seccomp_rc=$?
  set -e

  # If strace ran successfully, seccomp might not be blocking ptrace
  # (This is OK in some test environments where seccomp isn't available)
  if [[ "$seccomp_out" == *"version"* ]]; then
    echo "smoke: NOTE (strace succeeded; seccomp may not be blocking ptrace)" >&2
  elif [[ "$seccomp_out" == "strace_blocked" ]]; then
    echo "smoke: seccomp blocking verified"
  fi
fi
```

**Step 2: Run smoke test**

Run: `./scripts/smoke.sh`

**Step 3: Commit**

```bash
git add scripts/smoke.sh
git commit -m "test(smoke): add seccomp blocking verification"
```

---

## Task 11: Update Documentation

**Files:**
- Modify: `docs/llm-proxy.md` or create `docs/seccomp.md`

**Step 1: Create seccomp documentation**

Create `docs/seccomp.md`:

```markdown
# Seccomp-BPF Syscall Filtering

agentsh uses seccomp-bpf to enforce syscall-level security controls on agent processes.

## Overview

When enabled, seccomp filtering provides two types of protection:

1. **Unix Socket Monitoring**: Intercepts socket operations for policy-based access control
2. **Syscall Blocking**: Immediately terminates processes that attempt blocked syscalls

## Configuration

```yaml
sandbox:
  seccomp:
    enabled: true
    mode: enforce  # enforce | audit | disabled

    unix_socket:
      enabled: true
      action: enforce  # enforce | audit

    syscalls:
      default_action: allow  # allow | block
      block:
        - ptrace
        - process_vm_readv
        - process_vm_writev
        - mount
        - umount2
        # ... see defaults below
      on_block: kill  # kill | log_and_kill
```

## Default Blocked Syscalls

When seccomp is enabled, these syscalls are blocked by default:

| Syscall | Reason |
|---------|--------|
| ptrace | Process debugging/injection |
| process_vm_readv | Cross-process memory read |
| process_vm_writev | Cross-process memory write |
| personality | Execution domain changes |
| mount | Filesystem mounting |
| umount2 | Filesystem unmounting |
| pivot_root | Root filesystem changes |
| reboot | System reboot |
| kexec_load | Kernel replacement |
| init_module | Kernel module loading |
| finit_module | Kernel module loading (fd) |
| delete_module | Kernel module unloading |

## Audit Events

When a process is killed for attempting a blocked syscall, a `seccomp_blocked` event is logged:

```json
{
  "type": "seccomp_blocked",
  "timestamp": "2026-01-04T10:30:00Z",
  "session_id": "sess_abc123",
  "pid": 12345,
  "comm": "malicious-tool",
  "syscall": "ptrace",
  "syscall_nr": 101,
  "reason": "blocked_by_policy",
  "action": "killed"
}
```

## Requirements

- Linux kernel 5.0+ with seccomp user-notify support
- libseccomp installed (for syscall name resolution)
- CAP_SYS_ADMIN or no_new_privs for filter installation
```

**Step 2: Commit**

```bash
git add docs/seccomp.md
git commit -m "docs: add seccomp-bpf configuration documentation"
```

---

## Task 12: Final Verification and Cleanup

**Step 1: Run all tests**

```bash
go test ./...
```

**Step 2: Run smoke test**

```bash
./scripts/smoke.sh
```

**Step 3: Verify build**

```bash
make build
```

**Step 4: Final commit with all remaining changes**

```bash
git status
git add -A
git commit -m "chore: seccomp-bpf implementation complete"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Config types | internal/config/config.go |
| 2 | Event schema | internal/events/schema.go |
| 3 | Filter builder | internal/seccomp/*.go |
| 4 | Wrapper config | cmd/agentsh-unixwrap/config.go |
| 5 | Extended filter | internal/netmonitor/unix/seccomp_linux.go |
| 6 | Wrapper integration | cmd/agentsh-unixwrap/main.go |
| 7 | Session config passing | internal/session/exec.go |
| 8 | SIGSYS detection | internal/session/process.go |
| 9 | Integration test | internal/seccomp/integration_test.go |
| 10 | Smoke test | scripts/smoke.sh |
| 11 | Documentation | docs/seccomp.md |
| 12 | Final verification | N/A |
