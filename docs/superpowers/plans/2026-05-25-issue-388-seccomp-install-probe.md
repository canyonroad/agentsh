# Honest seccomp installability in `detect` (#388) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `agentsh detect` report `seccomp-execve`/`seccomp_user_notify` (and the Command Control score) from a real `NEW_LISTENER` install attempt — not a read-only probe — so environments where the install fails (e.g. Daytona EBUSY) are reported honestly.

**Architecture:** A throwaway re-exec child (reusing the #369 two-factor-gate pattern) runs the exact `loadRawFilter` install the runtime uses and reports success or the failing errno. The parent (`capabilities`, non-cgo) reads the child's exit code/stderr; the child (cgo, linked into the agentsh binary) does the install. `detect`'s display + score derive from this new "installable here" signal; the read-only probe stays as the "kernel-supported" signal. Runtime/startup gating is untouched.

**Tech Stack:** Go; `internal/netmonitor/unix` (cgo seccomp), `internal/capabilities`.

**Spec:** `docs/superpowers/specs/2026-05-25-issue-388-seccomp-install-probe-design.md`

**Verified facts (don't re-derive):**
- Real install: `loadRawFilter(prog []byte, withWaitKill bool) (int, error)` (`internal/netmonitor/unix/seccomp_load_linux.go`, `//go:build linux && cgo`): does `runtime.LockOSThread()` → `prctl(PR_SET_NO_NEW_PRIVS)` → `seccomp(SET_MODE_FILTER, NEW_LISTENER[|WAIT_KILLABLE_RECV])`. Returns the listener fd or an error wrapping the errno.
- `buildProbeFilterBytes() ([]byte, error)` and `exportFilterBPF` exist in the same package (`wait_killable_probe_runner_linux.go`, cgo): `ActAllow` default + `ActNotify` on socket/openat/etc. The default-allow means `close`/`write`/`exit_group` are NOT trapped.
- Re-exec child precedent (`wait_killable_probe_runner_linux.go`): `init()` calls `isProbeChildInvocation()` (argv[1] == a sentinel AND env token len ≥ 16) and, if matched, runs the child then `os.Exit`. Parent builds argv via `os.Executable()` + sentinel and an env token. `internal/api` imports `netmonitor/unix`; `cmd/agentsh` imports `internal/api` → the child `init()` is linked into the `agentsh` binary (and into the package's own `go test` binary). The package has non-cgo stubs and does NOT import `internal/capabilities` (no cycle).
- `boundedBuffer` (write-capped buffer) already exists in `wait_killable_probe_runner_linux.go` — reuse it for child stderr capture.
- `internal/capabilities`: `SecurityCapabilities` struct is defined in BOTH `security_caps.go` (`//go:build linux`) and `security_caps_other.go` (non-linux), with fields `Seccomp bool` / `SeccompBasic bool`. Populated in `security_caps.go` (~L67): `caps.Seccomp = checkSeccompUserNotify().Available`. Check seams are package vars in `check.go` (`checkSeccompUserNotify = realCheckSeccompUserNotify`, etc.); `CheckResult{Feature string; ConfigKey string; Available bool; Error error; Suggestion string}`.
- `detect_linux.go`: `buildLinuxDomains` sets `seccomp-notify` (L86) and `seccomp-execve` (L93) backends with `Available: caps.Seccomp`. `backwardCompatCaps` (L218) has `"seccomp": caps.Seccomp`, `"seccomp_user_notify": caps.Seccomp`, `"seccomp_basic": caps.SeccompBasic`. `ComputeScore` (`detect_result.go:74`) gives a domain its full Weight iff ANY backend is `Available`. **Do NOT touch** `detectFileEnforcementBackend` (L15), `SelectMode` (`security_caps.go:100`), or the `Active` labels — those feed runtime mode selection (non-goal).

---

## File Structure

- `internal/netmonitor/unix/seccomp_install_probe_linux.go` (new, `linux && cgo`) — `InstallProbeResult`, `ProbeSeccompInstall` (cached), the classifier, the injectable `runInstallProbe` seam, the child `init()` + `runInstallProbeChild`, contract constants.
- `internal/netmonitor/unix/seccomp_install_probe_stub.go` (new, `!linux || !cgo`) — stub `InstallProbeResult` + `ProbeSeccompInstall`.
- `internal/netmonitor/unix/seccomp_install_probe_linux_test.go` (new) — classifier unit tests (injected seam) + a real re-exec integration test.
- `internal/capabilities/check_seccomp_linux.go` — `realCheckSeccompInstall`; `internal/capabilities/check.go` — `checkSeccompInstall` seam var.
- `internal/capabilities/security_caps.go` + `security_caps_other.go` — `SeccompInstallable bool` + `SeccompInstallDetail string` fields; populate in `security_caps.go`.
- `internal/capabilities/detect_linux.go` — flip the two backend `Available` + add detail; update `backwardCompatCaps`.
- `internal/capabilities/detect_linux_test.go` (new or existing) — verdict/score/detail tests.

---

## Task 1: Install-probe (child + parent classifier + stub)

**Files:**
- Create: `internal/netmonitor/unix/seccomp_install_probe_linux.go`
- Create: `internal/netmonitor/unix/seccomp_install_probe_stub.go`
- Create: `internal/netmonitor/unix/seccomp_install_probe_linux_test.go`

- [ ] **Step 1: Write the failing classifier + stub-contract tests**

Create `internal/netmonitor/unix/seccomp_install_probe_linux_test.go`:

```go
//go:build linux && cgo

package unix

import (
	"errors"
	"syscall"
	"testing"
)

func TestClassifyInstallProbe(t *testing.T) {
	cases := []struct {
		name       string
		exitCode   int
		stderr     string
		spawnErr   error
		wantInst   bool
		wantErrno  syscall.Errno
	}{
		{"success", 0, "", nil, true, 0},
		{"ebusy", 1, "install filter: ... INSTALL_ERRNO=16\n", nil, false, syscall.EBUSY},
		{"eperm", 1, "INSTALL_ERRNO=1\n", nil, false, syscall.EPERM},
		{"einval", 1, "INSTALL_ERRNO=22\n", nil, false, syscall.EINVAL},
		{"nonerrno_setup_fail", 1, "build filter: boom\n", nil, false, 0},
		{"spawn_error", -1, "", errors.New("fork failed"), false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyInstallProbe(tc.exitCode, tc.stderr, tc.spawnErr)
			if got.Installable != tc.wantInst {
				t.Fatalf("Installable=%v, want %v (detail=%q)", got.Installable, tc.wantInst, got.Detail)
			}
			if got.Errno != tc.wantErrno {
				t.Errorf("Errno=%v (%d), want %v (%d)", got.Errno, got.Errno, tc.wantErrno, tc.wantErrno)
			}
			if !got.Installable && got.Detail == "" {
				t.Error("not-installable result must carry a non-empty Detail")
			}
		})
	}
}

// Real end-to-end: re-exec this test binary as the install-probe child and
// confirm the mechanism runs and returns a coherent verdict. On a kernel that
// supports user-notify the install succeeds; otherwise it reports a recognized
// errno (never a false positive). Skips only if the kernel lacks user-notify.
func TestProbeSeccompInstall_Integration(t *testing.T) {
	if probeSeccompUserNotifyKernel() != nil {
		t.Skip("kernel lacks user-notify; install probe not meaningful here")
	}
	res := ProbeSeccompInstall()
	if !res.Installable && res.Errno == 0 && res.Detail == "" {
		t.Fatalf("incoherent probe result: %+v", res)
	}
	if !res.Installable {
		t.Logf("install not available here: errno=%v detail=%q", res.Errno, res.Detail)
	}
}
```

(`probeSeccompUserNotifyKernel` is a tiny local helper for the skip guard — Step 3 defines it as a read-only `SECCOMP_GET_NOTIF_SIZES` check returning an error when unsupported.)

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/netmonitor/unix/ -run 'ClassifyInstallProbe|ProbeSeccompInstall_Integration' 2>&1 | head`
Expected: FAIL — `classifyInstallProbe`, `ProbeSeccompInstall`, `probeSeccompUserNotifyKernel` undefined.

- [ ] **Step 3: Implement the install-probe (cgo file)**

Create `internal/netmonitor/unix/seccomp_install_probe_linux.go`:

```go
//go:build linux && cgo

package unix

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Issue #388: detect must report seccomp enforcement from a REAL NEW_LISTENER
// install, not a read-only capability probe. This probe re-execs a throwaway
// child that runs the exact loadRawFilter install the runtime uses and reports
// success or the failing errno.

const (
	installProbeArgvSentinel = "--agentsh-internal-seccomp-install-probe-child-v1"
	installProbeEnv          = "AGENTSH_SECCOMP_INSTALL_PROBE_CHILD"
	installProbeStderrCap    = 4096
	// installErrnoPrefix is printed by the child on failure so the parent can
	// recover the precise errno without encoding it in the exit status.
	installErrnoPrefix = "INSTALL_ERRNO="
)

// InstallProbeResult reports whether agentsh can install its NEW_LISTENER
// seccomp filter in this environment. Errno is 0 when Installable.
type InstallProbeResult struct {
	Installable bool
	Errno       syscall.Errno
	Detail      string
}

// runInstallProbe spawns the probe child and returns its exit code, captured
// (bounded) stderr, and any spawn error. Injectable seam for tests.
var runInstallProbe = realRunInstallProbe

var (
	installProbeOnce   sync.Once
	installProbeResult InstallProbeResult
)

// ProbeSeccompInstall returns whether a NEW_LISTENER filter install succeeds
// here. Cached per process. Fail-safe: any inability to run the probe yields
// Installable=false with a descriptive Detail — never a false positive.
func ProbeSeccompInstall() InstallProbeResult {
	installProbeOnce.Do(func() {
		code, stderr, err := runInstallProbe()
		installProbeResult = classifyInstallProbe(code, stderr, err)
	})
	return installProbeResult
}

func classifyInstallProbe(exitCode int, stderr string, spawnErr error) InstallProbeResult {
	if spawnErr != nil {
		return InstallProbeResult{Installable: false, Detail: fmt.Sprintf("install probe could not run: %v", spawnErr)}
	}
	if exitCode == 0 {
		return InstallProbeResult{Installable: true}
	}
	if errno := parseInstallErrno(stderr); errno != 0 {
		return InstallProbeResult{Installable: false, Errno: errno, Detail: fmt.Sprintf("%s (errno %d)", errno, int(errno))}
	}
	detail := strings.TrimSpace(stderr)
	if detail == "" {
		detail = fmt.Sprintf("install probe exited %d", exitCode)
	}
	return InstallProbeResult{Installable: false, Detail: detail}
}

func parseInstallErrno(stderr string) syscall.Errno {
	for _, line := range strings.Split(stderr, "\n") {
		i := strings.Index(line, installErrnoPrefix)
		if i < 0 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(line[i+len(installErrnoPrefix):]))
		if err == nil && n > 0 {
			return syscall.Errno(n)
		}
	}
	return 0
}

func realRunInstallProbe() (int, string, error) {
	bin, err := os.Executable()
	if err != nil {
		return -1, "", fmt.Errorf("os.Executable: %w", err)
	}
	cmd := exec.Command(bin, installProbeArgvSentinel)
	cmd.Env = append(os.Environ(), installProbeEnv+"="+ensureProbeChildToken())
	stderr := &boundedBuffer{cap: installProbeStderrCap}
	cmd.Stdout = nil
	cmd.Stderr = stderr
	cmd.Stdin = nil
	runErr := cmd.Run()
	if runErr == nil {
		return 0, stderr.String(), nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return exitErr.ExitCode(), stderr.String(), nil // non-zero exit, not a spawn failure
	}
	return -1, stderr.String(), runErr // could not start / other
}

// isInstallProbeChildInvocation gates probe-child mode (two-factor: argv
// sentinel + env token length >= 16), mirroring isProbeChildInvocation.
func isInstallProbeChildInvocation() bool {
	if len(os.Args) < 2 || os.Args[1] != installProbeArgvSentinel {
		return false
	}
	return len(os.Getenv(installProbeEnv)) >= 16
}

func init() {
	if isInstallProbeChildInvocation() {
		runInstallProbeChild()
		os.Exit(0) // unreachable: runInstallProbeChild always exits
	}
}

// runInstallProbeChild installs the probe filter via the SAME loadRawFilter the
// runtime uses, then exits. The filter's ActAllow default means the child's own
// close/write/exit syscalls are never trapped, so no servicing is needed and
// the child cannot hang. Exits 0 on install success; on failure prints
// INSTALL_ERRNO=<n> (when the error is an errno) and exits 1.
func runInstallProbeChild() {
	prog, err := buildProbeFilterBytes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "seccomp install probe: build filter: %v\n", err)
		os.Exit(1)
	}
	fd, err := loadRawFilter(prog, false)
	if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			fmt.Fprintf(os.Stderr, "seccomp install probe: install filter: %v %s%d\n", err, installErrnoPrefix, int(errno))
		} else {
			fmt.Fprintf(os.Stderr, "seccomp install probe: install filter: %v\n", err)
		}
		os.Exit(1)
	}
	_ = unix.Close(fd)
	os.Exit(0)
}

// probeSeccompUserNotifyKernel is a read-only "does the kernel know user-notify"
// check (SECCOMP_GET_NOTIF_SIZES), used only as a test skip guard. Returns nil
// when supported.
func probeSeccompUserNotifyKernel() error {
	var sizes [3]uint16 // struct seccomp_notif_sizes { __u16 seccomp_notif, seccomp_notif_resp, seccomp_data; }
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&sizes)))
	if errno != 0 {
		return errno
	}
	return nil
}
```

- [ ] **Step 4: Implement the stub (non-cgo / non-linux)**

Create `internal/netmonitor/unix/seccomp_install_probe_stub.go`:

```go
//go:build !linux || !cgo

package unix

import "syscall"

// InstallProbeResult mirrors the cgo type so callers compile on every target.
type InstallProbeResult struct {
	Installable bool
	Errno       syscall.Errno
	Detail      string
}

// ProbeSeccompInstall is a stub for non-Linux / linux-without-cgo builds: there
// is no probe-child handler compiled in, so there is nothing to re-exec.
func ProbeSeccompInstall() InstallProbeResult {
	return InstallProbeResult{Installable: false, Detail: "seccomp install probe unavailable (no cgo / unsupported OS)"}
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./internal/netmonitor/unix/ -run 'ClassifyInstallProbe|ProbeSeccompInstall_Integration' -v`
Expected: classifier cases PASS; integration test PASSes (Installable=true on a normal kernel) or skips if user-notify is unsupported.

- [ ] **Step 6: Build (cgo + non-cgo) and full package**

Run: `go build ./... && CGO_ENABLED=0 go build ./internal/netmonitor/unix/ && go test ./internal/netmonitor/unix/`
Expected: both builds succeed (stub covers non-cgo); package tests pass.

- [ ] **Step 7: Commit**

```bash
git add internal/netmonitor/unix/seccomp_install_probe_linux.go internal/netmonitor/unix/seccomp_install_probe_stub.go internal/netmonitor/unix/seccomp_install_probe_linux_test.go
git commit -m "feat(#388): seccomp NEW_LISTENER install probe (re-exec child)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: capabilities — `SeccompInstallable` signal

**Files:**
- Modify: `internal/capabilities/security_caps.go` (struct field + populate)
- Modify: `internal/capabilities/security_caps_other.go` (struct field — non-linux parity)
- Modify: `internal/capabilities/check.go` (seam var)
- Modify: `internal/capabilities/check_seccomp_linux.go` (realCheckSeccompInstall)
- Create: `internal/capabilities/seccomp_install_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/capabilities/seccomp_install_test.go`:

```go
//go:build linux

package capabilities

import "testing"

// Issue #388: SeccompInstallable comes from the real install probe, distinct
// from the read-only Seccomp (kernel-supported) signal.
func TestDetectSecurityCapabilities_SeccompInstallable(t *testing.T) {
	origUN, origInstall := checkSeccompUserNotify, checkSeccompInstall
	defer func() { checkSeccompUserNotify, checkSeccompInstall = origUN, origInstall }()

	checkSeccompUserNotify = func() CheckResult { return CheckResult{Feature: "seccomp-user-notify", Available: true} }
	checkSeccompInstall = func() CheckResult { return CheckResult{Feature: "seccomp-install", Available: false, Error: errForTest("EBUSY (errno 16)")} }

	caps := DetectSecurityCapabilities()
	if !caps.Seccomp {
		t.Error("Seccomp (kernel-supported) should be true")
	}
	if caps.SeccompInstallable {
		t.Error("SeccompInstallable should be false when the install probe fails")
	}
	if caps.SeccompInstallDetail == "" {
		t.Error("SeccompInstallDetail should carry the failure reason")
	}
}
```

Add a tiny test helper at the bottom of the same file:

```go
type testErr string

func (e testErr) Error() string { return string(e) }
func errForTest(s string) error { return testErr(s) }
```

(If `DetectSecurityCapabilities` is not the exported constructor name, use the actual one — confirm with `grep -n "func DetectSecurityCapabilities\|func DetectSecurity" internal/capabilities/security_caps.go`. The verified populate site is `security_caps.go:67`.)

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/capabilities/ -run TestDetectSecurityCapabilities_SeccompInstallable -v`
Expected: FAIL — `checkSeccompInstall` / `caps.SeccompInstallable` / `caps.SeccompInstallDetail` undefined.

- [ ] **Step 3: Add struct fields**

In `internal/capabilities/security_caps.go`, add to `SecurityCapabilities` (immediately after `SeccompBasic bool`):

```go
	SeccompInstallable bool   // a real NEW_LISTENER filter install succeeds here (issue #388)
	SeccompInstallDetail string // why install is unavailable, when SeccompInstallable is false
```

Add the **same two fields** to the `SecurityCapabilities` struct in `internal/capabilities/security_caps_other.go` (non-linux parity, so cross-compiles).

- [ ] **Step 4: Add the check seam + real check**

In `internal/capabilities/check.go`, add to the `var (...)` seam block:

```go
	checkSeccompInstall = realCheckSeccompInstall
```

In `internal/capabilities/check_seccomp_linux.go`, add (import `github.com/agentsh/agentsh/internal/netmonitor/unix` as `unixmon`):

```go
func realCheckSeccompInstall() CheckResult {
	res := unixmon.ProbeSeccompInstall()
	r := CheckResult{Feature: "seccomp-install", Available: res.Installable}
	if !res.Installable {
		r.Error = fmt.Errorf("NEW_LISTENER filter install failed: %s", res.Detail)
	}
	return r
}
```

For non-linux builds, add a `realCheckSeccompInstall` returning `CheckResult{Feature: "seccomp-install", Available: false}` in the existing non-linux check file (mirror how `realCheckSeccompUserNotify` is stubbed for non-linux; if there's a `check_other.go`, add it there).

- [ ] **Step 5: Populate in DetectSecurityCapabilities**

In `internal/capabilities/security_caps.go`, immediately after `caps.SeccompBasic = checkSeccompBasic()` (~L68):

```go
	{
		r := checkSeccompInstall()
		caps.SeccompInstallable = r.Available
		if r.Error != nil {
			caps.SeccompInstallDetail = r.Error.Error()
		}
	}
```

- [ ] **Step 6: Run to verify it passes + build**

Run: `go test ./internal/capabilities/ -run TestDetectSecurityCapabilities_SeccompInstallable -v && go build ./... && GOOS=windows go build ./...`
Expected: test PASS; both builds OK (non-linux struct parity + check stub).

- [ ] **Step 7: Commit**

```bash
git add internal/capabilities/security_caps.go internal/capabilities/security_caps_other.go internal/capabilities/check.go internal/capabilities/check_seccomp_linux.go internal/capabilities/seccomp_install_test.go
git commit -m "feat(#388): SeccompInstallable capability from the install probe

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

(If a non-linux check file also changed, add it to the `git add` list.)

---

## Task 3: detect display + score from `SeccompInstallable`

**Files:**
- Modify: `internal/capabilities/detect_linux.go` (two backends + backwardCompatCaps)
- Modify/Create: `internal/capabilities/detect_linux_test.go`

- [ ] **Step 1: Write the failing detect test**

Add to `internal/capabilities/detect_linux_test.go` (create if absent, `//go:build linux`, `package capabilities`):

```go
//go:build linux

package capabilities

import "strings"
import "testing"

func TestBuildLinuxDomains_SeccompInstallFalseFlipsVerdictAndScore(t *testing.T) {
	caps := &SecurityCapabilities{
		Seccomp:              true,  // kernel-supported
		SeccompInstallable:   false, // but install fails here (e.g. Daytona EBUSY)
		SeccompInstallDetail: "EBUSY (errno 16)",
	}
	domains := buildLinuxDomains(caps)

	exec := findBackend(t, domains, "Command Control", "seccomp-execve")
	if exec.Available {
		t.Error("seccomp-execve must be unavailable when install fails")
	}
	if !strings.Contains(exec.Detail, "EBUSY") || !strings.Contains(strings.ToLower(exec.Detail), "kernel") {
		t.Errorf("seccomp-execve detail should name both kernel-support and the errno; got %q", exec.Detail)
	}
	notify := findBackend(t, domains, "File Protection", "seccomp-notify")
	if notify.Available {
		t.Error("seccomp-notify must be unavailable when install fails")
	}

	// With seccomp the only command backend, Command Control score must drop.
	caps.Ptrace = false
	domains = buildLinuxDomains(caps)
	cc := findDomain(t, domains, "Command Control")
	if ComputeScore([]ProtectionDomain{cc}) != 0 {
		t.Error("Command Control should score 0 when neither seccomp-execve nor ptrace is available")
	}
}

func TestBuildLinuxDomains_SeccompInstallTrueKeepsVerdict(t *testing.T) {
	caps := &SecurityCapabilities{Seccomp: true, SeccompInstallable: true}
	domains := buildLinuxDomains(caps)
	if !findBackend(t, domains, "Command Control", "seccomp-execve").Available {
		t.Error("seccomp-execve must be available when install succeeds")
	}
}

func findDomain(t *testing.T, domains []ProtectionDomain, name string) ProtectionDomain {
	t.Helper()
	for _, d := range domains {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("domain %q not found", name)
	return ProtectionDomain{}
}

func findBackend(t *testing.T, domains []ProtectionDomain, domain, backend string) DetectedBackend {
	t.Helper()
	d := findDomain(t, domains, domain)
	for _, b := range d.Backends {
		if b.Name == backend {
			return b
		}
	}
	t.Fatalf("backend %q not found in %q", backend, domain)
	return DetectedBackend{}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/capabilities/ -run TestBuildLinuxDomains_SeccompInstall -v`
Expected: FAIL — `seccomp-execve`/`seccomp-notify` are still `Available: caps.Seccomp` (true), so the unavailable assertions fail.

- [ ] **Step 3: Add a detail helper + flip the two backends**

In `internal/capabilities/detect_linux.go`, add a helper (near the top of the file):

```go
// seccompBackendDetail explains the seccomp verdict, distinguishing
// "kernel-supported" from "installable here" (issue #388).
func seccompBackendDetail(caps *SecurityCapabilities) string {
	if caps.SeccompInstallable {
		return ""
	}
	if caps.Seccomp {
		d := caps.SeccompInstallDetail
		if d == "" {
			d = "install failed"
		}
		return "kernel supports user-notify, but NEW_LISTENER install failed here: " + d
	}
	return "" // kernel doesn't support user-notify; existing Available=false speaks for itself
}
```

In `buildLinuxDomains`, change the `seccomp-notify` backend (L86) and `seccomp-execve` backend (L93) from `Available: caps.Seccomp, Detail: ""` to:

```go
				{Name: "seccomp-notify", Available: caps.SeccompInstallable, Detail: seccompBackendDetail(caps), Description: "openat/stat enforcement", CheckMethod: "probe"},
```
```go
				{Name: "seccomp-execve", Available: caps.SeccompInstallable, Detail: seccompBackendDetail(caps), Description: "execve interception", CheckMethod: "probe"},
```

- [ ] **Step 4: Update backwardCompatCaps**

In `internal/capabilities/detect_linux.go` `backwardCompatCaps`, change the `seccomp_user_notify` entry and add a kernel-supported key:

```go
		"seccomp":                    caps.Seccomp,
		"seccomp_user_notify":        caps.SeccompInstallable,        // installable here (issue #388)
		"seccomp_user_notify_kernel": caps.Seccomp,                   // kernel-supported (read-only probe)
		"seccomp_basic":              caps.SeccompBasic,
```

- [ ] **Step 4b: Clear `SeccompInstallable` when the wrapper is missing**

In `internal/capabilities/detect_linux.go` `applyWrapperAvailability`, alongside the existing `secCaps.Seccomp = false` (the "Wrapper missing — clear secCaps fields" block, ~L156), add:

```go
	secCaps.SeccompInstallable = false
```

so the `seccomp_user_notify` map entry (now sourced from `SeccompInstallable`) is also false when the wrapper is absent. (The domain-loop already disables the `wrapperDependentBackends` seccomp backends, so this is for `backwardCompatCaps` consistency.)

- [ ] **Step 4c: Fix the existing `TestApplyWrapperAvailability_Present`**

That test (`internal/capabilities/detect_linux_test.go`) builds `caps := &SecurityCapabilities{Seccomp: true, Landlock: true, ...}` and asserts `seccomp-notify`/`seccomp-execve` are **available** when the wrapper is present. Now that those backends read `caps.SeccompInstallable`, add `SeccompInstallable: true` to that struct literal:

```go
	caps := &SecurityCapabilities{
		Seccomp:            true,
		SeccompInstallable: true,
		Landlock:           true,
		LandlockABI:        5,
		FUSE:               true,
		Ptrace:             true,
	}
```

The wrapper-missing tests (`TestApplyWrapperAvailability_Missing*`, `TestDetect_WrapperMissing_Tip`) assert those backends are **un**available, which still holds (they default false), so they need no change.

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./internal/capabilities/ -run TestBuildLinuxDomains_SeccompInstall -v`
Expected: PASS (both).

- [ ] **Step 6: Full capabilities package + build**

Run: `go test ./internal/capabilities/ && go build ./... && GOOS=windows go build ./...`
Expected: package tests pass (Step 4c already updated the one existing test that asserted the old verdict); builds OK.

- [ ] **Step 7: Commit**

```bash
git add internal/capabilities/detect_linux.go internal/capabilities/detect_linux_test.go
git commit -m "fix(#388): detect seccomp verdicts + score from real install probe

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build matrix**

Run: `go build ./... && GOOS=windows go build ./... && CGO_ENABLED=0 go build ./internal/netmonitor/unix/ ./internal/capabilities/`
Expected: all succeed (cgo + non-cgo + windows).

- [ ] **Step 2: Vet + gofmt**

Run: `go vet ./internal/netmonitor/unix/ ./internal/capabilities/ && gofmt -l internal/netmonitor/unix/seccomp_install_probe_linux.go internal/netmonitor/unix/seccomp_install_probe_stub.go internal/netmonitor/unix/seccomp_install_probe_linux_test.go internal/capabilities/security_caps.go internal/capabilities/security_caps_other.go internal/capabilities/check.go internal/capabilities/check_seccomp_linux.go internal/capabilities/detect_linux.go internal/capabilities/seccomp_install_test.go internal/capabilities/detect_linux_test.go`
Expected: vet clean; `gofmt -l` prints nothing.

- [ ] **Step 3: Affected package tests**

Run: `go test ./internal/netmonitor/unix/ ./internal/capabilities/`
Expected: ok for both.

- [ ] **Step 4: Manual smoke (optional, informational)**

Run: `go run ./cmd/agentsh detect 2>&1 | grep -iA1 seccomp || true`
Expected: on this dev host (install works) `seccomp-execve` shows available; the point is no crash and the verdict reflects a real install.

- [ ] **Step 5: Commit any formatting fixes (only if Step 2 changed files)**

```bash
git add -A && git commit -m "chore(#388): gofmt" || echo "nothing to commit"
```

---

## Self-review notes

- **Spec coverage:** install-probe child+parent+stub reusing `buildProbeFilterBytes`/`loadRawFilter` (Task 1) ← spec §1; `SeccompInstallable` signal + seam (Task 2) ← spec §2; detect verdicts/score/detail from installability + dual-signal map, runtime untouched (Task 3) ← spec §2 + non-goals; cgo/non-cgo + windows builds (Tasks 1/2/4). Non-goals respected: `SelectMode`/`detectFileEnforcementBackend`/`Active` and runtime/startup gating untouched; read-only signal retained (`seccomp`, `seccomp_user_notify_kernel`); fail-safe classifier (spawn error / unparseable ⇒ not installable, never false positive).
- **Type/name consistency:** `InstallProbeResult{Installable,Errno,Detail}`, `ProbeSeccompInstall()`, `classifyInstallProbe`, `runInstallProbe` seam, `installProbeArgvSentinel`/`installProbeEnv`, `checkSeccompInstall`/`realCheckSeccompInstall`, `caps.SeccompInstallable`/`SeccompInstallDetail`, `buildLinuxDomains`/`ComputeScore`/`DetectedBackend`/`ProtectionDomain` — consistent across tasks and match verified facts.
- **Build-green per commit:** Task 1 = new files only; Task 2 consumes Task 1's `ProbeSeccompInstall`; Task 3 consumes Task 2's field. Each compiles.
- **No placeholders:** every step has concrete code/commands. The constructor name (`DetectSecurityCapabilities`) and the one existing test that asserted the old verdict (`TestApplyWrapperAvailability_Present`, fixed in Task 3 Step 4c) are both verified, not open questions.
