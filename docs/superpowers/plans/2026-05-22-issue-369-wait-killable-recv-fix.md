# Issue #369 — WAIT_KILLABLE_RECV Behavioral Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `ProbeWaitKillable` (uname version check) with a server-side behavioral probe and an operator override (`sandbox.seccomp.wait_killable`), so wrapped commands stop being killed on exe.dev-class kernels where the kernel-version probe lies.

**Architecture:** Server decides once at boot via a four-branch switch (config override → kernel<6 → safe composition → behavioral probe), memoizes the result, and passes it to every wrapper through the existing `AGENTSH_SECCOMP_CONFIG` env var. Wrapper consumes the bool and feeds it into `InstallFilterWithConfig`. Spec at `docs/superpowers/specs/2026-05-22-issue-369-wait-killable-recv-fix-design.md`.

**Tech Stack:** Go 1.x, `golang.org/x/sys/unix`, `github.com/seccomp/libseccomp-golang`, `slog`.

---

## Standing rules for every task

- **TDD discipline:** failing test → run test (verify fails) → implementation → run test (verify passes) → commit.
- **Cross-compile check** after any code change: `GOOS=windows go build ./...` must succeed (CLAUDE.md requirement).
- **After every commit, run `roborev-refine`** on the current branch. Fix every issue at severity above `low`. Iterate until only `low` issues remain or returns are diminishing, *then* move to the next task. The memory `feedback_roborev_between_tasks.md` is the source of truth for this rule.
- **Conventional commit subjects** scoped by area (`feat(config):`, `feat(seccomp):`, `test(...):`).

## File map

| File | New/Modify | Responsibility |
|---|---|---|
| `internal/config/config.go` | Modify (line 489-507) | Add `SandboxSeccompConfig.WaitKillable *bool` |
| `internal/config/seccomp_wait_killable.go` | **New** | Pure heuristic `WaitKillableFilterCompositionTriggersBug` |
| `internal/config/seccomp_wait_killable_test.go` | **New** | Heuristic table test |
| `internal/api/seccomp_wrapper_config.go` | Modify (line 15-43) | Add `seccompWrapperConfig.WaitKillable *bool` + serializer wires `&a.waitKillableDecision` |
| `internal/api/seccomp_wrapper_test.go` | Modify | Assert JSON round-trip preserves `nil`/`&true`/`&false` |
| `cmd/agentsh-unixwrap/config.go` | Modify (line 14-41) | Add `WrapperConfig.WaitKillable *bool` |
| `cmd/agentsh-unixwrap/config_test.go` | Modify | Assert wrapper-side JSON parse for all three values |
| `cmd/agentsh-unixwrap/main.go` | Modify (line 99-110) | Wire `cfg.WaitKillable` → `filterCfg.WaitKillable` |
| `internal/netmonitor/unix/seccomp_linux.go` | Modify (lines 243-254, 303) | Add `FilterConfig.WaitKillable *bool`; consult it before falling back to `ProbeWaitKillable()` |
| `internal/netmonitor/unix/seccomp_linux_test.go` | Modify | Assert override behavior via `loadFilterSyscall` injection seam |
| `internal/netmonitor/unix/wait_killable_probe_linux.go` | **New** | `ProbeWaitKillableBehavior(ctx, iterations)` + per-iteration runner |
| `internal/netmonitor/unix/wait_killable_probe_stub.go` | **New** | Non-Linux stub returns `(false, nil)` |
| `internal/netmonitor/unix/wait_killable_probe_linux_test.go` | **New** | Mocked-runner unit + real-Linux integration |
| `internal/api/wait_killable_decision.go` | **New** | Pure switch over (config, kernel, composition, probe) → `(bool, string)` — testable on every platform |
| `internal/api/wait_killable_decision_test.go` | **New** | Seven-row table test of the switch |
| `internal/api/app.go` | Modify (lines 49-112, 162-178) | Add `waitKillableDecision bool` + `waitKillableSource string` fields; populate in `NewApp` via `decideWaitKillable` |
| `internal/netmonitor/unix/sigurg_probe_test.go` | Modify | Add sub-test asserting operator override flows end-to-end |

---

### Task 1: Add the `WaitKillable *bool` field to `SandboxSeccompConfig`

**Files:**
- Modify: `internal/config/config.go:489-507`

- [ ] **Step 1: Add the field**

Open `internal/config/config.go`. Locate the `SandboxSeccompConfig` struct around line 489 and insert the new field after `MitigationDirs`:

```go
type SandboxSeccompConfig struct {
	Enabled     bool                            `yaml:"enabled"`
	Mode        string                          `yaml:"mode"`
	UnixSocket  SandboxSeccompUnixConfig        `yaml:"unix_socket"`
	Syscalls    SandboxSeccompSyscallConfig     `yaml:"syscalls"`
	Execve      ExecveConfig                    `yaml:"execve"`
	FileMonitor SandboxSeccompFileMonitorConfig `yaml:"file_monitor"`

	BlockedSocketFamilies []SandboxSeccompSocketFamilyConfig `yaml:"blocked_socket_families"`
	SocketRules           []SandboxSeccompSocketRuleConfig   `yaml:"socket_rules"`
	MitigationSets        []string                           `yaml:"mitigation_sets"`
	MitigationDirs        []string                           `yaml:"mitigation_dirs"`

	// WaitKillable tri-states SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV:
	//   nil   = auto-detect via boot-time behavioral probe
	//   &true = force on (skip probe)
	//   &false = force off (skip probe)
	// Issue #369: kernels >=6 may accept the flag and then misbehave when
	// the filter combines socket-family and file/metadata-family notify rules.
	WaitKillable *bool `yaml:"wait_killable"`
}
```

- [ ] **Step 2: Verify the project still builds and tests pass**

Run: `go build ./... && GOOS=windows go build ./... && go test ./internal/config/... -count=1`
Expected: PASS on both builds and the config-package test suite.

- [ ] **Step 3: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): add sandbox.seccomp.wait_killable tri-state knob

Pure field addition for issue #369. No callers yet — wired in later
tasks. Nil = auto-detect via behavioral probe; non-nil = operator override."
```

- [ ] **Step 4: Run roborev-refine and clear non-low issues**

Use the `roborev-refine` skill on the current branch. Fix every issue at severity above `low`. Stop only when remaining findings are all `low` or returns are diminishing.

---

### Task 2: Pure filter-composition heuristic

**Files:**
- Create: `internal/config/seccomp_wait_killable.go`
- Create: `internal/config/seccomp_wait_killable_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/config/seccomp_wait_killable_test.go`:

```go
package config

import (
	"testing"
)

func TestWaitKillableFilterCompositionTriggersBug(t *testing.T) {
	tt := boolPtr(true)
	ff := boolPtr(false)

	cases := []struct {
		name string
		cfg  SandboxSeccompConfig
		want bool
	}{
		{
			name: "all off",
			cfg:  SandboxSeccompConfig{},
			want: false,
		},
		{
			name: "only socket family",
			cfg: SandboxSeccompConfig{
				UnixSocket: SandboxSeccompUnixConfig{Enabled: true},
			},
			want: false,
		},
		{
			name: "only file_monitor",
			cfg: SandboxSeccompConfig{
				FileMonitor: SandboxSeccompFileMonitorConfig{Enabled: tt},
			},
			want: false,
		},
		{
			name: "socket + file_monitor explicit on",
			cfg: SandboxSeccompConfig{
				UnixSocket:  SandboxSeccompUnixConfig{Enabled: true},
				FileMonitor: SandboxSeccompFileMonitorConfig{Enabled: tt},
			},
			want: true,
		},
		{
			name: "socket + file_monitor disabled but enforce_without_fuse on (intercept_metadata defaults true)",
			cfg: SandboxSeccompConfig{
				UnixSocket: SandboxSeccompUnixConfig{Enabled: true},
				FileMonitor: SandboxSeccompFileMonitorConfig{
					Enabled:            ff,
					EnforceWithoutFUSE: tt,
				},
			},
			want: true,
		},
		{
			name: "socket + file_monitor disabled, enforce_without_fuse on, intercept_metadata explicitly off",
			cfg: SandboxSeccompConfig{
				UnixSocket: SandboxSeccompUnixConfig{Enabled: true},
				FileMonitor: SandboxSeccompFileMonitorConfig{
					Enabled:            ff,
					EnforceWithoutFUSE: tt,
					InterceptMetadata:  ff,
				},
			},
			want: false,
		},
		{
			name: "socket + intercept_metadata explicit on, file_monitor explicit off",
			cfg: SandboxSeccompConfig{
				UnixSocket: SandboxSeccompUnixConfig{Enabled: true},
				FileMonitor: SandboxSeccompFileMonitorConfig{
					Enabled:           ff,
					InterceptMetadata: tt,
				},
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := WaitKillableFilterCompositionTriggersBug(tc.cfg)
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Verify test fails**

Run: `go test ./internal/config/ -run TestWaitKillableFilterCompositionTriggersBug -count=1`
Expected: FAIL — `WaitKillableFilterCompositionTriggersBug` undefined.

- [ ] **Step 3: Implement the heuristic**

Create `internal/config/seccomp_wait_killable.go`:

```go
package config

// WaitKillableFilterCompositionTriggersBug returns true when the effective
// seccomp filter for the given config would install notify rules from both
// the socket family (unix_socket) AND the file/metadata family
// (file_monitor or intercept_metadata). This is the known-bad combination
// from issue #369: on kernels that lie about WAIT_KILLABLE_RECV support
// (e.g. 6.12.67 with ProcessVMReadv=ENOSYS), the wrapped process is killed
// by signal during the post-execve syscall storm when this combination is
// present together with WAIT_KILLABLE_RECV.
//
// The function operates on effective config (resolving FileMonitor.*
// defaults exactly as buildSeccompWrapperConfig does) so that the gotcha
// in the issue's bisection table — file_monitor.enabled=false with
// enforce_without_fuse=true still installs metadata notify rules — is
// caught correctly.
func WaitKillableFilterCompositionTriggersBug(cfg SandboxSeccompConfig) bool {
	socketFamily := cfg.UnixSocket.Enabled

	fmDefault := FileMonitorBoolWithDefault(cfg.FileMonitor.EnforceWithoutFUSE, false)
	fileFamily := FileMonitorBoolWithDefault(cfg.FileMonitor.Enabled, false) ||
		FileMonitorBoolWithDefault(cfg.FileMonitor.InterceptMetadata, fmDefault)

	return socketFamily && fileFamily
}
```

- [ ] **Step 4: Verify test passes**

Run: `go test ./internal/config/ -run TestWaitKillableFilterCompositionTriggersBug -count=1 -v`
Expected: PASS — all 7 sub-cases.

- [ ] **Step 5: Cross-compile + full config-package test**

Run: `GOOS=windows go build ./... && go test ./internal/config/... -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/seccomp_wait_killable.go internal/config/seccomp_wait_killable_test.go
git commit -m "feat(config): heuristic for WAIT_KILLABLE_RECV trigger composition

Pure function: returns true when the effective seccomp filter would
combine socket-family and file/metadata-family notify rules. Operates
on resolved defaults so that EnforceWithoutFUSE=true is correctly
detected as a file-family trigger even when file_monitor.enabled=false.

Issue #369."
```

- [ ] **Step 7: Run roborev-refine and clear non-low issues.**

---

### Task 3: Wrapper-side JSON field

**Files:**
- Modify: `cmd/agentsh-unixwrap/config.go:14-41`
- Modify: `cmd/agentsh-unixwrap/config_test.go`

- [ ] **Step 1: Add the field to `WrapperConfig`**

Open `cmd/agentsh-unixwrap/config.go`. Inside `WrapperConfig`, after `BlockIOUring`:

```go
	BlockIOUring      bool `json:"block_io_uring,omitempty"`

	// WaitKillable, when non-nil, forces SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
	// on or off, bypassing the wrapper's legacy kernel-version probe. The
	// server makes this decision (boot-time behavioral probe + optional
	// config override) and forwards the result; nil means "fall back to
	// ProbeWaitKillable()" for direct/test invocations. Issue #369.
	WaitKillable *bool `json:"wait_killable,omitempty"`
```

- [ ] **Step 2: Write the failing test**

Append to `cmd/agentsh-unixwrap/config_test.go`:

```go
func TestWrapperConfig_WaitKillable_JSON(t *testing.T) {
	cases := []struct {
		name string
		json string
		want *bool
	}{
		{name: "absent", json: `{"unix_socket_enabled":true}`, want: nil},
		{name: "true", json: `{"unix_socket_enabled":true,"wait_killable":true}`, want: boolPtr(true)},
		{name: "false", json: `{"unix_socket_enabled":true,"wait_killable":false}`, want: boolPtr(false)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AGENTSH_SECCOMP_CONFIG", tc.json)
			cfg, err := loadConfig()
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			switch {
			case tc.want == nil && cfg.WaitKillable != nil:
				t.Fatalf("want nil, got &%v", *cfg.WaitKillable)
			case tc.want != nil && cfg.WaitKillable == nil:
				t.Fatalf("want &%v, got nil", *tc.want)
			case tc.want != nil && *cfg.WaitKillable != *tc.want:
				t.Fatalf("want %v got %v", *tc.want, *cfg.WaitKillable)
			}
		})
	}
}

func boolPtr(v bool) *bool { return &v }
```

If `boolPtr` already exists in the test file, drop the helper at the end.

- [ ] **Step 3: Run the test**

Run: `go test ./cmd/agentsh-unixwrap/ -run TestWrapperConfig_WaitKillable_JSON -count=1 -v`
Expected: PASS — the JSON tag was already added in Step 1, so all three sub-cases pass.

- [ ] **Step 4: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/agentsh-unixwrap/config.go cmd/agentsh-unixwrap/config_test.go
git commit -m "feat(unixwrap): accept wait_killable in AGENTSH_SECCOMP_CONFIG

Tri-state passthrough from server's wait_killable decision. Nil means
'wrapper falls back to legacy probe' for direct/test invocations.

Issue #369."
```

- [ ] **Step 6: Run roborev-refine and clear non-low issues.**

---

### Task 4: Server-side JSON field

**Files:**
- Modify: `internal/api/seccomp_wrapper_config.go:15-43`
- Modify: `internal/api/seccomp_wrapper_test.go`

- [ ] **Step 1: Add the field to `seccompWrapperConfig`**

In `internal/api/seccomp_wrapper_config.go`, add after `BlockIOUring`:

```go
	BlockIOUring      bool `json:"block_io_uring,omitempty"`

	// WaitKillable forwards the server's wait_killable decision to the
	// wrapper. nil only if the App somehow has no decision set (treated as
	// "wrapper falls back to legacy probe"). Issue #369.
	WaitKillable *bool `json:"wait_killable,omitempty"`
```

- [ ] **Step 2: Don't wire it into `buildSeccompWrapperConfig` yet**

The App-level `waitKillableDecision` field doesn't exist yet (Task 8). Leave the serializer-side field present but unset; verify it serializes as omitted.

- [ ] **Step 3: Append a JSON round-trip test**

Append to `internal/api/seccomp_wrapper_test.go`:

```go
func TestSeccompWrapperConfig_WaitKillable_JSON(t *testing.T) {
	cases := []struct {
		name        string
		in          *bool
		wantSubstr  string
		wantAbsent  bool
	}{
		{name: "absent", in: nil, wantAbsent: true},
		{name: "true", in: boolPtrLocal(true), wantSubstr: `"wait_killable":true`},
		{name: "false", in: boolPtrLocal(false), wantSubstr: `"wait_killable":false`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := seccompWrapperConfig{WaitKillable: tc.in}
			b, err := json.Marshal(cfg)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			s := string(b)
			if tc.wantAbsent && strings.Contains(s, "wait_killable") {
				t.Fatalf("expected wait_killable to be omitted, got %s", s)
			}
			if !tc.wantAbsent && !strings.Contains(s, tc.wantSubstr) {
				t.Fatalf("expected %q in %s", tc.wantSubstr, s)
			}
		})
	}
}

func boolPtrLocal(v bool) *bool { return &v }
```

Add `encoding/json` and `strings` imports at the top of the file if not already present.

- [ ] **Step 4: Run the test**

Run: `go test ./internal/api/ -run TestSeccompWrapperConfig_WaitKillable_JSON -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Cross-compile + package test**

Run: `GOOS=windows go build ./... && go test ./internal/api/... -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/api/seccomp_wrapper_config.go internal/api/seccomp_wrapper_test.go
git commit -m "feat(api): serialize wait_killable into AGENTSH_SECCOMP_CONFIG

Field added now; wired to the App-level decision in a later task.

Issue #369."
```

- [ ] **Step 7: Run roborev-refine and clear non-low issues.**

---

### Task 5: `FilterConfig.WaitKillable` + override in `InstallFilterWithConfig`

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_linux.go:243-254, 303`
- Modify: `internal/netmonitor/unix/seccomp_linux_test.go`
- Modify: `cmd/agentsh-unixwrap/main.go:99-110`

- [ ] **Step 1: Write the failing test**

Open `internal/netmonitor/unix/seccomp_linux_test.go`. There's an existing pattern that uses the `loadFilterSyscall` seam (see `seccomp_retry_test.go` for inspiration). Add a new test:

```go
// TestInstallFilterWithConfig_WaitKillableOverride asserts that
// FilterConfig.WaitKillable, when non-nil, controls the
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV bit on the seccomp(2) flags
// argument regardless of host kernel support.
//
// Issue #369: the operator override path must not be subordinate to the
// kernel-version probe.
func TestInstallFilterWithConfig_WaitKillableOverride(t *testing.T) {
	bt := true
	bf := false
	cases := []struct {
		name      string
		cfgValue  *bool
		wantFlag  bool
	}{
		{name: "explicit true", cfgValue: &bt, wantFlag: true},
		{name: "explicit false", cfgValue: &bf, wantFlag: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origLoad := loadFilterSyscall
			origPrctl := prctlSetNoNewPrivs
			t.Cleanup(func() {
				loadFilterSyscall = origLoad
				prctlSetNoNewPrivs = origPrctl
			})

			var capturedFlags uintptr
			loadFilterSyscall = func(flags uintptr, _ *unix.SockFprog) (int, error) {
				capturedFlags = flags
				return 99, nil // pretend success, fd=99
			}
			prctlSetNoNewPrivs = func() error { return nil }

			cfg := FilterConfig{
				UnixSocketEnabled: true,
				WaitKillable:      tc.cfgValue,
			}
			_, err := InstallFilterWithConfig(cfg)
			if err != nil {
				t.Fatalf("install: %v", err)
			}
			gotFlag := capturedFlags&unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV != 0
			if gotFlag != tc.wantFlag {
				t.Fatalf("WAIT_KILLABLE_RECV bit: got %v want %v (flags=0x%x)",
					gotFlag, tc.wantFlag, capturedFlags)
			}
		})
	}
}
```

Imports needed at the top of the file: `golang.org/x/sys/unix`. Already imported in `seccomp_load_linux.go`; verify the test file imports it too.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/netmonitor/unix/ -run TestInstallFilterWithConfig_WaitKillableOverride -count=1 -v`
Expected: FAIL — `FilterConfig.WaitKillable` is not yet a field.

- [ ] **Step 3: Add the field**

In `internal/netmonitor/unix/seccomp_linux.go`, modify `FilterConfig` (around line 243):

```go
type FilterConfig struct {
	UnixSocketEnabled  bool
	ExecveEnabled      bool
	FileMonitorEnabled bool
	InterceptMetadata  bool
	WriteOnlyOpens     bool
	BlockIOUring       bool
	BlockedSyscalls    []int
	BlockedFamilies    []seccompkg.BlockedFamily
	SocketRules        []seccompkg.SocketRule
	OnBlockAction      seccompkg.OnBlockAction

	// WaitKillable, when non-nil, overrides the legacy kernel-version
	// probe for SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV. Nil keeps the
	// legacy ProbeWaitKillable() fallback for direct/test invocations
	// where the server hasn't computed a decision. Issue #369.
	WaitKillable *bool
}
```

- [ ] **Step 4: Honor it inside `InstallFilterWithConfig`**

In the same file, replace line 303 (`wantWaitKill := ProbeWaitKillable()`) with:

```go
	var wantWaitKill bool
	if cfg.WaitKillable != nil {
		wantWaitKill = *cfg.WaitKillable
	} else {
		// Legacy fallback for direct/test invocations: when no explicit
		// decision is provided, fall back to the kernel-version probe.
		// Server-side decisions (issue #369) always set WaitKillable, so
		// this path only runs when the wrapper is invoked outside the
		// normal server flow.
		wantWaitKill = ProbeWaitKillable()
	}
```

- [ ] **Step 5: Run the test, verify it passes**

Run: `go test ./internal/netmonitor/unix/ -run TestInstallFilterWithConfig_WaitKillableOverride -count=1 -v`
Expected: PASS — both sub-cases.

- [ ] **Step 6: Run existing seccomp + sigurg tests to verify no regression**

Run: `go test ./internal/netmonitor/unix/ -run 'Seccomp|Sigurg|InstallFilter|WaitKill' -count=1`
Expected: PASS.

- [ ] **Step 7: Wire `WaitKillable` through the wrapper main**

In `cmd/agentsh-unixwrap/main.go`, locate the `unixmon.FilterConfig{...}` construction (around line 99). Add the new field:

```go
	filterCfg := unixmon.FilterConfig{
		UnixSocketEnabled:  cfg.UnixSocketEnabled,
		ExecveEnabled:      cfg.ExecveEnabled,
		FileMonitorEnabled: cfg.FileMonitorEnabled,
		InterceptMetadata:  cfg.InterceptMetadata,
		WriteOnlyOpens:     cfg.WriteOnlyOpens,
		BlockIOUring:       cfg.BlockIOUring,
		BlockedSyscalls:    blockedNrs,
		BlockedFamilies:    cfg.BlockedFamilies,
		SocketRules:        cfg.SocketRules,
		OnBlockAction:      onBlock,
		WaitKillable:       cfg.WaitKillable,
	}
```

- [ ] **Step 8: Cross-compile + full build**

Run: `go build ./... && GOOS=windows go build ./... && go test ./internal/netmonitor/unix/... ./cmd/agentsh-unixwrap/... -count=1`
Expected: PASS on all.

- [ ] **Step 9: Commit**

```bash
git add internal/netmonitor/unix/seccomp_linux.go internal/netmonitor/unix/seccomp_linux_test.go cmd/agentsh-unixwrap/main.go
git commit -m "feat(seccomp): honor FilterConfig.WaitKillable in install path

When the server passes a definitive bool, use it directly instead of
the legacy uname-based ProbeWaitKillable(). Keeps the legacy probe as
fallback for wrapper invocations that bypass the server (tests,
direct CLI).

Issue #369."
```

- [ ] **Step 10: Run roborev-refine and clear non-low issues.**

---

### Task 6: Behavioral probe — non-Linux stub + Linux file skeleton

**Files:**
- Create: `internal/netmonitor/unix/wait_killable_probe_stub.go`
- Create: `internal/netmonitor/unix/wait_killable_probe_linux.go`

This task introduces the function signature and the per-iteration runner injection seam *without* the real fork/exec body. Real implementation lands in Task 7. Doing it in two halves lets us test the decision logic (all-pass, first-fail, all-error) without involving fork.

- [ ] **Step 1: Create the non-Linux stub**

```go
//go:build !linux
// +build !linux

package unix

import "context"

// ProbeWaitKillableBehavior is a non-Linux stub. Returns (false, nil) so
// non-Linux callers behave as if WAIT_KILLABLE_RECV is not safe, which
// is also true: the flag is Linux-only.
func ProbeWaitKillableBehavior(_ context.Context, _ int) (bool, error) {
	return false, nil
}
```

Save as `internal/netmonitor/unix/wait_killable_probe_stub.go`.

- [ ] **Step 2: Create the Linux file with the signature + injectable runner**

```go
//go:build linux && cgo
// +build linux,cgo

package unix

import (
	"context"
	"errors"
	"fmt"
)

// IterationResult classifies one probe iteration.
type IterationResult int

const (
	IterPass IterationResult = iota
	IterKilled
	IterTimeout
)

// runProbeIteration runs a single probe iteration. Production
// implementation lands in wait_killable_probe_runner_linux.go (Task 7).
// Exposed as a package var so the decision-logic test can inject a
// mocked runner.
var runProbeIteration = func(ctx context.Context) (IterationResult, error) {
	return 0, errors.New("runProbeIteration not implemented yet")
}

// ProbeWaitKillableBehavior runs `iterations` real probes of the
// production filter composition under WAIT_KILLABLE_RECV. Returns true
// only when every iteration's child exits cleanly (exit_status=0).
// Short-circuits on the first iteration that fails.
//
// Errors from runProbeIteration (fork/socketpair/filter-install failures)
// cause this function to return the error so callers can apply
// fail-safe semantics. Iteration outcomes IterKilled and IterTimeout
// both indicate the kernel bug from issue #369 and cause (false, nil).
func ProbeWaitKillableBehavior(ctx context.Context, iterations int) (bool, error) {
	if iterations <= 0 {
		return false, fmt.Errorf("ProbeWaitKillableBehavior: iterations must be >0, got %d", iterations)
	}
	for i := 1; i <= iterations; i++ {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}
		res, err := runProbeIteration(ctx)
		if err != nil {
			return false, err
		}
		switch res {
		case IterPass:
			continue
		case IterKilled, IterTimeout:
			return false, nil
		default:
			return false, fmt.Errorf("ProbeWaitKillableBehavior: unknown IterationResult %d", res)
		}
	}
	return true, nil
}
```

Save as `internal/netmonitor/unix/wait_killable_probe_linux.go`.

- [ ] **Step 3: Write the decision-logic unit test**

Create `internal/netmonitor/unix/wait_killable_probe_linux_test.go`:

```go
//go:build linux && cgo
// +build linux,cgo

package unix

import (
	"context"
	"errors"
	"testing"
)

func TestProbeWaitKillableBehavior_AllPass(t *testing.T) {
	orig := runProbeIteration
	t.Cleanup(func() { runProbeIteration = orig })

	calls := 0
	runProbeIteration = func(_ context.Context) (IterationResult, error) {
		calls++
		return IterPass, nil
	}
	ok, err := ProbeWaitKillableBehavior(context.Background(), 5)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Fatal("want true")
	}
	if calls != 5 {
		t.Fatalf("want 5 iterations, got %d", calls)
	}
}

func TestProbeWaitKillableBehavior_FirstFailShortCircuits(t *testing.T) {
	orig := runProbeIteration
	t.Cleanup(func() { runProbeIteration = orig })

	calls := 0
	runProbeIteration = func(_ context.Context) (IterationResult, error) {
		calls++
		return IterKilled, nil
	}
	ok, err := ProbeWaitKillableBehavior(context.Background(), 5)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Fatal("want false")
	}
	if calls != 1 {
		t.Fatalf("want short-circuit after 1 iteration, got %d", calls)
	}
}

func TestProbeWaitKillableBehavior_MidFail(t *testing.T) {
	orig := runProbeIteration
	t.Cleanup(func() { runProbeIteration = orig })

	calls := 0
	runProbeIteration = func(_ context.Context) (IterationResult, error) {
		calls++
		if calls == 3 {
			return IterTimeout, nil
		}
		return IterPass, nil
	}
	ok, err := ProbeWaitKillableBehavior(context.Background(), 5)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Fatal("want false (timeout at iter 3 must fail the probe)")
	}
	if calls != 3 {
		t.Fatalf("want 3 iterations, got %d", calls)
	}
}

func TestProbeWaitKillableBehavior_ErrorPropagates(t *testing.T) {
	orig := runProbeIteration
	t.Cleanup(func() { runProbeIteration = orig })

	want := errors.New("fork failed")
	runProbeIteration = func(_ context.Context) (IterationResult, error) {
		return 0, want
	}
	ok, err := ProbeWaitKillableBehavior(context.Background(), 5)
	if !errors.Is(err, want) {
		t.Fatalf("want %v, got %v", want, err)
	}
	if ok {
		t.Fatal("want false on error")
	}
}

func TestProbeWaitKillableBehavior_CancelledContext(t *testing.T) {
	orig := runProbeIteration
	t.Cleanup(func() { runProbeIteration = orig })

	runProbeIteration = func(_ context.Context) (IterationResult, error) {
		return IterPass, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok, err := ProbeWaitKillableBehavior(ctx, 5)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if ok {
		t.Fatal("want false on cancel")
	}
}

func TestProbeWaitKillableBehavior_ZeroIterations(t *testing.T) {
	_, err := ProbeWaitKillableBehavior(context.Background(), 0)
	if err == nil {
		t.Fatal("want error for iterations=0")
	}
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/netmonitor/unix/ -run TestProbeWaitKillableBehavior_ -count=1 -v`
Expected: PASS for all six sub-tests.

- [ ] **Step 5: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: PASS (the stub takes over).

- [ ] **Step 6: Commit**

```bash
git add internal/netmonitor/unix/wait_killable_probe_linux.go internal/netmonitor/unix/wait_killable_probe_stub.go internal/netmonitor/unix/wait_killable_probe_linux_test.go
git commit -m "feat(seccomp): WAIT_KILLABLE_RECV behavioral probe skeleton

Decision logic + injectable per-iteration runner. Tests cover all-pass,
short-circuit, error propagation, context cancel, and zero-iterations
guard. Real per-iteration runner (fork/seccomp/execve + waitpid) lands
in the next task.

Issue #369."
```

- [ ] **Step 7: Run roborev-refine and clear non-low issues.**

---

### Task 7: Behavioral probe — real per-iteration runner

**Files:**
- Create: `internal/netmonitor/unix/wait_killable_probe_runner_linux.go`
- Modify: `internal/netmonitor/unix/wait_killable_probe_linux_test.go` (add real-fork integration test)

- [ ] **Step 1: Implement the per-iteration runner**

The runner must:

1. Build a minimal seccomp filter program (BPF bytes) with notify rules for both syscall families. Use the existing `exportFilterBPF` + `loadRawFilter` pattern from `seccomp_load_linux.go`.
2. `fork()` via `unix.ForkExec` is too high-level; we need a raw fork to do prctl + seccomp before exec. Use `syscall.RawSyscall(SYS_FORK, ...)` or `syscall.ForkLock` + manual `fork`. Production reference: the existing wrapper code in `cmd/agentsh-unixwrap/main.go` uses `runtime.LockOSThread` + `prctl` + `seccomp` + `syscall.Exec` in the same goroutine — but that's *after* fork. For a probe we need to do this in a child. The cleanest approach is to re-exec our own binary in a "probe child" mode using `os/exec`, where the child entrypoint installs the filter and then execs `/bin/true`.

   **Chosen approach: probe child re-execs the current binary with a sentinel arg.** The current binary (server or wrapper) recognizes the sentinel, installs the filter, and execs `/bin/true`. This avoids fragile manual-fork code in Go and reuses the existing `loadRawFilter` path.

2. Plumb the sentinel:
   - Add an `init()` to the probe-runner file that checks for `AGENTSH_WAIT_KILLABLE_PROBE_CHILD=1` and, if set, runs the child sequence and never returns.
   - The child sequence: build the same BPF program (in-process); call `loadRawFilter(prog, withWaitKill=true)` to install with WAIT_KILLABLE_RECV; send the returned notify fd to the parent over an inherited socketpair fd (passed in env `AGENTSH_WAIT_KILLABLE_PROBE_SOCK`); then `syscall.Exec("/bin/true", ...)`.
3. Parent sequence:
   - `socketpair(AF_UNIX, SOCK_STREAM, …)` for fd handoff.
   - `os/exec.Command(os.Args[0])` with `Env` containing the sentinel and the socket fd; `ExtraFiles: [parent end]`; `Stderr: io.Discard`.
   - `cmd.Start()`.
   - Goroutine: read notify fd from socketpair; service all incoming `SECCOMP_IOCTL_NOTIF_RECV` notifications with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` responses until the child exits.
   - `cmd.Wait()` with a 1-second deadline via `context.WithTimeout`; on timeout, `cmd.Process.Kill()` and treat as `IterTimeout`.
   - Classify: `*exec.ExitError` with `WIFEXITED && status 0` → `IterPass`. `WIFSIGNALED` → `IterKilled`. Timeout → `IterTimeout`. Anything else → return as `(0, err)`.

The full implementation:

```go
//go:build linux && cgo
// +build linux,cgo

package unix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

const (
	probeChildEnv    = "AGENTSH_WAIT_KILLABLE_PROBE_CHILD"
	probeChildSockFD = "AGENTSH_WAIT_KILLABLE_PROBE_SOCK"
	probeBinaryPath  = "/bin/true"
)

// init wires the production runner and detects probe-child mode. When
// invoked as a probe child the process never returns: it either execs
// /bin/true (success path) or os.Exit(70)s. Otherwise it just installs
// realRunProbeIteration over the placeholder from
// wait_killable_probe_linux.go.
func init() {
	if os.Getenv(probeChildEnv) == "1" {
		runProbeChild()
		// runProbeChild never returns on success (it execs). If it does
		// return, treat as fatal child-side error.
		os.Exit(70)
	}
	runProbeIteration = realRunProbeIteration
}

func runProbeChild() {
	sockStr := os.Getenv(probeChildSockFD)
	sockFD, err := strconv.Atoi(sockStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wait_killable probe child: bad %s=%q: %v\n",
			probeChildSockFD, sockStr, err)
		return
	}

	prog, err := buildProbeFilterBytes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wait_killable probe child: build filter: %v\n", err)
		return
	}

	notifyFD, err := loadRawFilter(prog, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wait_killable probe child: install filter: %v\n", err)
		return
	}

	// Hand notifyFD to the parent.
	if err := sendProbeFD(sockFD, notifyFD); err != nil {
		fmt.Fprintf(os.Stderr, "wait_killable probe child: send fd: %v\n", err)
		return
	}
	_ = unix.Close(notifyFD)
	_ = unix.Close(sockFD)

	// Exec /bin/true to fire the post-execve syscall storm under the
	// installed filter. Falls back to /bin/echo if /bin/true is missing.
	bin := probeBinaryPath
	if _, err := os.Stat(bin); err != nil {
		bin = "/bin/echo"
	}
	_ = syscall.Exec(bin, []string{bin}, []string{})
	fmt.Fprintf(os.Stderr, "wait_killable probe child: exec failed\n")
}

// buildProbeFilterBytes constructs the worst-case filter composition
// (socket family + file/metadata family + execve trap) as raw BPF bytes
// using the existing libseccomp + exportFilterBPF path. Filter is
// ActAllow by default so syscalls not in the rule set pass through
// unimpeded.
func buildProbeFilterBytes() ([]byte, error) {
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return nil, err
	}
	defer filt.Release()

	trap := seccomp.ActNotify
	syscalls := []seccomp.ScmpSyscall{
		seccomp.ScmpSyscall(unix.SYS_SOCKET),
		seccomp.ScmpSyscall(unix.SYS_CONNECT),
		seccomp.ScmpSyscall(unix.SYS_BIND),
		seccomp.ScmpSyscall(unix.SYS_LISTEN),
		seccomp.ScmpSyscall(unix.SYS_SENDTO),
		seccomp.ScmpSyscall(unix.SYS_OPENAT),
		seccomp.ScmpSyscall(unix.SYS_STATX),
		seccomp.ScmpSyscall(unix.SYS_NEWFSTATAT),
		seccomp.ScmpSyscall(unix.SYS_FACCESSAT2),
		seccomp.ScmpSyscall(unix.SYS_READLINKAT),
	}
	for _, sc := range syscalls {
		if err := filt.AddRule(sc, trap); err != nil {
			return nil, fmt.Errorf("add probe rule %v: %w", sc, err)
		}
	}
	return exportFilterBPF(filt)
}

// sendProbeFD writes notifyFD over sockFD using SCM_RIGHTS.
func sendProbeFD(sockFD, notifyFD int) error {
	rights := unix.UnixRights(notifyFD)
	return unix.Sendmsg(sockFD, []byte{'F'}, rights, nil, 0)
}

// recvProbeFD reads one fd from sockFD over SCM_RIGHTS.
func recvProbeFD(sockFD int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(sockFD, buf, oob, 0)
	if err != nil {
		return -1, err
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	for _, c := range cmsgs {
		fds, err := unix.ParseUnixRights(&c)
		if err == nil && len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, errors.New("no fd received")
}

// realRunProbeIteration is the production runner installed in init().
func realRunProbeIteration(ctx context.Context) (IterationResult, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, fmt.Errorf("socketpair: %w", err)
	}
	parentSock, childSock := pair[0], pair[1]
	defer unix.Close(parentSock)

	binaryPath, err := os.Executable()
	if err != nil {
		unix.Close(childSock)
		return 0, fmt.Errorf("os.Executable: %w", err)
	}

	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Env = []string{
		probeChildEnv + "=1",
		probeChildSockFD + "=3", // ExtraFiles index 0 = fd 3
	}
	cmd.ExtraFiles = []*os.File{os.NewFile(uintptr(childSock), "probe-sock")}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		unix.Close(childSock)
		return 0, fmt.Errorf("start probe child: %w", err)
	}
	// The fd was duped into the child; close our end.
	_ = unix.Close(childSock)

	notifyFD, err := recvProbeFD(parentSock)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 0, fmt.Errorf("recv probe fd: %w", err)
	}
	defer unix.Close(notifyFD)

	// Service notifications until the child exits.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	serviceCtx, serviceCancel := context.WithCancel(ctx)
	defer serviceCancel()
	go serviceProbeNotifications(serviceCtx, notifyFD)

	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()

	select {
	case err := <-done:
		serviceCancel()
		return classifyProbeExit(err)
	case <-timeout.C:
		serviceCancel()
		_ = cmd.Process.Kill()
		<-done
		return IterTimeout, nil
	}
}

// serviceProbeNotifications drains the notify fd and responds CONTINUE
// to every notification until ctx is cancelled or the fd errors.
//
// Uses libseccomp-golang's seccomp.NotifReceive (the same call site as
// internal/netmonitor/unix/handler.go:41) for receive, and the existing
// NotifRespondContinue helper from addfd_linux.go for the response.
func serviceProbeNotifications(ctx context.Context, notifyFD int) {
	scmpFD := seccomp.ScmpFd(notifyFD)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		notif, err := seccomp.NotifReceive(scmpFD)
		if err != nil {
			if !errors.Is(err, unix.EINTR) {
				slog.Debug("wait_killable probe: notify recv ended", "error", err)
			}
			return
		}
		if err := NotifRespondContinue(notifyFD, notif.ID); err != nil {
			slog.Debug("wait_killable probe: notify respond failed", "error", err)
			return
		}
	}
}

// classifyProbeExit maps cmd.Wait()'s result to an IterationResult.
func classifyProbeExit(err error) (IterationResult, error) {
	if err == nil {
		return IterPass, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return IterKilled, nil
			}
			if ws.Exited() && ws.ExitStatus() == 0 {
				return IterPass, nil
			}
			return IterKilled, nil
		}
	}
	return 0, fmt.Errorf("wait_killable probe: unclassified exit: %w", err)
}
```

Save as `internal/netmonitor/unix/wait_killable_probe_runner_linux.go`.

- [ ] **Step 2: Add real-fork integration test (Linux only, gated on `testing.Short`)**

Append to `internal/netmonitor/unix/wait_killable_probe_linux_test.go`:

```go
func TestProbeWaitKillableBehavior_RealKernel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-fork probe test in short mode")
	}
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("/bin/true missing on this host")
	}
	if !ProbeWaitKillable() {
		t.Skip("kernel <6: WAIT_KILLABLE_RECV not supported on this host")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	start := time.Now()
	ok, err := ProbeWaitKillableBehavior(ctx, 2)
	dur := time.Since(start)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	t.Logf("probe result: ok=%v duration=%v", ok, dur)
	if !ok {
		t.Fatal("probe expected to succeed on stock CI kernel — if this fails, document the kernel posture")
	}
	if dur > 5*time.Second {
		t.Errorf("probe took too long: %v (expected <5s)", dur)
	}
}
```

Add imports for `os` and `time` at the top of the test file if not already present.

- [ ] **Step 3: Run all probe tests**

Run: `go test ./internal/netmonitor/unix/ -run TestProbeWaitKillableBehavior -count=1 -v`
Expected: PASS — six unit tests + one real-kernel test (on Linux CI with stock kernel).

- [ ] **Step 4: Run the full netmonitor/unix test suite to catch regressions**

Run: `go test ./internal/netmonitor/unix/... -count=1`
Expected: PASS.

- [ ] **Step 5: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/netmonitor/unix/wait_killable_probe_runner_linux.go internal/netmonitor/unix/wait_killable_probe_linux_test.go
git commit -m "feat(seccomp): real per-iteration runner for wait_killable probe

Self-exec sentinel child installs the worst-case filter composition
under WAIT_KILLABLE_RECV, sends notify fd to parent over socketpair,
and execs /bin/true. Parent services notifications with CONTINUE and
classifies child exit as IterPass/IterKilled/IterTimeout.

Real-kernel integration test runs on Linux CI; mocked-runner tests
cover the decision logic on every platform.

Issue #369."
```

- [ ] **Step 7: Run roborev-refine and clear non-low issues.**

---

### Task 8: Server-side decision logic (pure switch)

**Files:**
- Create: `internal/api/wait_killable_decision.go`
- Create: `internal/api/wait_killable_decision_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/api/wait_killable_decision_test.go`:

```go
package api

import (
	"context"
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestDecideWaitKillable(t *testing.T) {
	tt := true
	ff := false

	probeOK := func(_ context.Context) (bool, error) { return true, nil }
	probeFail := func(_ context.Context) (bool, error) { return false, nil }
	probeErr := func(_ context.Context) (bool, error) { return false, errors.New("probe boom") }

	compositionRisky := SandboxSeccompConfig{
		UnixSocket:  config.SandboxSeccompUnixConfig{Enabled: true},
		FileMonitor: config.SandboxSeccompFileMonitorConfig{Enabled: &tt},
	}
	compositionSafe := SandboxSeccompConfig{
		UnixSocket: config.SandboxSeccompUnixConfig{Enabled: true},
	}

	cases := []struct {
		name              string
		cfg               config.SandboxSeccompConfig
		kernelSupports    bool
		probe             func(context.Context) (bool, error)
		wantDecision      bool
		wantSource        string
	}{
		{name: "config &true wins", cfg: configWithWait(compositionRisky, &tt), kernelSupports: true, probe: probeFail, wantDecision: true, wantSource: "config"},
		{name: "config &false wins", cfg: configWithWait(compositionRisky, &ff), kernelSupports: true, probe: probeOK, wantDecision: false, wantSource: "config"},
		{name: "kernel <6 forces off", cfg: compositionRisky, kernelSupports: false, probe: probeOK, wantDecision: false, wantSource: "kernel_unsupported"},
		{name: "safe composition skips probe", cfg: compositionSafe, kernelSupports: true, probe: probeFail, wantDecision: true, wantSource: "filter_composition_safe"},
		{name: "probe pass", cfg: compositionRisky, kernelSupports: true, probe: probeOK, wantDecision: true, wantSource: "behavioral_probe"},
		{name: "probe fail", cfg: compositionRisky, kernelSupports: true, probe: probeFail, wantDecision: false, wantSource: "behavioral_probe"},
		{name: "probe error fails safe", cfg: compositionRisky, kernelSupports: true, probe: probeErr, wantDecision: false, wantSource: "behavioral_probe_error"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotDecision, gotSource := decideWaitKillable(context.Background(), waitKillableDeps{
				cfg:            tc.cfg,
				kernelSupports: func() bool { return tc.kernelSupports },
				probe:          tc.probe,
			})
			if gotDecision != tc.wantDecision {
				t.Errorf("decision: got %v want %v", gotDecision, tc.wantDecision)
			}
			if gotSource != tc.wantSource {
				t.Errorf("source: got %q want %q", gotSource, tc.wantSource)
			}
		})
	}
}

func configWithWait(cfg config.SandboxSeccompConfig, v *bool) config.SandboxSeccompConfig {
	cfg.WaitKillable = v
	return cfg
}
```

If the test file is in package `api`, but the production code uses `config.SandboxSeccompConfig` directly, the test may need to reference `config.SandboxSeccompConfig` qualified (as above) or you can use a type alias. Keep the qualified form for clarity.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/api/ -run TestDecideWaitKillable -count=1 -v`
Expected: FAIL — `decideWaitKillable` and `waitKillableDeps` undefined.

- [ ] **Step 3: Implement the decision logic**

Create `internal/api/wait_killable_decision.go`:

```go
package api

import (
	"context"

	"github.com/agentsh/agentsh/internal/config"
)

// waitKillableDeps wraps the inputs to decideWaitKillable so tests can
// inject the kernel-version probe and the behavioral probe without
// crossing platform build tags.
type waitKillableDeps struct {
	cfg            config.SandboxSeccompConfig
	kernelSupports func() bool
	probe          func(context.Context) (bool, error)
}

// decideWaitKillable applies the four-branch decision from issue #369
// and returns (decision, source). Source is a stable string suitable for
// inclusion in log lines so operators can grep one line to triage.
//
// Branches, in priority order:
//
//  1. Operator override (cfg.WaitKillable non-nil) → use as-is.
//  2. Kernel <6 → false (the flag doesn't exist).
//  3. Filter composition cannot trigger the bug → true (probe unneeded).
//  4. Behavioral probe → its result. Probe errors are fail-safe (false).
func decideWaitKillable(ctx context.Context, deps waitKillableDeps) (bool, string) {
	if v := deps.cfg.WaitKillable; v != nil {
		return *v, "config"
	}
	if !deps.kernelSupports() {
		return false, "kernel_unsupported"
	}
	if !config.WaitKillableFilterCompositionTriggersBug(deps.cfg) {
		return true, "filter_composition_safe"
	}
	ok, err := deps.probe(ctx)
	if err != nil {
		return false, "behavioral_probe_error"
	}
	return ok, "behavioral_probe"
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/api/ -run TestDecideWaitKillable -count=1 -v`
Expected: PASS — all 7 sub-cases.

- [ ] **Step 5: Cross-compile + package test**

Run: `GOOS=windows go build ./... && go test ./internal/api/... -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/api/wait_killable_decision.go internal/api/wait_killable_decision_test.go
git commit -m "feat(api): server-side wait_killable decision switch

Pure four-branch decision: config override > kernel<6 > safe
composition > behavioral probe. Returns (decision, source) so the
existing seccomp:filter loaded log line can announce the source for
incident triage.

Issue #369."
```

- [ ] **Step 7: Run roborev-refine and clear non-low issues.**

---

### Task 9: Wire the decision into `NewApp` and `buildSeccompWrapperConfig`

**Files:**
- Modify: `internal/api/app.go:49-112, 162-178`
- Modify: `internal/api/seccomp_wrapper_config.go:51-64`

- [ ] **Step 1: Add fields to `App`**

In `internal/api/app.go`, inside the `App` struct (after `acceptNotifyFDForTest`):

```go
	// waitKillableDecision is the server-process boot-time decision for
	// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV. Populated once in NewApp
	// and read by buildSeccompWrapperConfig on every exec. Issue #369.
	waitKillableDecision bool
	waitKillableSource   string
```

- [ ] **Step 2: Compute the decision in `NewApp`**

In `NewApp`, after the App struct is constructed (around line 176) and before `app.initPtraceTracer()`, add:

```go
	decision, source := decideWaitKillable(context.Background(), waitKillableDeps{
		cfg:            cfg.Sandbox.Seccomp,
		kernelSupports: waitKillableKernelSupports,
		probe:          waitKillableProbe,
	})
	app.waitKillableDecision = decision
	app.waitKillableSource = source
```

- [ ] **Step 3: Define the platform glue**

Create `internal/api/wait_killable_glue_linux.go`:

```go
//go:build linux && cgo
// +build linux,cgo

package api

import (
	"context"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
)

const waitKillableProbeIterations = 5

func waitKillableKernelSupports() bool { return unixmon.ProbeWaitKillable() }

func waitKillableProbe(ctx context.Context) (bool, error) {
	return unixmon.ProbeWaitKillableBehavior(ctx, waitKillableProbeIterations)
}
```

Create `internal/api/wait_killable_glue_stub.go`:

```go
//go:build !linux || !cgo
// +build !linux !cgo

package api

import "context"

// Non-Linux: WAIT_KILLABLE_RECV doesn't exist; decision is always false
// regardless of config. The decideWaitKillable switch handles this via
// the kernel_unsupported branch.
func waitKillableKernelSupports() bool { return false }

func waitKillableProbe(_ context.Context) (bool, error) { return false, nil }
```

- [ ] **Step 4: Wire `seccompWrapperConfig.WaitKillable` in `buildSeccompWrapperConfig`**

In `internal/api/seccomp_wrapper_config.go`, inside `buildSeccompWrapperConfig`, after the existing `seccompCfg.BlockIOUring = …` line:

```go
	// Pass the boot-time decision to every wrapper. Issue #369.
	seccompCfg.WaitKillable = &a.waitKillableDecision
```

- [ ] **Step 5: Add an integration test asserting the field flows through**

Append to `internal/api/seccomp_wrapper_test.go`:

```go
func TestBuildSeccompWrapperConfig_PropagatesWaitKillable(t *testing.T) {
	app := &App{
		cfg:                  testConfig(t),
		waitKillableDecision: false,
		waitKillableSource:   "behavioral_probe",
	}
	got := app.buildSeccompWrapperConfig(nil, seccompWrapperParams{})
	if got.WaitKillable == nil {
		t.Fatal("WaitKillable not set")
	}
	if *got.WaitKillable != false {
		t.Fatalf("want false, got true")
	}

	app.waitKillableDecision = true
	got = app.buildSeccompWrapperConfig(nil, seccompWrapperParams{})
	if got.WaitKillable == nil || *got.WaitKillable != true {
		t.Fatal("want &true after flipping decision")
	}
}
```

`testConfig(t)` is the existing test helper in the same file; reuse it. If it doesn't exist, find the helper that the other `buildSeccompWrapperConfig` tests use (look near line 299) and call that.

- [ ] **Step 6: Run the new test**

Run: `go test ./internal/api/ -run TestBuildSeccompWrapperConfig_PropagatesWaitKillable -count=1 -v`
Expected: PASS.

- [ ] **Step 7: Run the full api package tests**

Run: `go test ./internal/api/... -count=1`
Expected: PASS.

- [ ] **Step 8: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/api/app.go internal/api/seccomp_wrapper_config.go internal/api/seccomp_wrapper_test.go internal/api/wait_killable_glue_linux.go internal/api/wait_killable_glue_stub.go
git commit -m "feat(api): wire wait_killable decision into NewApp + wrapper config

App now computes the decision once at startup (kernel-supports probe +
behavioral probe + composition heuristic) and stamps it on every
seccompWrapperConfig via the new WaitKillable field. Per-platform glue
in wait_killable_glue_*.go isolates the cgo-bound probe.

Issue #369."
```

- [ ] **Step 10: Run roborev-refine and clear non-low issues.**

---

### Task 10: Diagnostic log lines

**Files:**
- Modify: `internal/api/app.go` (NewApp)
- Modify: `internal/api/wait_killable_decision.go` (or new helper)
- Modify: `internal/netmonitor/unix/wait_killable_probe_linux.go`
- Modify: `internal/netmonitor/unix/seccomp_linux.go:500-504`

- [ ] **Step 1: Add per-iteration log in the probe runner**

In `internal/netmonitor/unix/wait_killable_probe_linux.go`, add `slog` import and log lines inside `ProbeWaitKillableBehavior`:

```go
import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

func ProbeWaitKillableBehavior(ctx context.Context, iterations int) (bool, error) {
	if iterations <= 0 {
		return false, fmt.Errorf("ProbeWaitKillableBehavior: iterations must be >0, got %d", iterations)
	}
	slog.Info("seccomp: wait_killable behavioral probe starting",
		"iterations", iterations,
		"timeout_per_iter_ms", 1000)
	overallStart := time.Now()
	for i := 1; i <= iterations; i++ {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}
		start := time.Now()
		res, err := runProbeIteration(ctx)
		dur := time.Since(start)
		if err != nil {
			slog.Warn("seccomp: wait_killable iteration error",
				"iteration", i, "duration_ms", dur.Milliseconds(), "error", err)
			return false, err
		}
		slog.Info("seccomp: wait_killable iteration",
			"iteration", i, "result", iterationName(res), "duration_ms", dur.Milliseconds())
		if res != IterPass {
			slog.Info("seccomp: wait_killable probe complete",
				"decision", false,
				"reason", fmt.Sprintf("iteration %d %s", i, iterationName(res)),
				"total_duration_ms", time.Since(overallStart).Milliseconds())
			return false, nil
		}
	}
	slog.Info("seccomp: wait_killable probe complete",
		"decision", true,
		"reason", "all iterations passed",
		"total_duration_ms", time.Since(overallStart).Milliseconds())
	return true, nil
}

func iterationName(r IterationResult) string {
	switch r {
	case IterPass:
		return "pass"
	case IterKilled:
		return "killed"
	case IterTimeout:
		return "timeout"
	default:
		return fmt.Sprintf("unknown_%d", r)
	}
}
```

- [ ] **Step 2: Add the boot-decision log in `NewApp`**

In `internal/api/app.go`, immediately after the `app.waitKillableDecision = decision` line, add:

```go
	if source == "behavioral_probe" || source == "behavioral_probe_error" {
		// Probe logged its own per-iteration lines; emit only the
		// final decision line for readability.
	} else {
		slog.Info("seccomp: wait_killable decision",
			"value", decision,
			"source", source)
	}
```

The probe-path final-decision line is emitted from inside `ProbeWaitKillableBehavior` (Step 1); the non-probe paths emit it here.

- [ ] **Step 3: Surface the source on the per-exec line**

In `internal/netmonitor/unix/seccomp_linux.go`, around line 500, extend the existing log line and add a `WaitKillableSource` field to `FilterConfig`:

```go
type FilterConfig struct {
	// ... existing fields ...
	WaitKillable       *bool
	WaitKillableSource string // free-form diagnostic source string; included verbatim in the loaded-filter log line
}
```

And in `InstallFilterWithConfig`:

```go
	slog.Info("seccomp: filter loaded",
		"fd", rawFd,
		"wait_killable", gotWaitKill,
		"wait_killable_source", cfg.WaitKillableSource,
		"kernel_probe_supports", wantWaitKill,
		"libseccomp_runtime", libVer)
```

Plumb `WaitKillableSource` through:

- `seccompWrapperConfig.WaitKillableSource string` json:"wait_killable_source,omitempty"
- `buildSeccompWrapperConfig` sets `seccompCfg.WaitKillableSource = a.waitKillableSource`
- `cmd/agentsh-unixwrap/config.go` `WrapperConfig.WaitKillableSource string` json:"wait_killable_source,omitempty"
- `cmd/agentsh-unixwrap/main.go` passes `cfg.WaitKillableSource` into `filterCfg.WaitKillableSource`

Update the JSON round-trip tests in Tasks 3 and 4 to also assert the new field round-trips (add as sub-tests; don't break existing assertions).

- [ ] **Step 4: Build + run all touched packages**

Run: `go build ./... && GOOS=windows go build ./... && go test ./internal/config/... ./internal/api/... ./internal/netmonitor/unix/... ./cmd/agentsh-unixwrap/... -count=1`
Expected: PASS.

- [ ] **Step 5: Manual log inspection (Linux only, optional)**

Run a stock Linux build of the server briefly; grep the log output for:
- `seccomp: wait_killable behavioral probe starting`
- `seccomp: wait_killable iteration`
- `seccomp: wait_killable probe complete decision=true`
- `seccomp: filter loaded ... wait_killable_source=behavioral_probe`

Confirms the per-exec line now carries the source. Document the observation in the commit message.

- [ ] **Step 6: Commit**

```bash
git add internal/api/app.go internal/api/seccomp_wrapper_config.go internal/api/seccomp_wrapper_test.go internal/netmonitor/unix/wait_killable_probe_linux.go internal/netmonitor/unix/seccomp_linux.go cmd/agentsh-unixwrap/config.go cmd/agentsh-unixwrap/main.go internal/api/wait_killable_decision.go
git commit -m "feat(seccomp): diagnostic logging for wait_killable decisions

Boot-time emits one line per iteration plus a final decision line.
Non-probe paths (config override, kernel<6, safe composition) emit a
single decision line directly from NewApp. The existing per-exec
'seccomp: filter loaded' line now carries wait_killable_source so a
single grep tells an operator why this exec saw a given flag value.

Issue #369."
```

- [ ] **Step 7: Run roborev-refine and clear non-low issues.**

---

### Task 11: End-to-end test — operator override flows through

**Files:**
- Modify: `internal/netmonitor/unix/sigurg_probe_test.go`

- [ ] **Step 1: Inspect the existing test**

Open `internal/netmonitor/unix/sigurg_probe_test.go`. It already re-execs the test binary and asserts the loaded-filter log contains `wait_killable=true` on supported kernels (line 27+). The pattern we need is the same, but with `AGENTSH_SECCOMP_CONFIG` set to `{"wait_killable": false}` and the assertion inverted.

- [ ] **Step 2: Add a new sub-test**

Add at the end of `sigurg_probe_test.go`:

```go
// TestInstallFilter_HonorsOperatorOverride re-execs the test binary
// with AGENTSH_SECCOMP_CONFIG carrying an explicit wait_killable=false
// and asserts that:
//  1. The 'seccomp: filter loaded' line announces wait_killable=false.
//  2. The wait_killable_source field is "config".
// Issue #369 — end-to-end coverage of the operator override path.
func TestInstallFilter_HonorsOperatorOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("re-exec test skipped in short mode")
	}
	if !ProbeWaitKillable() {
		t.Skip("kernel <6: WAIT_KILLABLE_RECV not supported")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestInstallFilter_HonorsOperatorOverride_Child$")
	cmd.Env = append(os.Environ(),
		"AGENTSH_TEST_CHILD=1",
		`AGENTSH_SECCOMP_CONFIG={"unix_socket_enabled":true,"wait_killable":false}`,
	)
	out, _ := cmd.CombinedOutput()
	s := string(out)
	if !strings.Contains(s, "wait_killable=false") && !strings.Contains(s, `"wait_killable":false`) {
		t.Fatalf("override not honored — output:\n%s", s)
	}
	if !strings.Contains(s, `wait_killable_source=config`) && !strings.Contains(s, `"wait_killable_source":"config"`) {
		t.Fatalf("wait_killable_source not 'config' — output:\n%s", s)
	}
}

// TestInstallFilter_HonorsOperatorOverride_Child runs inside the
// re-exec'd child. It loads the wrapper config from env, runs
// InstallFilterWithConfig, and exits.
func TestInstallFilter_HonorsOperatorOverride_Child(t *testing.T) {
	if os.Getenv("AGENTSH_TEST_CHILD") != "1" {
		t.Skip()
	}
	cfg := FilterConfig{
		UnixSocketEnabled:  true,
		WaitKillable:       boolPtrLocal(false),
		WaitKillableSource: "config",
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	defer filt.Close()
}

func boolPtrLocal(v bool) *bool { return &v }
```

Imports as needed: `os`, `os/exec`, `strings`.

> The child test loads the FilterConfig directly rather than parsing `AGENTSH_SECCOMP_CONFIG` (that's the wrapper binary's job, not this test's). The parent's env-var setting is illustrative only — what we actually assert is that `FilterConfig.WaitKillable = &false` + `WaitKillableSource = "config"` produces the expected log line.

- [ ] **Step 3: Run the test**

Run: `go test ./internal/netmonitor/unix/ -run 'TestInstallFilter_HonorsOperatorOverride' -count=1 -v`
Expected: PASS.

- [ ] **Step 4: Run the sigurg suite to verify no regression**

Run: `go test ./internal/netmonitor/unix/ -run 'Sigurg|InstallFilter' -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/sigurg_probe_test.go
git commit -m "test(seccomp): end-to-end coverage for wait_killable override

Re-execs the test binary with FilterConfig.WaitKillable=&false +
WaitKillableSource='config' and asserts both fields show up in the
loaded-filter log line. Verifies the operator override flows through
the install path.

Issue #369."
```

- [ ] **Step 6: Run roborev-refine and clear non-low issues.**

---

### Task 12: Final integration verification

**Files:** none — this task is a verification gate, no commits unless issues are found.

- [ ] **Step 1: Full test suite**

Run: `go test ./... -count=1`
Expected: PASS across the repository.

- [ ] **Step 2: Cross-compile both targets**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: PASS.

- [ ] **Step 3: Re-read the spec against the tasks**

Open `docs/superpowers/specs/2026-05-22-issue-369-wait-killable-recv-fix-design.md`. Walk through every section of the spec and confirm:
- Architecture diagram realized in Tasks 5, 8, 9.
- Behavioral probe (Section 1 of the spec) realized in Tasks 6, 7.
- Filter-composition heuristic (Section 2) realized in Task 2.
- Config plumbing (Section 3) realized in Tasks 1, 3, 4, 5.
- Diagnosability (Section 4) realized in Task 10.
- Operator UX table reflected by the override path in Task 5 + Task 11.
- All six testing surfaces covered: Tasks 2, 4, 3, 5, 6+7, 11.

If any spec requirement is unimplemented, open a new task here and address it before merging.

- [ ] **Step 4: Run roborev-refine one more time on the full branch**

Use `roborev-refine` on the branch. Address every non-low issue. Once only low issues remain, the branch is ready for PR.

- [ ] **Step 5: Open the PR**

Use the `superpowers:finishing-a-development-branch` skill to decide between merge, PR, or further cleanup. The spec and plan are both committed; the PR description should reference both.

---

## Spec coverage checklist (self-review)

- [x] `SandboxSeccompConfig.WaitKillable` → Task 1
- [x] `WaitKillableFilterCompositionTriggersBug` heuristic → Task 2
- [x] `seccompWrapperConfig.WaitKillable` + JSON tag → Task 4
- [x] `WrapperConfig.WaitKillable` + JSON tag → Task 3
- [x] `FilterConfig.WaitKillable` + override in `InstallFilterWithConfig` → Task 5
- [x] `ProbeWaitKillableBehavior` skeleton + decision unit tests → Task 6
- [x] Real per-iteration runner (self-exec + socketpair + SCM_RIGHTS + `/bin/true` + waitpid + classify) → Task 7
- [x] `decideWaitKillable` four-branch switch + table test → Task 8
- [x] App-level wiring (`NewApp` decision + `buildSeccompWrapperConfig` propagation) → Task 9
- [x] Diagnostic log lines (probe iterations, boot decision, per-exec source) → Task 10
- [x] End-to-end operator-override test → Task 11
- [x] Cross-compile checks → every task
- [x] roborev-refine after every commit → every task standing rule

No placeholders. No "similar to Task N." Every step shows code, command, or commit message verbatim.
