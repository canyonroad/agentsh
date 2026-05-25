# Detect honesty for uninstallable seccomp — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `agentsh detect` (and the shared `SelectMode`) consume the `SeccompInstallable` probe so the Command Control domain's `✓/-` marks, `active backend` label, and score agree on hosts where the seccomp `NEW_LISTENER` filter can't install (e.g. Daytona/`EBUSY`).

**Architecture:** Three localized edits in `internal/capabilities` on the mode-selection/detect path. `SelectMode` gates `ModeFull` on `SeccompInstallable` (not kernel-support `Seccomp`); `buildLinuxDomains` makes the `ptrace` Command Control backend reflect *actual enforcement* (`Ptrace && PtraceEnabled`) and derives `commandActive` by priority. The existing any-backend `ComputeScore` then yields the correct number with no scorer change; darwin/windows builders and the runtime seccomp install path are untouched.

**Tech Stack:** Go, `//go:build linux` files, standard `go test`.

**Spec:** `docs/superpowers/specs/2026-05-25-issue-390-detect-installable-honesty-design.md`

---

### Task 1: `SelectMode()` requires installable seccomp for `ModeFull`

**Files:**
- Modify: `internal/capabilities/security_caps.go:111`
- Test: `internal/capabilities/security_caps_test.go:31-79`

- [ ] **Step 1: Update the test table — fix the existing "full" case and add a "not full when uninstallable" case**

In `internal/capabilities/security_caps_test.go`, replace the `tests` slice in `TestSecurityCapabilities_SelectMode` (currently lines 32-69) with:

```go
	tests := []struct {
		name     string
		caps     SecurityCapabilities
		expected string
	}{
		{
			name: "full mode when all available and seccomp installable",
			caps: SecurityCapabilities{
				Seccomp: true, SeccompInstallable: true, EBPF: true, FUSE: true, Landlock: true,
				Capabilities: true,
			},
			expected: "full",
		},
		{
			name: "not full when seccomp kernel-supported but not installable (falls to landlock)",
			caps: SecurityCapabilities{
				Seccomp: true, SeccompInstallable: false, EBPF: true, FUSE: true, Landlock: true,
				Capabilities: true,
			},
			expected: "landlock",
		},
		{
			name: "landlock mode when seccomp unavailable",
			caps: SecurityCapabilities{
				Seccomp: false, EBPF: false, FUSE: true, Landlock: true,
				Capabilities: true,
			},
			expected: "landlock",
		},
		{
			name: "landlock-only when FUSE also unavailable",
			caps: SecurityCapabilities{
				Seccomp: false, EBPF: false, FUSE: false, Landlock: true,
				Capabilities: true,
			},
			expected: "landlock-only",
		},
		{
			name: "minimal when nothing available",
			caps: SecurityCapabilities{
				Seccomp: false, EBPF: false, FUSE: false, Landlock: false,
				Capabilities: true,
			},
			expected: "minimal",
		},
	}
```

- [ ] **Step 2: Run the test to verify the new case fails**

Run: `go test ./internal/capabilities/ -run TestSecurityCapabilities_SelectMode -v`
Expected: FAIL — subtest `not_full_when_seccomp_kernel-supported_but_not_installable_(falls_to_landlock)` reports `expected mode "landlock", got "full"` (current code keys off `c.Seccomp`).

- [ ] **Step 3: Change the `ModeFull` condition to use `SeccompInstallable`**

In `internal/capabilities/security_caps.go`, in `SelectMode()` (line 109), change the first condition:

```go
func (c *SecurityCapabilities) SelectMode() string {
	// Full mode requires a seccomp NEW_LISTENER filter that actually installs
	// here, not merely kernel user-notify support (issue #390). On hosts where
	// the kernel supports user-notify but the listener cannot install (e.g.
	// Daytona/EBUSY), full mode would never actually enforce.
	if c.SeccompInstallable && c.EBPF && c.FUSE {
		return ModeFull
	}

	// Ptrace mode: SYS_PTRACE available and enabled
	if c.Ptrace && c.PtraceEnabled {
		return ModePtrace
	}

	// Landlock mode: Landlock + FUSE (no seccomp)
	if c.Landlock && c.FUSE {
		return ModeLandlock
	}

	// Landlock-only: just Landlock (no FUSE either)
	if c.Landlock {
		return ModeLandlockOnly
	}

	// Minimal: only capabilities dropping
	return ModeMinimal
}
```

(Only the first `if` changes: `c.Seccomp` → `c.SeccompInstallable`.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/capabilities/ -run TestSecurityCapabilities_SelectMode -v`
Expected: PASS (all five subtests).

- [ ] **Step 5: Commit**

```bash
git add internal/capabilities/security_caps.go internal/capabilities/security_caps_test.go
git commit -m "$(cat <<'EOF'
fix(#390): SelectMode gates full mode on seccomp installability

Full mode now requires SeccompInstallable (a real NEW_LISTENER install),
not merely kernel user-notify support, so the reported mode is honest on
hosts where the listener cannot install (e.g. Daytona/EBUSY).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Command Control backends reflect actual enforcement in `buildLinuxDomains`

**Files:**
- Modify: `internal/capabilities/detect_linux.go:65-69` (`commandActive`), `:113` (ptrace backend), and add `ptraceBackendDetail` helper near `seccompBackendDetail` (`:28-45`)
- Test: `internal/capabilities/detect_linux_test.go` (new tests + update three existing ones)

- [ ] **Step 1: Write/adjust the failing tests**

In `internal/capabilities/detect_linux_test.go`:

**(a)** Add two new tests:

```go
func TestBuildLinuxDomains_PtraceBackendReflectsEnforcement(t *testing.T) {
	// Capability present but not enabled in config: not actively enforcing.
	idle := buildLinuxDomains(&SecurityCapabilities{Ptrace: true, PtraceEnabled: false})
	pb := findBackend(t, idle, "Command Control", "ptrace")
	if pb.Available {
		t.Error("ptrace backend must be unavailable when ptrace is a present-but-unengaged capability")
	}
	if pb.Detail != "available, not active (enable ptrace mode)" {
		t.Errorf("ptrace detail = %q, want the actionable not-active message", pb.Detail)
	}

	// Capability present AND enabled: actively enforcing.
	active := buildLinuxDomains(&SecurityCapabilities{Ptrace: true, PtraceEnabled: true})
	ab := findBackend(t, active, "Command Control", "ptrace")
	if !ab.Available {
		t.Error("ptrace backend must be available when ptrace is enabled (actively enforcing)")
	}
	if ab.Detail != "" {
		t.Errorf("ptrace detail = %q, want empty when actively enforcing", ab.Detail)
	}
}

func TestBuildLinuxDomains_CommandActivePriority(t *testing.T) {
	// seccomp installable -> seccomp-execve is the active backend.
	d := buildLinuxDomains(&SecurityCapabilities{SeccompInstallable: true})
	if got := findDomain(t, d, "Command Control").Active; got != "seccomp-execve" {
		t.Errorf("active = %q, want seccomp-execve when seccomp is installable", got)
	}

	// seccomp not installable, ptrace not enforcing -> no active backend.
	d = buildLinuxDomains(&SecurityCapabilities{SeccompInstallable: false, Ptrace: true, PtraceEnabled: false})
	if got := findDomain(t, d, "Command Control").Active; got != "" {
		t.Errorf("active = %q, want empty when nothing enforces command control", got)
	}

	// seccomp not installable, ptrace enforcing (mode==ptrace) -> ptrace active.
	d = buildLinuxDomains(&SecurityCapabilities{SeccompInstallable: false, Ptrace: true, PtraceEnabled: true})
	if got := findDomain(t, d, "Command Control").Active; got != "ptrace" {
		t.Errorf("active = %q, want ptrace when ptrace is the actively-enforcing fallback", got)
	}
}
```

**(b)** Rewrite the ptrace block of `TestBuildLinuxDomains_SeccompInstallFalseFlipsVerdictAndScore` — replace lines 295-310 (everything after the `seccomp-notify` unavailable assertion, i.e. from the `// ptrace is a genuine fallback` comment to the end of the function) with:

```go
	// #390: a present-but-unengaged ptrace capability does NOT keep Command
	// Control's weight — only an actively-enforcing backend scores.
	caps.Ptrace = true
	caps.PtraceEnabled = false
	ccIdle := findDomain(t, buildLinuxDomains(caps), "Command Control")
	if got := ComputeScore([]ProtectionDomain{ccIdle}); got != 0 {
		t.Errorf("Command Control should score 0 when ptrace is present but not enabled; got %d", got)
	}

	// ptrace actively enforcing (capability present AND enabled) keeps the weight.
	caps.PtraceEnabled = true
	ccActive := findDomain(t, buildLinuxDomains(caps), "Command Control")
	if got := ComputeScore([]ProtectionDomain{ccActive}); got != WeightCommandControl {
		t.Errorf("Command Control should score %d when ptrace is actively enforcing; got %d", WeightCommandControl, got)
	}

	// Neither seccomp installable nor ptrace active -> score 0.
	caps.Ptrace = false
	caps.PtraceEnabled = false
	ccNone := findDomain(t, buildLinuxDomains(caps), "Command Control")
	if ComputeScore([]ProtectionDomain{ccNone}) != 0 {
		t.Error("Command Control should score 0 when neither seccomp-execve nor ptrace is active")
	}
}
```

**(c)** In `TestApplyWrapperAvailability_Missing`, add `PtraceEnabled: true` to the caps literal (currently lines 80-88) so the ptrace backend is actually-enforcing and the existing "ptrace remains available when wrapper missing" assertion (lines 106-108) still holds (ptrace is not wrapper-dependent):

```go
	caps := &SecurityCapabilities{
		Seccomp:            true,
		SeccompInstallable: true,
		Landlock:           true,
		LandlockABI:        5,
		LandlockNetwork:    true,
		FUSE:               true,
		Ptrace:             true,
		PtraceEnabled:      true,
	}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/capabilities/ -run 'TestBuildLinuxDomains|TestApplyWrapperAvailability_Missing' -v`
Expected: FAIL —
- `TestBuildLinuxDomains_PtraceBackendReflectsEnforcement`: ptrace backend currently `Available: caps.Ptrace` (true even when not enabled) and `Detail` empty.
- `TestBuildLinuxDomains_CommandActivePriority`: `Active` currently hard-wired to `"seccomp-execve"`.
- `TestBuildLinuxDomains_SeccompInstallFalseFlipsVerdictAndScore`: idle-ptrace case currently scores 25, not 0.
- (`TestApplyWrapperAvailability_Missing` compiles and still passes — it's adjusted to stay green once the impl lands.)

- [ ] **Step 3: Add the `ptraceBackendDetail` helper**

In `internal/capabilities/detect_linux.go`, after `seccompBackendDetail` (ends line 45), add:

```go
// ptraceBackendDetail explains the ptrace Command Control backend's verdict.
// ptrace enforcement is opt-in (config: sandbox ptrace mode), and detect is
// config-agnostic, so on most hosts this reports the capability as
// present-but-not-active. The capability itself stays visible in the flat
// CAPABILITIES section (caps.Ptrace, via backwardCompatCaps). Issue #390.
func ptraceBackendDetail(caps *SecurityCapabilities) string {
	if caps.Ptrace && caps.PtraceEnabled {
		return "" // actively enforcing; the ✓ speaks for itself
	}
	if caps.Ptrace {
		return "available, not active (enable ptrace mode)"
	}
	return "" // capability absent; the - speaks for itself
}
```

- [ ] **Step 4: Make `commandActive` priority-based**

In `internal/capabilities/detect_linux.go`, replace the current `commandActive` block (lines 65-69):

```go
	mode := caps.SelectMode()
	commandActive := "seccomp-execve"
	if mode == ModePtrace {
		commandActive = "ptrace"
	}
```

with a priority chain mirroring the `networkActive` block below it:

```go
	mode := caps.SelectMode()
	commandActive := ""
	if caps.SeccompInstallable {
		commandActive = "seccomp-execve"
	} else if mode == ModePtrace {
		commandActive = "ptrace"
	}
```

- [ ] **Step 5: Make the ptrace backend reflect actual enforcement**

In `internal/capabilities/detect_linux.go`, in the Command Control domain (line 113), change the ptrace backend from:

```go
				{Name: "ptrace", Available: caps.Ptrace, Detail: "", Description: "syscall tracing", CheckMethod: "probe"},
```

to:

```go
				{Name: "ptrace", Available: caps.Ptrace && caps.PtraceEnabled, Detail: ptraceBackendDetail(caps), Description: "syscall tracing", CheckMethod: "probe"},
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/capabilities/ -run 'TestBuildLinuxDomains|TestApplyWrapperAvailability' -v`
Expected: PASS (new tests, rewritten score test, and both wrapper-availability tests).

- [ ] **Step 7: Commit**

```bash
git add internal/capabilities/detect_linux.go internal/capabilities/detect_linux_test.go
git commit -m "$(cat <<'EOF'
fix(#390): Command Control reflects actual enforcement in detect

The ptrace backend's Available now tracks actual enforcement
(Ptrace && PtraceEnabled) rather than mere capability, and commandActive
falls back by priority (seccomp-execve if installable -> ptrace if mode
ptrace -> none). With both Command Control backends honest, the existing
any-backend ComputeScore yields 0/25 on hosts where seccomp can't install
and ptrace isn't engaged. ptrace capability stays visible in CAPABILITIES.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Whole-suite verification and cross-compile

**Files:** none (verification only)

- [ ] **Step 1: Run the capabilities and server suites**

Run: `go test ./internal/capabilities/... ./internal/server/...`
Expected: PASS (no regressions in validate, detect, config-generator, or security tests).

- [ ] **Step 2: Build everything (native)**

Run: `go build ./...`
Expected: success, no output.

- [ ] **Step 3: Verify Windows cross-compile**

Run: `GOOS=windows go build ./...`
Expected: success (changed files are `//go:build linux`; darwin/windows builders untouched).

- [ ] **Step 4: Sanity-check detect output on this host**

Run: `go run ./cmd/agentsh detect`
Expected: the `COMMAND CONTROL` domain's `ptrace` row shows `-  available, not active (enable ptrace mode)`; if this host's seccomp install probe succeeds, `seccomp-execve` shows `✓` and `active backend: seccomp-execve` with `25/25`; if it fails, `seccomp-execve` shows `-`, no `active backend` line, and Command Control is `0/25`. `CAPABILITIES` still lists `ptrace ✓`.

- [ ] **Step 5: Commit (only if Step 4 surfaced a doc/comment tweak; otherwise skip)**

No code change expected here. If a comment/detail string needed adjusting, commit it with an explicit `git add` of just that file.

---

## Self-Review

**1. Spec coverage:**
- SelectMode consumes `SeccompInstallable` → Task 1. ✓
- `commandActive` priority chain → Task 2 Step 4. ✓
- ptrace backend `Available` = actual enforcement + explanatory `Detail` → Task 2 Steps 3 & 5. ✓
- `ComputeScore` unchanged, Daytona → CC 0/25 → verified by the rewritten score test (Task 2 Step 1b) and the detect sanity check (Task 3 Step 4). ✓
- darwin/windows builders + runtime install path untouched → no task modifies them; cross-compile verified (Task 3 Step 3). ✓
- ptrace capability stays in `CAPABILITIES` → unchanged `backwardCompatCaps`; asserted indirectly by existing `TestDetect_Linux` capability-key check and the Task 3 sanity check. ✓
- Behavior change (honest mode / strict fail-fast) → falls out of the SelectMode change; existing `validate_test.go` passes explicit modes so stays green (Task 3 Step 1). ✓

**2. Placeholder scan:** No TBD/TODO; every code step shows complete code and exact commands. ✓

**3. Type consistency:** `ptraceBackendDetail(caps *SecurityCapabilities) string` matches the call site in Task 2 Step 5; `commandActive` remains a `string` assigned to the domain `Active`; `findDomain`/`findBackend` helpers already exist in `detect_linux_test.go:321-342`; `WeightCommandControl` is defined in `detect_result.go:66`. ✓
