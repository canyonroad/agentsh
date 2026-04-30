# Socket Family Blocking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-socket-family blocking to agentsh's sandbox: a YAML-configurable list of `AF_*` families whose `socket(2)`/`socketpair(2)` calls return `EAFNOSUPPORT` (or kill, log, log_and_kill). Two enforcement engines share the same config and types: seccomp-bpf primary, ptrace fallback when seccomp is unavailable.

**Architecture:** New `internal/seccomp/families.go` defines `BlockedFamily` + name↔number table + `DefaultBlockedFamilies()`. The seccomp engine (`internal/netmonitor/unix/seccomp_linux.go`) gets `AddRuleConditional` calls keyed on arg0. The ptrace engine (`internal/ptrace/family_checker.go`) gets a small checker invoked from the existing tracer dispatch. Config field on `SandboxSeccompConfig`. Spec: `docs/superpowers/specs/2026-04-29-socket-family-block-design.md`.

**Tech Stack:** Go 1.x, `github.com/seccomp/libseccomp-golang` (already a dep, used at `internal/seccomp/syscalls.go:8`), `golang.org/x/sys/unix`, internal `audit`/`config`/`server` packages.

---

## Conventions for every task

- Run all commands from `/home/eran/work/agentsh`. The brainstorming skill should have placed you in a worktree under `.claude/worktrees/<branch>/`; if so, run from there.
- Read the existing analogous code first when adding new code: `internal/netmonitor/unix/seccomp_linux.go::InstallFilterWithConfig` for seccomp rules, `internal/ptrace/static_policy.go` for ptrace patterns.
- Module path: `github.com/agentsh/agentsh` (verify with `head -1 go.mod`).
- Tab indentation; `gofmt -w` on touched files; `go vet ./...` clean before commit.
- Cross-compile gate per `CLAUDE.md`: `GOOS=windows go build ./...` after every Linux-only file change.
- Run `go test -race ./internal/seccomp/... ./internal/ptrace/... ./internal/netmonitor/unix/...` after engine changes.
- Don't `git add -A`. Add files explicitly per the commit step.
- Don't push.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/seccomp/families.go` (new) | `BlockedFamily` type, `nameTable`, `ParseFamily`, `DefaultBlockedFamilies` |
| `internal/seccomp/families_test.go` (new) | Table-driven tests for the above |
| `internal/seccomp/filter.go` (modify) | Add `BlockedFamilies` to `FilterConfig` + helper |
| `internal/seccomp/filter_test.go` (modify) | Tests for the helper |
| `internal/config/config.go` (modify) | Add `SandboxSeccompSocketFamilyConfig` + field on `SandboxSeccompConfig` + `applyDefaults` for it |
| `internal/config/seccomp_test.go` or similar (modify) | Default-merge + round-trip tests |
| `internal/netmonitor/unix/seccomp_linux.go` (modify) | Add per-family `AddRuleConditional` block + `blockedFamilyMap` |
| `internal/netmonitor/unix/seccomp_family_test.go` (new) | Real-process integration tests for seccomp engine |
| `internal/ptrace/family_checker.go` (new) | `FamilyChecker` type + `Check` + `Apply` |
| `internal/ptrace/family_checker_test.go` (new) | Unit tests with synthetic regs |
| `internal/ptrace/family_checker_integration_test.go` (new) | Real-tracee integration test |
| `internal/server/security.go` or `server.go` (modify) | Engine selection: seccomp vs ptrace vs warn |
| `cmd/agentsh-unixwrap/config.go` + `main.go` (modify) | Forward `BlockedFamilies` from JSON config to FilterConfig |

---

## Task 1: Define `BlockedFamily` type and family name table

**Files:**
- Create: `internal/seccomp/families.go`
- Create: `internal/seccomp/families_test.go`

- [ ] **Step 1: Read existing files for reference**

```bash
cat internal/seccomp/filter.go internal/seccomp/syscalls.go
```

- [ ] **Step 2: Write failing tests**

`internal/seccomp/families.go` will live in `package seccomp` (same as filter.go) with `//go:build linux && cgo`. The test file uses the same constraints.

`internal/seccomp/families_test.go`:

```go
//go:build linux && cgo

package seccomp

import (
	"testing"
)

func TestParseFamily_Names(t *testing.T) {
	cases := []struct {
		in     string
		wantNr int
	}{
		{"AF_ALG", 38},
		{"AF_VSOCK", 40},
		{"AF_RDS", 21},
		{"AF_TIPC", 30},
		{"AF_KCM", 41},
		{"AF_X25", 9},
		{"AF_AX25", 3},
		{"AF_NETROM", 6},
		{"AF_ROSE", 11},
		{"AF_DECnet", 12},
		{"AF_APPLETALK", 5},
		{"AF_IPX", 4},
		{"AF_INET", 2},
		{"AF_INET6", 10},
		{"AF_UNIX", 1},
		{"AF_NETLINK", 16},
		{"AF_PACKET", 17},
		{"AF_BLUETOOTH", 31},
		{"AF_CAN", 29},
	}
	for _, c := range cases {
		nr, name, ok := ParseFamily(c.in)
		if !ok {
			t.Errorf("ParseFamily(%q): ok=false, want true", c.in)
			continue
		}
		if nr != c.wantNr {
			t.Errorf("ParseFamily(%q): nr=%d, want %d", c.in, nr, c.wantNr)
		}
		if name != c.in {
			t.Errorf("ParseFamily(%q): name=%q, want %q", c.in, name, c.in)
		}
	}
}

func TestParseFamily_NumericFallback(t *testing.T) {
	nr, name, ok := ParseFamily("38")
	if !ok || nr != 38 || name != "" {
		t.Errorf("ParseFamily(\"38\"): got (%d, %q, %v), want (38, \"\", true)", nr, name, ok)
	}
	nr, _, ok = ParseFamily("63") // upper edge of valid range
	if !ok || nr != 63 {
		t.Errorf("ParseFamily(\"63\"): got (%d, _, %v), want (63, _, true)", nr, ok)
	}
}

func TestParseFamily_Invalid(t *testing.T) {
	cases := []string{"", "AF_ALGOG", "AF_NOT_A_THING", "-1", "64", "1000", "abc"}
	for _, in := range cases {
		if _, _, ok := ParseFamily(in); ok {
			t.Errorf("ParseFamily(%q): ok=true, want false", in)
		}
	}
}

func TestDefaultBlockedFamilies(t *testing.T) {
	defaults := DefaultBlockedFamilies()
	if len(defaults) == 0 {
		t.Fatal("DefaultBlockedFamilies returned empty list")
	}
	// AF_ALG must be in defaults — copy.fail mitigation.
	found := false
	for _, bf := range defaults {
		if bf.Name == "AF_ALG" && bf.Family == 38 {
			found = true
			if bf.Action != OnBlockErrno {
				t.Errorf("AF_ALG default action = %s, want errno", bf.Action)
			}
		}
	}
	if !found {
		t.Error("AF_ALG missing from DefaultBlockedFamilies")
	}
	// All defaults must use errno.
	for _, bf := range defaults {
		if bf.Action != OnBlockErrno {
			t.Errorf("default %s action = %s, want errno", bf.Name, bf.Action)
		}
	}
}
```

- [ ] **Step 3: Run tests; expect compile failure**

```bash
go test ./internal/seccomp/ -run "TestParseFamily|TestDefaultBlockedFamilies" -v
```

Expected: build failure (`undefined: ParseFamily`, etc.).

- [ ] **Step 4: Implement `families.go`**

`internal/seccomp/families.go`:

```go
//go:build linux && cgo

package seccomp

import "strconv"

// BlockedFamily is one entry on the blocked_socket_families list.
type BlockedFamily struct {
	Family int           // resolved AF_* number
	Action OnBlockAction // errno|kill|log|log_and_kill
	Name   string        // original config name; "" if numeric
}

// nameTable maps human-readable AF_* names to their kernel numbers.
// New families need a code update — kernel adds them rarely.
var nameTable = map[string]int{
	"AF_UNIX":      1,
	"AF_INET":      2,
	"AF_AX25":      3,
	"AF_IPX":       4,
	"AF_APPLETALK": 5,
	"AF_NETROM":    6,
	"AF_X25":       9,
	"AF_INET6":     10,
	"AF_ROSE":      11,
	"AF_DECnet":    12,
	"AF_NETLINK":   16,
	"AF_PACKET":    17,
	"AF_RDS":       21,
	"AF_CAN":       29,
	"AF_TIPC":      30,
	"AF_BLUETOOTH": 31,
	"AF_ALG":       38,
	"AF_VSOCK":     40,
	"AF_KCM":       41,
}

// ParseFamily resolves a config value (name string or numeric string) to
// its AF_* int. Returns ok=false if the value is neither a known name
// nor a parseable integer in [0, 64).
//
// On numeric input, name is returned as "" so callers can preserve the
// fact that the operator chose a number.
func ParseFamily(value string) (nr int, name string, ok bool) {
	if value == "" {
		return 0, "", false
	}
	if n, found := nameTable[value]; found {
		return n, value, true
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, "", false
	}
	if parsed < 0 || parsed >= 64 {
		// AF_MAX is currently 47 in mainline; 64 leaves headroom but
		// rejects clearly-bogus values like 1000.
		return 0, "", false
	}
	return parsed, "", true
}

// DefaultBlockedFamilies returns the recommended-default list applied
// when blocked_socket_families is unset in config. Each entry uses
// OnBlockErrno (returns EAFNOSUPPORT to userspace).
//
// Rationale per docs/superpowers/specs/2026-04-29-socket-family-block-design.md.
func DefaultBlockedFamilies() []BlockedFamily {
	names := []string{
		"AF_ALG", "AF_VSOCK", "AF_RDS", "AF_TIPC", "AF_KCM",
		"AF_X25", "AF_AX25", "AF_NETROM", "AF_ROSE", "AF_DECnet",
		"AF_APPLETALK", "AF_IPX",
	}
	out := make([]BlockedFamily, 0, len(names))
	for _, n := range names {
		out = append(out, BlockedFamily{
			Family: nameTable[n],
			Action: OnBlockErrno,
			Name:   n,
		})
	}
	return out
}
```

- [ ] **Step 5: Run tests; expect pass**

```bash
go test ./internal/seccomp/ -run "TestParseFamily|TestDefaultBlockedFamilies" -v
```

Expected: all tests pass.

- [ ] **Step 6: Cross-compile check**

```bash
GOOS=windows go build ./...
```

Expected: clean (no output).

- [ ] **Step 7: Commit**

```bash
git add internal/seccomp/families.go internal/seccomp/families_test.go
git commit -m "feat(seccomp): BlockedFamily type and AF_* name table

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 2: Wire `BlockedFamilies` into `FilterConfig`

**Files:**
- Modify: `internal/seccomp/filter.go`
- Modify: `internal/seccomp/filter_test.go`

- [ ] **Step 1: Read current filter.go**

```bash
cat internal/seccomp/filter.go
```

Confirms shape: `FilterConfig { UnixSocketEnabled bool; BlockedSyscalls []string; OnBlock OnBlockAction }` and `FilterConfigFromYAML(unixEnabled, blockedSyscalls, onBlock)`.

- [ ] **Step 2: Write failing test**

Append to `internal/seccomp/filter_test.go`:

```go
func TestFilterConfig_IncludesBlockedFamilies(t *testing.T) {
	cfg := FilterConfig{
		UnixSocketEnabled: false,
		BlockedSyscalls:   nil,
		BlockedFamilies: []BlockedFamily{
			{Family: 38, Action: OnBlockErrno, Name: "AF_ALG"},
		},
		OnBlock: OnBlockErrno,
	}
	if len(cfg.BlockedFamilies) != 1 {
		t.Fatalf("expected 1 family, got %d", len(cfg.BlockedFamilies))
	}
	if cfg.BlockedFamilies[0].Name != "AF_ALG" {
		t.Errorf("name=%q want AF_ALG", cfg.BlockedFamilies[0].Name)
	}
}

func TestFilterConfigFromYAML_PassesFamilies(t *testing.T) {
	families := []BlockedFamily{
		{Family: 38, Action: OnBlockErrno, Name: "AF_ALG"},
	}
	cfg := FilterConfigFromYAML(true, []string{"ptrace"}, "errno", families)
	if len(cfg.BlockedFamilies) != 1 || cfg.BlockedFamilies[0].Family != 38 {
		t.Errorf("FilterConfigFromYAML did not pass families through: %+v", cfg.BlockedFamilies)
	}
}
```

- [ ] **Step 3: Run; expect compile failure**

```bash
go test ./internal/seccomp/ -run "TestFilterConfig_IncludesBlockedFamilies|TestFilterConfigFromYAML_PassesFamilies" -v
```

Expected: build error (`unknown field BlockedFamilies` and arity mismatch on `FilterConfigFromYAML`).

- [ ] **Step 4: Modify `internal/seccomp/filter.go`**

Replace the `FilterConfig` struct and `FilterConfigFromYAML` signature:

```go
// FilterConfig holds settings for building a seccomp filter.
type FilterConfig struct {
	UnixSocketEnabled bool
	BlockedSyscalls   []string
	BlockedFamilies   []BlockedFamily
	OnBlock           OnBlockAction
}

// FilterConfigFromYAML creates a FilterConfig from config package types.
// This is a separate function to avoid import cycles.
func FilterConfigFromYAML(unixEnabled bool, blockedSyscalls []string, onBlock string, blockedFamilies []BlockedFamily) FilterConfig {
	action, _ := ParseOnBlock(onBlock)
	return FilterConfig{
		UnixSocketEnabled: unixEnabled,
		BlockedSyscalls:   blockedSyscalls,
		BlockedFamilies:   blockedFamilies,
		OnBlock:           action,
	}
}
```

- [ ] **Step 5: Update existing callers of `FilterConfigFromYAML`**

Find callers:

```bash
grep -rn "FilterConfigFromYAML(" --include="*.go"
```

For each caller, add a `nil` argument as the new `blockedFamilies` parameter. Likely callers are in `internal/api/seccomp_wrapper_config.go` and `cmd/agentsh-unixwrap/main.go` and possibly tests. Pass `nil` for now — Tasks 6–7 will wire real values.

- [ ] **Step 6: Run filter package tests**

```bash
go test ./internal/seccomp/ -v
```

Expected: all pass (existing tests + 2 new).

- [ ] **Step 7: Run full build**

```bash
go build ./...
GOOS=windows go build ./...
```

Both clean.

- [ ] **Step 8: Commit**

```bash
git add internal/seccomp/filter.go internal/seccomp/filter_test.go internal/api/seccomp_wrapper_config.go cmd/agentsh-unixwrap/main.go
git commit -m "feat(seccomp): wire BlockedFamilies through FilterConfig

Callers pass nil; later tasks populate real values.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

If you didn't have to touch some of those files (because they don't actually call `FilterConfigFromYAML`), drop them from the `git add` line.

---

## Task 3: Config schema — `SandboxSeccompSocketFamilyConfig`

**Files:**
- Modify: `internal/config/config.go`
- Modify: a config test file (find with `grep -l "SandboxSeccompConfig\|SandboxSeccompSyscallConfig" internal/config/*_test.go`)

- [ ] **Step 1: Read the existing seccomp config block**

```bash
sed -n '482,520p' internal/config/config.go
```

Confirms `SandboxSeccompConfig` struct shape.

- [ ] **Step 2: Write failing tests**

Append to whichever test file owns seccomp config (likely `internal/config/config_test.go` or a dedicated `seccomp_test.go`):

```go
func TestSandboxSeccompSocketFamilyConfig_DefaultMerge(t *testing.T) {
	// When BlockedSocketFamilies is nil → defaults applied.
	cfg := &Config{}
	cfg.Sandbox.Seccomp.Enabled = true
	if err := cfg.applyDefaults(); err != nil {
		t.Fatalf("applyDefaults: %v", err)
	}
	if len(cfg.Sandbox.Seccomp.BlockedSocketFamilies) == 0 {
		t.Errorf("expected default-merge to populate BlockedSocketFamilies; got empty")
	}
	// AF_ALG must appear.
	found := false
	for _, e := range cfg.Sandbox.Seccomp.BlockedSocketFamilies {
		if e.Family == "AF_ALG" {
			found = true
			break
		}
	}
	if !found {
		t.Error("AF_ALG missing from default BlockedSocketFamilies")
	}
}

func TestSandboxSeccompSocketFamilyConfig_ExplicitEmptyOptOut(t *testing.T) {
	// When the operator sets blocked_socket_families: [] → opt-out.
	// Distinguish nil (unset, apply defaults) from empty (explicit opt-out).
	cfg := &Config{}
	cfg.Sandbox.Seccomp.Enabled = true
	cfg.Sandbox.Seccomp.BlockedSocketFamilies = []SandboxSeccompSocketFamilyConfig{} // explicit empty
	cfg.Sandbox.Seccomp.BlockedSocketFamiliesSet = true                              // sentinel
	if err := cfg.applyDefaults(); err != nil {
		t.Fatalf("applyDefaults: %v", err)
	}
	if len(cfg.Sandbox.Seccomp.BlockedSocketFamilies) != 0 {
		t.Errorf("explicit empty should not be replaced by defaults; got %v",
			cfg.Sandbox.Seccomp.BlockedSocketFamilies)
	}
}

func TestSandboxSeccompSocketFamilyConfig_NonEmptyOverridesDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.Sandbox.Seccomp.Enabled = true
	cfg.Sandbox.Seccomp.BlockedSocketFamiliesSet = true
	cfg.Sandbox.Seccomp.BlockedSocketFamilies = []SandboxSeccompSocketFamilyConfig{
		{Family: "AF_VSOCK", Action: "errno"},
	}
	if err := cfg.applyDefaults(); err != nil {
		t.Fatalf("applyDefaults: %v", err)
	}
	if len(cfg.Sandbox.Seccomp.BlockedSocketFamilies) != 1 {
		t.Errorf("non-empty should override defaults entirely; got %d entries",
			len(cfg.Sandbox.Seccomp.BlockedSocketFamilies))
	}
}
```

If the existing config tests use a different `Config` constructor / different `applyDefaults` entry point, adapt to whatever is real. The shape of the assertions is the right scope.

- [ ] **Step 3: Run; expect failure**

```bash
go test ./internal/config/ -run "TestSandboxSeccompSocketFamily" -v
```

Expected: build failure (`undefined: SandboxSeccompSocketFamilyConfig`).

- [ ] **Step 4: Add the config struct and field**

In `internal/config/config.go`, after `SandboxSeccompFileMonitorConfig` (around line 512), add:

```go
// SandboxSeccompSocketFamilyConfig describes one blocked socket family.
type SandboxSeccompSocketFamilyConfig struct {
	Family string `yaml:"family"` // AF_* name or numeric string
	Action string `yaml:"action"` // errno|kill|log|log_and_kill (defaults to errno)
}
```

In `SandboxSeccompConfig` struct (lines 482–489), add two fields:

```go
type SandboxSeccompConfig struct {
	Enabled     bool                            `yaml:"enabled"`
	Mode        string                          `yaml:"mode"`
	UnixSocket  SandboxSeccompUnixConfig        `yaml:"unix_socket"`
	Syscalls    SandboxSeccompSyscallConfig     `yaml:"syscalls"`
	Execve      ExecveConfig                    `yaml:"execve"`
	FileMonitor SandboxSeccompFileMonitorConfig `yaml:"file_monitor"`

	BlockedSocketFamilies    []SandboxSeccompSocketFamilyConfig `yaml:"blocked_socket_families"`
	// BlockedSocketFamiliesSet is internal — set by the YAML unmarshaler when
	// the field is present (even as []), so applyDefaults can distinguish
	// "unset → apply defaults" from "explicit empty → opt-out".
	BlockedSocketFamiliesSet bool `yaml:"-"`
}
```

For YAML unmarshal to correctly set `BlockedSocketFamiliesSet`, you need a custom `UnmarshalYAML` on `SandboxSeccompConfig`. The simplest approach: a sentinel through a parallel type. Look at how the codebase handles other "unset vs empty" distinctions; if there's an existing pattern (e.g., `*[]Foo` pointer), use it instead of the bool sentinel.

If `*[]SandboxSeccompSocketFamilyConfig` (pointer to slice) is the project's convention, adapt the design accordingly:

```go
BlockedSocketFamilies *[]SandboxSeccompSocketFamilyConfig `yaml:"blocked_socket_families,omitempty"`
```

…and the test/applyDefaults code uses `nil` vs `&[]{}` to distinguish. Pick whichever pattern matches existing code.

- [ ] **Step 5: Add default-merge in `applyDefaults`**

Find the relevant block (around line 1574–1605 — search for existing `Sandbox.Seccomp` defaults):

```bash
grep -n "Sandbox.Seccomp.Syscalls" internal/config/config.go | head
```

After the existing `Syscalls.Block` default-merge block, add:

```go
// Apply default blocked socket families when seccomp is enabled and the
// operator hasn't explicitly set the field. Unset → apply defaults.
// Explicit [] → opt-out (no defaults applied).
if seccompActive && !cfg.Sandbox.Seccomp.BlockedSocketFamiliesSet {
	for _, bf := range seccomp.DefaultBlockedFamilies() {
		cfg.Sandbox.Seccomp.BlockedSocketFamilies = append(
			cfg.Sandbox.Seccomp.BlockedSocketFamilies,
			SandboxSeccompSocketFamilyConfig{
				Family: bf.Name,
				Action: string(bf.Action),
			},
		)
	}
}
```

(`seccomp` import is `github.com/agentsh/agentsh/internal/seccomp`. Add the import if not already present in config.go.)

If the project uses the pointer-slice convention instead of a bool sentinel, replace `!cfg.Sandbox.Seccomp.BlockedSocketFamiliesSet` with `cfg.Sandbox.Seccomp.BlockedSocketFamilies == nil`, and update tests accordingly.

- [ ] **Step 6: Run tests; expect pass**

```bash
go test ./internal/config/ -run "TestSandboxSeccompSocketFamily" -v
```

- [ ] **Step 7: Run full config tests**

```bash
go test ./internal/config/ -v
```

Make sure no existing tests broke from the schema addition.

- [ ] **Step 8: Cross-compile**

```bash
GOOS=windows go build ./...
GOOS=darwin go build ./...
```

Both clean. (Config field is platform-neutral.)

- [ ] **Step 9: Commit**

```bash
git add internal/config/config.go internal/config/<test-file>.go
git commit -m "feat(config): blocked_socket_families with default-merge

Distinguishes unset (apply defaults) from explicit empty (opt-out).
Defaults from internal/seccomp.DefaultBlockedFamilies.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 4: Config validation — reject unknown family names

**Files:**
- Modify: `internal/config/config.go` (or wherever validation lives — find with `grep -n "func.*Validate\|return.*fmt.Errorf.*sandbox.seccomp" internal/config/*.go`)
- Modify: same test file as Task 3

- [ ] **Step 1: Write failing test**

```go
func TestSandboxSeccompSocketFamily_RejectsUnknownName(t *testing.T) {
	cfg := &Config{}
	cfg.Sandbox.Seccomp.Enabled = true
	cfg.Sandbox.Seccomp.BlockedSocketFamiliesSet = true
	cfg.Sandbox.Seccomp.BlockedSocketFamilies = []SandboxSeccompSocketFamilyConfig{
		{Family: "AF_NOT_REAL", Action: "errno"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for unknown family name")
	}
	if !strings.Contains(err.Error(), "AF_NOT_REAL") {
		t.Errorf("error should mention bad name; got %v", err)
	}
}

func TestSandboxSeccompSocketFamily_RejectsBadAction(t *testing.T) {
	cfg := &Config{}
	cfg.Sandbox.Seccomp.Enabled = true
	cfg.Sandbox.Seccomp.BlockedSocketFamiliesSet = true
	cfg.Sandbox.Seccomp.BlockedSocketFamilies = []SandboxSeccompSocketFamilyConfig{
		{Family: "AF_ALG", Action: "deny"}, // "deny" is not in the OnBlockAction enum
	}
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error for invalid action")
	}
}

func TestSandboxSeccompSocketFamily_AcceptsNumericFamily(t *testing.T) {
	cfg := &Config{}
	cfg.Sandbox.Seccomp.Enabled = true
	cfg.Sandbox.Seccomp.BlockedSocketFamiliesSet = true
	cfg.Sandbox.Seccomp.BlockedSocketFamilies = []SandboxSeccompSocketFamilyConfig{
		{Family: "38", Action: "errno"},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("numeric family should be accepted; got %v", err)
	}
}
```

Adapt to whatever the project's `Validate()` entry point is named.

- [ ] **Step 2: Run; expect failure**

```bash
go test ./internal/config/ -run "TestSandboxSeccompSocketFamily_Reject|TestSandboxSeccompSocketFamily_Accepts" -v
```

- [ ] **Step 3: Add validation**

In `Config.Validate()` (find with `grep -n "func.*Validate" internal/config/config.go | head`), add a block:

```go
// Validate blocked_socket_families entries.
for i, e := range cfg.Sandbox.Seccomp.BlockedSocketFamilies {
	if _, _, ok := seccomp.ParseFamily(e.Family); !ok {
		return fmt.Errorf("sandbox.seccomp.blocked_socket_families[%d].family: %q is not a valid AF_* name or number", i, e.Family)
	}
	if e.Action != "" {
		if _, ok := seccomp.ParseOnBlock(e.Action); !ok {
			return fmt.Errorf("sandbox.seccomp.blocked_socket_families[%d].action: %q is not valid (allowed: errno, kill, log, log_and_kill)", i, e.Action)
		}
	}
}
```

If the project's validation is split into multiple methods (e.g., `validateSandbox()`), put the block in the seccomp-relevant one.

- [ ] **Step 4: Run; expect pass**

```bash
go test ./internal/config/ -run "TestSandboxSeccompSocketFamily" -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/<test-file>.go
git commit -m "feat(config): validate blocked_socket_families entries

Reject unknown AF_* names and unknown actions at config-load time.
Numeric family values pass validation if in [0, 64).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 5: Convert config to `[]seccomp.BlockedFamily`

**Files:**
- Create: `internal/config/seccomp_families.go`
- Create: `internal/config/seccomp_families_test.go`

A small adapter function that converts the YAML-typed `[]SandboxSeccompSocketFamilyConfig` to the engine-typed `[]seccomp.BlockedFamily`. Lives in `internal/config` to avoid making `internal/seccomp` import config.

- [ ] **Step 1: Write failing test**

`internal/config/seccomp_families_test.go`:

```go
package config

import (
	"testing"

	"github.com/agentsh/agentsh/internal/seccomp"
)

func TestResolveBlockedFamilies(t *testing.T) {
	in := []SandboxSeccompSocketFamilyConfig{
		{Family: "AF_ALG", Action: "errno"},
		{Family: "40", Action: "kill"},
		{Family: "AF_VSOCK", Action: ""}, // empty action → defaults to errno
	}
	out, err := ResolveBlockedFamilies(in)
	if err != nil {
		t.Fatalf("ResolveBlockedFamilies: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("got %d entries, want 3", len(out))
	}
	if out[0].Family != 38 || out[0].Name != "AF_ALG" || out[0].Action != seccomp.OnBlockErrno {
		t.Errorf("entry 0 wrong: %+v", out[0])
	}
	if out[1].Family != 40 || out[1].Name != "" || out[1].Action != seccomp.OnBlockKill {
		t.Errorf("entry 1 wrong: %+v", out[1])
	}
	if out[2].Action != seccomp.OnBlockErrno {
		t.Errorf("entry 2 default action wrong: %s", out[2].Action)
	}
}

func TestResolveBlockedFamilies_RejectsBadEntry(t *testing.T) {
	in := []SandboxSeccompSocketFamilyConfig{
		{Family: "BOGUS", Action: "errno"},
	}
	_, err := ResolveBlockedFamilies(in)
	if err == nil {
		t.Errorf("expected error for bogus family name")
	}
}
```

- [ ] **Step 2: Run; expect failure**

```bash
go test ./internal/config/ -run "TestResolveBlockedFamilies" -v
```

- [ ] **Step 3: Implement the adapter**

`internal/config/seccomp_families.go`:

```go
package config

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/seccomp"
)

// ResolveBlockedFamilies converts YAML-typed entries into the engine-typed
// slice consumed by FilterConfigFromYAML / FamilyChecker. Empty Action
// defaults to errno. Caller should have run config validation first;
// this function returns an error if any entry fails to resolve, but it
// does not catch unknown-action strings (those degrade to errno via
// seccomp.ParseOnBlock).
func ResolveBlockedFamilies(in []SandboxSeccompSocketFamilyConfig) ([]seccomp.BlockedFamily, error) {
	out := make([]seccomp.BlockedFamily, 0, len(in))
	for i, e := range in {
		nr, name, ok := seccomp.ParseFamily(e.Family)
		if !ok {
			return nil, fmt.Errorf("blocked_socket_families[%d]: invalid family %q", i, e.Family)
		}
		actionStr := e.Action
		if actionStr == "" {
			actionStr = string(seccomp.OnBlockErrno)
		}
		action, _ := seccomp.ParseOnBlock(actionStr)
		out = append(out, seccomp.BlockedFamily{
			Family: nr,
			Action: action,
			Name:   name,
		})
	}
	return out, nil
}
```

- [ ] **Step 4: Run; expect pass**

```bash
go test ./internal/config/ -run "TestResolveBlockedFamilies" -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/config/seccomp_families.go internal/config/seccomp_families_test.go
git commit -m "feat(config): ResolveBlockedFamilies adapter

Converts YAML-typed entries to seccomp.BlockedFamily. Empty Action
defaults to errno.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 6: Seccomp engine — add per-family rules

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_linux.go`
- Create: `internal/netmonitor/unix/seccomp_family_test.go`

- [ ] **Step 1: Read the existing filter builder around lines 350–400**

```bash
sed -n '340,410p' internal/netmonitor/unix/seccomp_linux.go
```

Note: the file has `BlockedSyscalls`, `OnBlockAction`, and a `blockListMap` for notify-routing. Our family rules go AFTER the existing `BlockedSyscalls` block.

- [ ] **Step 2: Add `BlockedFamilies` to the local `FilterConfig`**

Around line 217 in `seccomp_linux.go`:

```go
type FilterConfig struct {
	UnixSocketEnabled  bool
	ExecveEnabled      bool
	FileMonitorEnabled bool
	InterceptMetadata  bool
	BlockIOUring       bool
	BlockedSyscalls    []int
	BlockedFamilies    []seccompkg.BlockedFamily  // NEW
	OnBlockAction      seccompkg.OnBlockAction
}
```

- [ ] **Step 3: Add a per-family map for notify routing**

Find the existing `blockListMap` declaration (line 357 from grep earlier) and add a sibling:

```go
blockListMap := map[uint32]seccompkg.OnBlockAction{}
blockedFamilyMap := map[uint64]seccompkg.BlockedFamily{}  // key = (syscall<<32) | family
```

If `blockListMap` is exposed via a getter for the userspace handler, add the equivalent getter for `blockedFamilyMap`. Inspect the file to see how `blockListMap` is exposed (likely returned as part of the `*Filter` struct).

- [ ] **Step 4: Add the family-rule installation block**

After the existing `BlockedSyscalls` switch block (line ~379), add:

```go
// Per-socket-family blocking on socket(2) and socketpair(2).
// libseccomp action-precedence (KILL > TRAP > ERRNO > … > NOTIFY) ensures
// these conditional rules take priority over the unconditional ActNotify
// rule on socket(2) added by UnixSocketEnabled.
for _, bf := range cfg.BlockedFamilies {
	cond := seccomp.ScmpCondition{
		Argument: 0,
		Op:       seccomp.CompareEqual,
		Operand1: uint64(bf.Family),
	}
	famAction, err := familyToScmpAction(bf.Action)
	if err != nil {
		slog.Warn("seccomp: skipping family rule with unknown action",
			"family", bf.Name, "action", bf.Action, "error", err)
		continue
	}
	for _, sc := range []uint{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR} {
		if err := filt.AddRuleConditional(
			seccomp.ScmpSyscall(sc), famAction, []seccomp.ScmpCondition{cond},
		); err != nil {
			slog.Warn("seccomp: failed to add family rule; family skipped",
				"family", bf.Name, "syscall", sc, "error", err)
			continue
		}
	}
	if bf.Action == seccompkg.OnBlockLog || bf.Action == seccompkg.OnBlockLogAndKill {
		blockedFamilyMap[uint64(unix.SYS_SOCKET)<<32|uint64(bf.Family)] = bf
		blockedFamilyMap[uint64(unix.SYS_SOCKETPAIR)<<32|uint64(bf.Family)] = bf
	}
}
```

Add the helper near the bottom of the file:

```go
// familyToScmpAction maps an OnBlockAction to the libseccomp action used
// for per-family rules.
func familyToScmpAction(a seccompkg.OnBlockAction) (seccomp.ScmpAction, error) {
	switch a {
	case seccompkg.OnBlockErrno:
		return seccomp.ActErrno.SetReturnCode(int16(unix.EAFNOSUPPORT)), nil
	case seccompkg.OnBlockKill:
		return seccomp.ActKillProcess, nil
	case seccompkg.OnBlockLog, seccompkg.OnBlockLogAndKill:
		return seccomp.ActNotify, nil
	default:
		return seccomp.ActAllow, fmt.Errorf("unknown action %q", a)
	}
}
```

- [ ] **Step 5: Write integration test**

`internal/netmonitor/unix/seccomp_family_test.go`:

```go
//go:build linux && cgo

package unix

import (
	"errors"
	"os/exec"
	"runtime"
	"syscall"
	"testing"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"golang.org/x/sys/unix"
)

// TestSeccomp_FamilyBlock_Errno spawns a child process under a filter
// that errnos AF_ALG, then asserts a socket(AF_ALG) call returns
// EAFNOSUPPORT.
func TestSeccomp_FamilyBlock_Errno(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	// Use exec.Command + a small Go helper that calls socket(AF_ALG).
	// Build the helper at test time. Skip if uname doesn't allow filter
	// installation.
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp filter not supported: %v", err)
	}

	// Inline the test in the current process by installing the filter
	// before forking. Use unix.RawSyscall directly so we don't go
	// through libc.
	cmd := exec.Command("/bin/sh", "-c", `
		exec /proc/self/exe -test.run=helperFamilyAFALG
	`)
	cmd.Env = append(cmd.Env, "FAMILY_TEST_HELPER=1")
	out, _ := cmd.CombinedOutput()
	t.Logf("child output: %s", out)
	// We expect the child to print "EAFNOSUPPORT" if our filter worked.
	// (Implementation detail: this depends on a TestMain helper —
	// alternative is to use syscall.ForkExec with a custom child entry.)
}

// helperFamilyAFALG is invoked inside the child process when
// FAMILY_TEST_HELPER is set. It installs the filter, calls socket(AF_ALG),
// prints the result, and exits.
//
// (For implementation: the cleaner pattern in this codebase is to put
// the helper in a separate test main — see internal/seccomp/integration_test.go
// for an existing example to model on. Adapt the helper structure to whatever
// the existing tests use.)
```

The actual test mechanics depend on how the existing seccomp integration tests are structured. Look at `internal/seccomp/integration_test.go` (already exists) for the helper pattern and **mirror it**. The key assertions:

1. With `BlockedFamilies: [{AF_ALG, errno}]` and the filter installed, `socket(AF_ALG, SOCK_SEQPACKET, 0)` returns errno `EAFNOSUPPORT` (97).
2. With `BlockedFamilies: [{AF_ALG, kill}]`, the child process gets killed (waitpid reports SIGSYS or kill signal).
3. With **both** `UnixSocketEnabled: true` AND `BlockedFamilies: [{AF_ALG, errno}]`, `socket(AF_UNIX, …)` succeeds (notify path) and `socket(AF_ALG, …)` returns EAFNOSUPPORT (errno path takes precedence over notify).

Use the existing test framework's helpers; don't reinvent forking infrastructure.

- [ ] **Step 6: Run integration test**

```bash
sudo go test ./internal/netmonitor/unix/ -run "TestSeccomp_FamilyBlock" -v
```

(Many seccomp tests need privileges. If they don't, drop `sudo`.)

Expected: tests pass.

- [ ] **Step 7: Update `cmd/agentsh-unixwrap` to forward families**

Find where `FilterConfig` is constructed in `cmd/agentsh-unixwrap/main.go` (around line 64):

```bash
sed -n '60,90p' cmd/agentsh-unixwrap/main.go
```

Add the family forwarding:

```go
// In the config struct (cmd/agentsh-unixwrap/config.go):
type WrapperConfig struct {
	UnixSocketEnabled bool                      `json:"unix_socket_enabled"`
	BlockedSyscalls   []string                  `json:"blocked_syscalls"`
	BlockedFamilies   []seccompkg.BlockedFamily `json:"blocked_families"`
	OnBlock           string                    `json:"on_block"`
	// ... existing fields
}

// In main.go, when populating the netmonitor FilterConfig:
filterCfg := unixfm.FilterConfig{
	UnixSocketEnabled: cfg.UnixSocketEnabled,
	BlockedSyscalls:   blockedNrs,
	BlockedFamilies:   cfg.BlockedFamilies, // forward as-is
	OnBlockAction:     /* existing */,
}
```

Then update `internal/api/seccomp_wrapper_config.go` (which composes the JSON sent to unixwrap from the YAML config) to add `BlockedFamilies` from `ResolveBlockedFamilies(cfg.Sandbox.Seccomp.BlockedSocketFamilies)`.

- [ ] **Step 8: Cross-compile + tests**

```bash
go build ./...
GOOS=windows go build ./...
go test ./internal/seccomp/... ./internal/netmonitor/unix/... ./internal/config/... ./cmd/agentsh-unixwrap/...
```

All pass.

- [ ] **Step 9: Commit**

```bash
git add internal/netmonitor/unix/seccomp_linux.go internal/netmonitor/unix/seccomp_family_test.go cmd/agentsh-unixwrap/config.go cmd/agentsh-unixwrap/main.go internal/api/seccomp_wrapper_config.go
git commit -m "feat(seccomp): per-family rules on socket(2)/socketpair(2)

AddRuleConditional with arg0 == family. EAFNOSUPPORT for errno action;
ActKillProcess for kill; ActNotify+blockedFamilyMap for log variants.
Coexists with UnixSocketEnabled via libseccomp action-precedence.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 7: Audit event for log/log_and_kill family attempts

**Files:**
- Modify: `internal/netmonitor/unix/<wherever the notify handler dispatches blocklist events>` — find with `grep -n "blockListMap\|BlockListMap\|seccomp.syscall_blocked" --include='*.go' -r internal/`
- Create or modify a test in the same package

The existing notify handler reads `blockListMap` to emit `seccomp.syscall_blocked` audit events for log-action syscall blocks. Adding family events follows the same path.

- [ ] **Step 1: Find the notify handler**

```bash
grep -rn "blockListMap\|seccomp.syscall_blocked" --include="*.go" internal/
```

Locate the function that processes a notify message and dispatches the audit event.

- [ ] **Step 2: Write failing test**

Adapt to the existing test pattern. Roughly:

```go
func TestNotifyHandler_FamilyAuditEvent(t *testing.T) {
	// Construct a FilterConfig with BlockedFamilies=[{AF_ALG, log}].
	// Spawn a tracee that calls socket(AF_ALG).
	// Assert exactly one audit event of kind seccomp.socket_family_blocked
	// with family_name=AF_ALG, family_number=38, syscall=socket, engine=seccomp.
}
```

- [ ] **Step 3: Implement event emission**

In the notify handler, after the existing `blockListMap` check, add a parallel lookup:

```go
key := uint64(req.Data.Nr)<<32 | uint64(req.Data.Args[0])
if bf, ok := filt.BlockedFamilyMap[key]; ok {
	auditSink.Emit(ctx, audit.Event{
		Kind: "seccomp.socket_family_blocked",
		Fields: map[string]any{
			"family_name":   bf.Name,
			"family_number": bf.Family,
			"syscall":       syscallName(req.Data.Nr),
			"action":        string(bf.Action),
			"engine":        "seccomp",
			"pid":           int(req.Pid),
		},
	})
	if bf.Action == seccompkg.OnBlockLogAndKill {
		// Send SIGKILL to the tracee.
	} else {
		// Allow the syscall.
	}
	return
}
```

Adapt the exact field names and audit-event API to whatever the codebase already uses for `seccomp.syscall_blocked`.

- [ ] **Step 4: Run test; expect pass**

- [ ] **Step 5: Commit**

```bash
git add <files>
git commit -m "feat(seccomp): emit seccomp.socket_family_blocked audit event

Dispatched from the notify handler when a log/log_and_kill family
attempt fires. Mirrors the existing syscall_blocked event shape.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 8: ptrace `FamilyChecker` (unit-level)

**Files:**
- Create: `internal/ptrace/family_checker.go`
- Create: `internal/ptrace/family_checker_test.go`

- [ ] **Step 1: Read existing ptrace patterns**

```bash
cat internal/ptrace/static_policy.go | head -80
ls internal/ptrace/ | head
```

Note the `arg0` extraction differs by arch — `internal/ptrace/args_amd64.go` and `args_arm64.go` exist for this.

- [ ] **Step 2: Write failing tests**

`internal/ptrace/family_checker_test.go`:

```go
//go:build linux

package ptrace

import (
	"testing"

	"github.com/agentsh/agentsh/internal/seccomp"
	"golang.org/x/sys/unix"
)

func TestFamilyChecker_Check_MatchAndMiss(t *testing.T) {
	c := NewFamilyChecker([]seccomp.BlockedFamily{
		{Family: 38, Action: seccomp.OnBlockErrno, Name: "AF_ALG"},
	})

	// AF_ALG on socket(2) → match.
	bf, ok := c.Check(uint64(unix.SYS_SOCKET), 38)
	if !ok || bf.Name != "AF_ALG" {
		t.Errorf("expected match for AF_ALG on SYS_SOCKET; got bf=%+v ok=%v", bf, ok)
	}

	// AF_INET on socket(2) → miss.
	if _, ok := c.Check(uint64(unix.SYS_SOCKET), 2); ok {
		t.Errorf("expected miss for AF_INET")
	}

	// AF_ALG on read(2) → miss (only socket/socketpair are checked).
	if _, ok := c.Check(uint64(unix.SYS_READ), 38); ok {
		t.Errorf("expected miss for AF_ALG on SYS_READ")
	}
}

func TestFamilyChecker_Check_Socketpair(t *testing.T) {
	c := NewFamilyChecker([]seccomp.BlockedFamily{
		{Family: 38, Action: seccomp.OnBlockErrno, Name: "AF_ALG"},
	})
	_, ok := c.Check(uint64(unix.SYS_SOCKETPAIR), 38)
	if !ok {
		t.Errorf("expected match for AF_ALG on SYS_SOCKETPAIR")
	}
}

func TestFamilyChecker_Empty(t *testing.T) {
	c := NewFamilyChecker(nil)
	if _, ok := c.Check(uint64(unix.SYS_SOCKET), 38); ok {
		t.Errorf("empty checker should never match")
	}
}
```

- [ ] **Step 3: Run; expect compile failure**

- [ ] **Step 4: Implement `family_checker.go`**

```go
//go:build linux

package ptrace

import (
	"github.com/agentsh/agentsh/internal/seccomp"
	"golang.org/x/sys/unix"
)

// FamilyChecker matches socket(2)/socketpair(2) calls against a list of
// blocked AF_* families. Reuses the same []seccomp.BlockedFamily slice
// that the seccomp engine consumes — single source of truth.
type FamilyChecker struct {
	// bySyscall: SYS_SOCKET / SYS_SOCKETPAIR → family number → entry.
	bySyscall map[uint64]map[uint64]seccomp.BlockedFamily
}

// NewFamilyChecker indexes the entries for fast lookup. nil/empty input
// produces a checker that never matches.
func NewFamilyChecker(entries []seccomp.BlockedFamily) *FamilyChecker {
	c := &FamilyChecker{bySyscall: map[uint64]map[uint64]seccomp.BlockedFamily{}}
	for _, sc := range []uint64{uint64(unix.SYS_SOCKET), uint64(unix.SYS_SOCKETPAIR)} {
		c.bySyscall[sc] = map[uint64]seccomp.BlockedFamily{}
	}
	for _, e := range entries {
		for sc := range c.bySyscall {
			c.bySyscall[sc][uint64(e.Family)] = e
		}
	}
	return c
}

// Check reports the BlockedFamily entry for a given syscall+arg0 pair.
// ok=false means no rule applies (the syscall should be allowed).
func (c *FamilyChecker) Check(syscall, arg0 uint64) (seccomp.BlockedFamily, bool) {
	if c == nil || c.bySyscall == nil {
		return seccomp.BlockedFamily{}, false
	}
	families, ok := c.bySyscall[syscall]
	if !ok {
		return seccomp.BlockedFamily{}, false
	}
	bf, ok := families[arg0]
	return bf, ok
}
```

- [ ] **Step 5: Run; expect pass**

```bash
go test ./internal/ptrace/ -run TestFamilyChecker -v
```

- [ ] **Step 6: Commit**

```bash
git add internal/ptrace/family_checker.go internal/ptrace/family_checker_test.go
git commit -m "feat(ptrace): FamilyChecker for socket-family blocking

Indexes []seccomp.BlockedFamily by syscall+family for fast lookup at
syscall-entry stops. Pure logic; no ptrace integration yet.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 9: ptrace integration — wire `FamilyChecker` into the tracer

**Files:**
- Modify: `internal/ptrace/tracer.go` (or wherever the syscall-entry callback dispatches handlers — verify with `grep -n "syscall.*entry\|HandleSyscall\|^func.*Tracer" internal/ptrace/tracer.go`)
- Modify: `internal/ptrace/family_checker.go` — add `Apply` method
- Create: `internal/ptrace/family_checker_integration_test.go`

- [ ] **Step 1: Find the syscall dispatch site**

```bash
grep -n "syscall\|Handler\|callback" internal/ptrace/tracer.go | head -20
```

Identify where the tracer reads `regs` at SYSCALL_ENTRY and decides what to do.

- [ ] **Step 2: Write failing integration test**

The existing `internal/ptrace/syscalls_test.go` and `static_policy_test.go` show how the project tests ptrace flows. Mirror that pattern. Test asserts: under a Tracer configured with `FamilyChecker(AF_ALG, errno)`, a tracee calling `socket(AF_ALG, ...)` gets `errno=EAFNOSUPPORT`.

The exact code depends heavily on existing test helpers; don't try to author it without reading them first.

- [ ] **Step 3: Add `Apply` to `FamilyChecker`**

`internal/ptrace/family_checker.go` — append:

```go
// Apply executes the action against a stopped tracee. Caller has already
// matched via Check. Returns nil on success, or an error if the
// underlying ptrace operations fail.
//
// errno: SetRegs RAX = -EAFNOSUPPORT, ORIG_RAX = -1 (skip syscall).
//        Caller continues with PTRACE_SYSEMU or equivalent.
// kill:  return PtraceKillRequested so the caller drives PTRACE_KILL.
// log:   emit audit event; allow syscall to proceed.
// log_and_kill: emit audit + return PtraceKillRequested.
//
// PtraceKillRequested is a sentinel error so callers can distinguish
// "killed intentionally" from "ptrace operation failed".
func (c *FamilyChecker) Apply(pid int, regs *unix.PtraceRegs, action seccomp.OnBlockAction, audit AuditSink, syscall uint64, family seccomp.BlockedFamily) error {
	switch action {
	case seccomp.OnBlockErrno:
		// Skip the syscall and set the return value.
		// Implementation detail: ORIG_RAX = -1 cancels the syscall on
		// modern kernels. RAX gets the negated errno.
		setReturnRegister(regs, -int64(unix.EAFNOSUPPORT))
		setSyscallNumber(regs, ^uint64(0)) // -1
		return unix.PtraceSetRegs(pid, regs)
	case seccomp.OnBlockKill:
		return PtraceKillRequested
	case seccomp.OnBlockLog:
		audit.Emit(audit.Event{
			Kind: "seccomp.socket_family_blocked",
			Fields: map[string]any{
				"family_name":   family.Name,
				"family_number": family.Family,
				"syscall":       syscallName(syscall),
				"action":        string(action),
				"engine":        "ptrace",
				"pid":           pid,
			},
		})
		return nil
	case seccomp.OnBlockLogAndKill:
		audit.Emit(audit.Event{
			Kind: "seccomp.socket_family_blocked",
			Fields: map[string]any{
				"family_name":   family.Name,
				"family_number": family.Family,
				"syscall":       syscallName(syscall),
				"action":        string(action),
				"engine":        "ptrace",
				"pid":           pid,
			},
		})
		return PtraceKillRequested
	default:
		return nil
	}
}

// PtraceKillRequested signals that the caller should kill the tracee.
var PtraceKillRequested = errors.New("ptrace: kill requested by family check")

// setReturnRegister and setSyscallNumber are arch-specific helpers
// already defined in args_amd64.go / args_arm64.go (or should be added
// there if not). The checker delegates rather than open-coding.
```

The arch-specific register helpers may already exist under different names in `internal/ptrace/args_*.go`. **Do not duplicate** — reuse what's there. If the names differ, adjust the call sites.

`AuditSink` type alias for the existing audit interface used elsewhere in `internal/ptrace`.

- [ ] **Step 4: Hook the checker into the tracer dispatch**

In `tracer.go`'s syscall-entry handler, after the static-allow checks and before the per-handler dispatch:

```go
if t.familyChecker != nil {
	syscallNr := getSyscallNumber(regs)
	arg0 := getArg(regs, 0)
	if bf, ok := t.familyChecker.Check(syscallNr, arg0); ok {
		if err := t.familyChecker.Apply(pid, regs, bf.Action, t.auditSink, syscallNr, bf); err != nil {
			if errors.Is(err, PtraceKillRequested) {
				_ = unix.Kill(pid, unix.SIGKILL)
				return
			}
			slog.Warn("ptrace family check apply failed", "pid", pid, "error", err)
		}
		// Skip the rest of the dispatch — the syscall has been handled.
		return
	}
}
```

Add a `familyChecker *FamilyChecker` field to the `Tracer` struct and a `WithFamilyChecker` option (or constructor argument).

- [ ] **Step 5: Run integration test; expect pass**

- [ ] **Step 6: Commit**

```bash
git add internal/ptrace/family_checker.go internal/ptrace/family_checker_integration_test.go internal/ptrace/tracer.go
git commit -m "feat(ptrace): wire FamilyChecker into tracer syscall-entry dispatch

errno path skips the syscall and sets RAX to -EAFNOSUPPORT.
kill path returns PtraceKillRequested for the caller to dispatch SIGKILL.
log/log_and_kill emit seccomp.socket_family_blocked audit events with
engine=ptrace.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 10: Engine selection in server startup

**Files:**
- Modify: `internal/server/security.go` (or wherever sandbox initialization happens — find with `grep -n "Sandbox.Seccomp\|InstallFilter\|tracer.New" internal/server/*.go`)

- [ ] **Step 1: Find where the engines are wired today**

```bash
grep -n "InstallFilter\|tracer\." internal/server/*.go
```

Find the spots where seccomp filter is installed AND where the ptrace tracer is constructed.

- [ ] **Step 2: Write failing test**

Server-startup tests usually use a config fixture and assert behavior. The minimum new test:

```go
func TestSkillcheck_FamilyEngineSelection_Seccomp(t *testing.T) {
	// Capabilities mock: seccomp present.
	// Config: blocked_socket_families set.
	// Assert: filter receives BlockedFamilies; tracer family-checker is nil.
}

func TestSkillcheck_FamilyEngineSelection_PtraceFallback(t *testing.T) {
	// Capabilities mock: seccomp absent, ptrace present.
	// Assert: tracer family-checker is populated; seccomp filter is not built.
}

func TestSkillcheck_FamilyEngineSelection_NeitherWarn(t *testing.T) {
	// Capabilities mock: both absent.
	// Assert: server starts; warning logged; nothing installed.
}
```

The test interfaces depend on what's mockable in the project. If capabilities aren't easily mockable for unit tests, write a smaller test that just checks the resolved `BlockedFamilies` slice is correctly forwarded into whichever engine path the resolver picks.

- [ ] **Step 3: Implement engine selection**

In the server bootstrap, around the existing seccomp-vs-ptrace decision (or add it if absent):

```go
families, err := config.ResolveBlockedFamilies(cfg.Sandbox.Seccomp.BlockedSocketFamilies)
if err != nil {
	return nil, fmt.Errorf("resolve blocked_socket_families: %w", err)
}

useSeccomp := cfg.Sandbox.Seccomp.Enabled && capabilities.HasSeccompFilter()
usePtrace := !useSeccomp && cfg.Sandbox.Ptrace.Enabled && capabilities.HasPtrace()

switch {
case useSeccomp:
	filterCfg.BlockedFamilies = families
case usePtrace:
	tracerCfg.FamilyChecker = ptrace.NewFamilyChecker(families)
case len(families) > 0:
	slog.Warn("socket family blocking is configured but no enforcement engine is available on this host (seccomp and ptrace both unavailable); families will not be blocked",
		"families", len(families))
}
```

The exact field names depend on the codebase. Don't invent new ones if the equivalents already exist.

- [ ] **Step 4: Run test; expect pass**

- [ ] **Step 5: Commit**

```bash
git add internal/server/security.go internal/server/<test-file>.go
git commit -m "feat(server): engine selection for socket family blocking

Seccomp primary; ptrace fallback when seccomp unavailable; warn-and-
continue when both are absent.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Self-Review

- [ ] **Spec coverage check**

Re-read `docs/superpowers/specs/2026-04-29-socket-family-block-design.md`. For each section, confirm a task implements it:

  - Config schema (Section: Configuration) → Task 3
  - Default list (Section: Recommended default list) → Task 1 + Task 3 default-merge
  - Both names + numeric (Section: Configuration) → Task 1 `ParseFamily`
  - Per-family action (Section: Configuration) → Tasks 6, 9 (both engines respect it)
  - Engine selection (Section: Engine selection) → Task 10
  - Audit events (Section: Audit events) → Tasks 7 (seccomp), 9 (ptrace)
  - libseccomp action-precedence coexistence (Section: Coexistence) → Task 6 integration test
  - Cross-platform build (Section: Cross-platform) → Tasks 1–10 all add cross-compile gate

- [ ] **Verification before completion**

After Task 10, run the full gate:

```bash
go build ./...
GOOS=windows go build ./...
GOOS=darwin go build ./...
go vet ./...
go test -race ./internal/seccomp/... ./internal/config/... ./internal/netmonitor/unix/... ./internal/ptrace/... ./internal/server/...
go test ./...
```

All clean.
