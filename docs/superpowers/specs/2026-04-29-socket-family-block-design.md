# Socket Family Blocking — Design

**Date:** 2026-04-29
**Status:** Draft, awaiting user review
**Related:** `internal/seccomp/`, `internal/netmonitor/unix/seccomp_linux.go`,
`internal/ptrace/`, `internal/capabilities/`. Mitigation context: [copy.fail](https://copy.fail/#mitigation).

## Summary

Add per-socket-family blocking to agentsh's sandbox. A new config field
`sandbox.seccomp.blocked_socket_families` lets operators block creation
of specified `AF_*` socket families on `socket(2)` and `socketpair(2)`,
with per-family action override (`errno|kill|log|log_and_kill`).

When `socket(AF_ALG, ...)` (or any blocked family) fires, the kernel
returns `EAFNOSUPPORT` (or kills the process, or routes through the
notify-handler for audit), depending on per-family action. Userspace
sees the same observable behavior as on a kernel that doesn't ship
that family — graceful fallback in well-written code.

Two enforcement engines, sharing config and types:

1. **seccomp-bpf (primary)** — `AddRuleConditional` on `socket(2)` arg0.
   Kernel-side filter, ~free runtime cost. Code lives in
   `internal/netmonitor/unix/seccomp_linux.go`.
2. **ptrace (fallback)** — checker invoked from the existing tracer
   when seccomp filter is unavailable. Skips the syscall and writes
   `-EAFNOSUPPORT` into `RAX`. Code lives in `internal/ptrace/`.

Recommended-default list ships blocked at `errno`: `AF_ALG`,
`AF_VSOCK`, `AF_RDS`, `AF_TIPC`, `AF_KCM`, plus the dead protocols
(`AF_X25`, `AF_AX25`, `AF_NETROM`, `AF_ROSE`, `AF_DECnet`,
`AF_APPLETALK`, `AF_IPX`). Operators override or extend.

## Motivation

[copy.fail (CVE-2025-…)] is the latest in a recurring class:
exploitation chains that begin with `socket(AF_<family>, ...)` against
a kernel subsystem that has thinner attack-surface review than the
mainline networking stack. AF_ALG is the kernel crypto API; AF_VSOCK
the VM-host transport; AF_RDS, AF_TIPC, AF_KCM are niche/legacy
networking subsystems. None see meaningful userspace use outside
narrow tooling, but every one is a kernel attack vector reachable from
unprivileged userspace.

The copy.fail mitigation says explicitly:

> For untrusted workloads, block `AF_ALG` socket creation via seccomp
> regardless of patch state.

agentsh today exposes `BlockedSyscalls []string` for whole-syscall
blocking by name. Adding `socket` to that list blocks every
`socket(2)` call (including AF_INET, AF_UNIX) — far too broad.
`libseccomp-golang` (already a project dep, used at
`internal/seccomp/syscalls.go:8`) supports argument-conditional
rules; the existing 46-line `internal/seccomp/filter.go` simply
doesn't expose that path.

This design exposes it as a typed surface — names not numbers,
per-family actions matching the existing `OnBlockAction` enum — and
adds a ptrace fallback for hosts where seccomp is unavailable.

[copy.fail (CVE-2025-…)]: https://copy.fail/#mitigation

## Non-Goals

- **`AF_NETLINK` blanket blocking.** Too widely used (iproute2, audit,
  libnl, systemd). If a specific netlink protocol family becomes a
  vector, that's a separate spec.
- **`AF_PACKET`, `AF_BLUETOOTH`, `AF_CAN` defaults.** Real userspace
  uses these; opt-in only.
- **eBPF LSM tier.** Cleanest long-term option for Linux 5.7+ but
  introduces a substantial new dependency stack (libbpf, CO-RE, BTF,
  CAP_BPF). Separate spec when/if pursued.
- **Landlock network rules for arbitrary families.** Kernel only
  exposes TCP bind/connect via Landlock. Kernel-side change required;
  out of agentsh's control.
- **`socketcall(2)` (i386 multiplexed entry).** Agentsh's existing
  seccomp setup doesn't filter it; libseccomp 2.6+ auto-emulates the
  modern entries on architectures without a dedicated `socket` syscall.
  Documented as a known limitation.
- **Auto-detection of which families a binary already uses.** Useful
  observability feature but requires a separate pass; out of v1.
- **macOS/Windows.** No AF_ALG, no equivalent attack surface. The
  config field parses (cross-compile builds clean) but is documented
  as Linux-only.

## Configuration

New top-level field on the sandbox seccomp config:

```yaml
sandbox:
  seccomp:
    # When unset → recommended-default list (below) applies at action: errno.
    # Set to []   → opt-out of all family blocking.
    # Non-empty   → overrides defaults entirely.
    blocked_socket_families:
      - family: AF_ALG       # by name (preferred)
        action: errno
      - family: 40           # numeric fallback (AF_VSOCK)
        action: log_and_kill
```

Per-family `action` field accepts the existing `OnBlockAction` values:
`errno` (default; returns `EAFNOSUPPORT = 97`), `kill`,
`log` (notify→audit, allow), `log_and_kill` (notify→audit, kill).

### Recommended default list (when field unset)

| Family | Number | Why default |
|---|---|---|
| `AF_ALG` | 38 | copy.fail mitigation; near-zero legitimate userspace use |
| `AF_VSOCK` | 40 | Niche (VM-host); multiple historical CVEs |
| `AF_RDS` | 21 | Reliable Datagram Sockets; multiple CVEs; effectively dead |
| `AF_TIPC` | 30 | Niche cluster protocol; multiple CVEs |
| `AF_KCM` | 41 | Kernel Connection Multiplexor; niche; CVEs |
| `AF_X25` | 9 | Legacy/dead protocol, pure attack surface |
| `AF_AX25` | 3 | Amateur radio; legacy |
| `AF_NETROM` | 6 | Amateur radio; legacy |
| `AF_ROSE` | 11 | Amateur radio; legacy |
| `AF_DECnet` | 12 | Dead protocol |
| `AF_APPLETALK` | 5 | Dead protocol |
| `AF_IPX` | 4 | Dead protocol |

All defaults use `action: errno` — `EAFNOSUPPORT` matches the standard
"this family isn't supported" semantics, so well-behaved userspace
falls back gracefully.

**Not** in defaults (too widely used; opt-in only):
`AF_NETLINK`, `AF_PACKET`, `AF_BLUETOOTH`, `AF_CAN`.

## Architecture

```
┌─────────────────── internal/seccomp ────────────────────┐
│ filter.go           types: BlockedFamily, FilterConfig   │
│ families.go (NEW)   name↔number table; ParseFamily;       │
│                     DefaultBlockedFamilies()              │
│ syscalls.go         (unchanged) libseccomp number lookup  │
└──────────────────────────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
┌─── seccomp engine ────┐    ┌─── ptrace fallback ────────┐
│ internal/netmonitor/  │    │ internal/ptrace/             │
│ unix/seccomp_linux.go │    │   family_checker.go (NEW)    │
│ (extended)            │    │   trace.go (modified)        │
└───────────────────────┘    └──────────────────────────────┘
        │                             │
        └─────────────┬───────────────┘
                      ▼
              ┌─── audit sink ────┐
              │ kind = seccomp.   │
              │ socket_family_    │
              │ blocked           │
              └───────────────────┘
```

## Components

### `internal/seccomp/filter.go` (extended)

Add to `FilterConfig`:

```go
type FilterConfig struct {
    UnixSocketEnabled  bool
    BlockedSyscalls    []string
    BlockedFamilies    []BlockedFamily   // NEW
    OnBlock            OnBlockAction
}
```

`FilterConfigFromYAML` extended to take and pass through.

### `internal/seccomp/families.go` (new)

```go
//go:build linux

package seccomp

// BlockedFamily is one entry on the blocked_socket_families list.
type BlockedFamily struct {
    Family int           // resolved AF_* number
    Action OnBlockAction // errno|kill|log|log_and_kill
    Name   string        // original config name; "" if numeric
}

// ParseFamily resolves a config value (name string or number) to its
// AF_* int. Returns ok=false if value is neither a known name nor a
// parseable number in [0, 64).
func ParseFamily(value string) (nr int, name string, ok bool)

// DefaultBlockedFamilies returns the recommended-default list.
// Each entry uses OnBlockErrno.
func DefaultBlockedFamilies() []BlockedFamily

// nameTable: AF_ALG → 38, AF_VSOCK → 40, … (compiled-in)
```

The table covers the families in the recommended-default list plus
common ones operators might want to add explicitly (AF_INET, AF_INET6,
AF_UNIX, AF_NETLINK, AF_PACKET, AF_BLUETOOTH, AF_CAN). New families
require a code update — kernel adds them rarely.

### `internal/netmonitor/unix/seccomp_linux.go` (modified)

After the existing `BlockedSyscalls` block in `InstallFilterWithConfig`:

```go
// Per-family socket(2) and socketpair(2) filtering.
for _, bf := range cfg.BlockedFamilies {
    cond := seccomp.ScmpCondition{
        Argument: 0,
        Op:       seccomp.CompareEqual,
        Operand1: uint64(bf.Family),
    }
    action := familyToScmpAction(bf.Action)
    for _, sc := range []uint{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR} {
        if err := filt.AddRuleConditional(
            seccomp.ScmpSyscall(sc), action, []seccomp.ScmpCondition{cond},
        ); err != nil {
            slog.Warn("seccomp: failed to add family rule; family skipped",
                "family", bf.Name, "syscall", sc, "error", err)
            continue
        }
    }
    if bf.Action == seccompkg.OnBlockLog || bf.Action == seccompkg.OnBlockLogAndKill {
        // Register for the userspace notify-handler to route to audit.
        // Composite key: (syscall<<32) | family.
        blockedFamilyMap[uint64(unix.SYS_SOCKET)<<32|uint64(bf.Family)] = bf
        blockedFamilyMap[uint64(unix.SYS_SOCKETPAIR)<<32|uint64(bf.Family)] = bf
    }
}
```

`familyToScmpAction(errno) = ActErrno(EAFNOSUPPORT)`,
`familyToScmpAction(kill) = ActKillProcess`,
`familyToScmpAction(log|log_and_kill) = ActNotify`.

### `internal/ptrace/family_checker.go` (new)

```go
//go:build linux

package ptrace

// FamilyChecker decides whether a socket(2)/socketpair(2) call should
// be blocked based on its family argument. Reuses the same
// []seccomp.BlockedFamily list as the seccomp engine.
type FamilyChecker struct {
    bySyscall map[uint64]map[uint64]seccomp.BlockedFamily // syscall → family → entry
}

// Check reports the action for a given syscall+arg0. ok=false means
// allow (no rule).
func (c *FamilyChecker) Check(syscall, arg0 uint64) (
    seccomp.BlockedFamily, bool,
)

// Apply executes the action against a stopped tracee:
//   errno         → set RAX = -EAFNOSUPPORT, skip syscall
//   kill          → PTRACE_KILL
//   log           → emit audit, allow syscall
//   log_and_kill  → emit audit + PTRACE_KILL
func (c *FamilyChecker) Apply(
    pid int, regs *unix.PtraceRegs, action seccompkg.OnBlockAction,
    audit AuditSink,
) error
```

Hooks into the existing tracer dispatch in `internal/ptrace/trace.go`
(or wherever the syscall-entry callback lives — verify before
implementing). Invocation is at the existing syscall-entry stop, after
the static-allow fast path and before any expensive checks.

`arg0` extraction is arch-specific (`regs.Rdi` on x86_64,
`regs.Regs[0]` on arm64). The checker abstracts this through a small
helper.

### Engine selection (`internal/server/server.go`)

At server startup:

```
if cfg.Sandbox.Seccomp.Enabled && capabilities.HasSeccompFilter():
    → seccomp path: family rules added to the filter alongside
      BlockedSyscalls etc.
elif cfg.Sandbox.Ptrace.Enabled && capabilities.HasPtrace():
    → ptrace path: FamilyChecker registered with the tracer
else:
    → log warning: "socket family blocking is configured but no
      enforcement engine is available on this host (seccomp and
      ptrace both unavailable); families will not be blocked"
    → continue startup
```

Both engines are mutually exclusive at runtime — never both for the
same tracee.

## Data flow

### Seccomp path (primary)

```
config YAML
    ↓ parse (internal/config)
[]BlockedFamily (resolved)
    ↓ FilterConfigFromYAML
seccomp.FilterConfig
    ↓ InstallFilterWithConfig
libseccomp filter (kernel BPF)
    ↓ socket(AF_ALG, …)
ActErrno(EAFNOSUPPORT) returned to tracee
    OR ActNotify → notify FD → userspace handler → audit event → action
```

### Ptrace path (fallback)

```
config YAML
    ↓ parse
[]BlockedFamily (resolved)
    ↓ NewFamilyChecker
FamilyChecker (in-memory map)
    ↓ tracee calls socket(AF_ALG, …) → SYSCALL_ENTRY stop
ptrace tracer reads RAX (syscall #) and RDI (arg0)
    ↓ FamilyChecker.Check
match found → Apply:
    errno → SETREGS RAX=-97, ORIG_RAX=-1, PTRACE_SYSEMU continue
    kill  → PTRACE_KILL
    log   → emit audit, PTRACE_CONT
    log_and_kill → emit audit + PTRACE_KILL
```

### Coexistence with existing `UnixSocketEnabled`

When both flags are active, libseccomp's action-precedence
(`KILL > TRAP > ERRNO > TRACE > LOG > ALLOW > NOTIFY`) ensures the
conditional `ActErrno` rule on AF_ALG outranks the unconditional
`ActNotify` rule on `socket(2)`. Validated by an integration test
(see Testing).

## Audit events

New event family `seccomp.socket_family_blocked` emitted when action
is `log` or `log_and_kill`:

| Field | Value |
|---|---|
| `kind` | `seccomp.socket_family_blocked` |
| `family_name` | e.g. `AF_ALG` (empty if numeric-only config) |
| `family_number` | e.g. `38` |
| `syscall` | `socket` or `socketpair` |
| `action` | `log` or `log_and_kill` |
| `engine` | `seccomp` or `ptrace` |
| `pid` | tracee PID |

Routed through the existing audit sink alongside other seccomp events.
Operators see the same SIEM signal regardless of which engine fired.

## Error handling

| Failure | Behavior |
|---|---|
| Unknown family name in config (typo) | Fail-fast at startup with valid-set listing |
| Numeric family out of range | Fail-fast |
| Invalid action string | Existing `ParseOnBlock` path: degrade to errno + warn |
| `AddRuleConditional` returns error for one family | Log family + syscall + error; skip that rule; continue |
| Tracer can't read regs (zombied tracee, etc.) | Skip family check, fall through to existing allow logic. Never block on inability to inspect — false positives mask real bugs |
| Both seccomp and ptrace unavailable | Startup warning; continue; families are not blocked |

## Testing strategy

| Surface | Tests |
|---|---|
| `internal/seccomp/families.go` | Table-driven name→number for every entry; numeric fallback; unknown names rejected; `DefaultBlockedFamilies()` returns documented set; YAML round-trip |
| `internal/seccomp` config integration | Default-merge: empty config → defaults; `[]` → opt-out; mix of named + numeric; per-family action variants; duplicate-family warning |
| `internal/netmonitor/unix/seccomp_linux.go` | Real-process: spawn child under filter, attempt `socket(AF_ALG, SOCK_SEQPACKET, 0)`, assert `errno == EAFNOSUPPORT`. Repeat with `kill` action; child receives SIGSYS or is killed. Coverage matrix: each action × at least two families |
| Coexistence with `UnixSocketEnabled` | Spawn under both flags; `socket(AF_UNIX,…)` → notify path succeeds; `socket(AF_ALG,…)` → blocked. Validates libseccomp action-precedence |
| `internal/ptrace/family_checker.go` | Unit: arg0 extraction across x86_64 + arm64; checker matrix per action |
| `internal/ptrace` integration | Real-tracee: spawn under tracer, attempt `socket(AF_ALG,…)`, assert errno; repeat with `kill` |
| Engine selection (`internal/server`) | Capabilities matrix: seccomp present → seccomp; only ptrace → ptrace; neither → startup warning + continue |
| Negative — backward compat | Existing tests for `BlockedSyscalls`, `UnixSocketEnabled`, `BlockIOUring` unchanged, still pass |

The seccomp coexistence test is the most important — it pins that
adding family rules doesn't break the existing AF_UNIX monitoring
users depend on today.

Cross-compile: `GOOS=windows go build ./...` and
`GOOS=darwin go build ./...` must succeed. The `BlockedFamily` type
is platform-neutral; the engine code is `//go:build linux`.

## Cross-platform

`go:build linux` on all enforcement code. Config parsing is
platform-neutral so cross-compile builds clean. On non-Linux,
agentsh logs `socket family blocking is configured but only enforced
on Linux; ignored on this platform` once at startup if the field is
non-empty.

## Open questions / future work

- **eBPF LSM tier.** When agentsh adopts libbpf for other purposes
  (network filtering, file integrity), revisit the `security_socket_create`
  hook as a third enforcement engine. Cleaner than ptrace, lower
  overhead. Out of scope for v1.
- **Per-binary policy.** Currently the family list applies to every
  tracee under the filter. A future extension might let policy match
  the executed binary so e.g. `iproute2` can use `AF_NETLINK` while
  arbitrary user binaries can't. Out of scope.
- **Reverse — allowlist mode.** If operators want "block everything
  except AF_INET/AF_INET6/AF_UNIX", today they'd have to enumerate
  ~30 families. A future `mode: allowlist` switch could invert. Not
  needed for v1.
- **Userspace observability.** Telling operators "this binary tried to
  use AF_ALG and got blocked" via audit is half the story. A future
  observability pass might surface this in a dashboard with workload
  attribution. Separate project.
