# Detect Output Redesign: Feature Inventory + Weighted Score

**Date:** 2026-03-21
**Status:** Draft
**Scope:** All platforms (Linux, Darwin, Windows)

## Background

The current `agentsh detect` output has several weaknesses:

1. **Stub detections**: eBPF (always true), cgroups v2 (always true), PID namespace (always false), capability drop (always true) — these report hardcoded values instead of probing the actual system.
2. **Mode-based score**: The protection score is a fixed lookup from the mode name (full=100, ptrace=90, etc.) — it doesn't reflect which individual features are actually working.
3. **Flat capability list**: Features are listed alphabetically with no grouping by what they protect. An operator can't quickly see "do I have file protection?" without knowing which capabilities map to which enforcement domains.

This design replaces stub detections with real probes, groups features by protection domain, and computes a weighted score based on actual feature availability.

## What Changes

### 1. Protection Domains and Weight Model

Five protection domains, each with a weight reflecting its security importance:

| Domain | Weight | What it covers |
|--------|--------|---------------|
| File Protection | 25 | Read/write/create/delete enforcement on filesystem |
| Command Control | 25 | Execution policy — allow/deny/redirect commands |
| Network | 20 | Outbound/inbound traffic monitoring and filtering |
| Resource Limits | 15 | CPU, memory, process count constraints |
| Isolation | 15 | Process namespace isolation, capability dropping |

Within each domain, multiple backends can provide coverage. The domain score is the full weight if **any** backend is available, 0 if none. Score = sum of available domain weights (0-100).

### 2. Feature Inventory Per Domain (Linux)

**File Protection** (25 pts)

| Backend | Detection Method | Enables |
|---------|-----------------|---------|
| FUSE | Open `/dev/fuse` + fusermount/fsopen/mount probe | Full file interception, soft-delete, redirect |
| Landlock | `landlock_create_ruleset` syscall probe (ABI 1-5) | Kernel-level path restrictions |
| Seccomp-notify file_monitor | seccomp API >= 6 + config check | openat/stat/unlink interception via user-notify |

**Command Control** (25 pts)

| Backend | Detection Method | Enables |
|---------|-----------------|---------|
| Seccomp execve | seccomp API >= 6 | execve/execveat interception via user-notify |
| Ptrace | `PTRACE_SEIZE` on forked child | Syscall-level exec interception + redirect |

**Network** (20 pts)

| Backend | Detection Method | Enables |
|---------|-----------------|---------|
| eBPF | `BPF_PROG_LOAD` syscall with `BPF_PROG_TYPE_CGROUP_SKB` | cgroup-level network monitoring |
| Landlock network | Landlock ABI >= 4 (from existing probe) | Kernel-level TCP bind/connect filtering |

**Resource Limits** (15 pts)

| Backend | Detection Method | Enables |
|---------|-----------------|---------|
| cgroups v2 | Stat `/sys/fs/cgroup` for type `cgroup2fs` + read test | CPU, memory, process count limits |

**Isolation** (15 pts)

| Backend | Detection Method | Enables |
|---------|-----------------|---------|
| PID namespace | Read `/proc/self/status` NSpid field (multiple entries = namespaced) | Process isolation |
| Capability drop | `capget()` succeeds | Privilege reduction |

### 3. Real Detection Probes

Replace four stubs with actual probes:

**eBPF probe**: Call `unix.Syscall(SYS_BPF, BPF_PROG_LOAD, ...)` with a minimal program (type `BPF_PROG_TYPE_CGROUP_SKB`, single `BPF_EXIT` instruction). Valid fd → works (close immediately). `EPERM` → missing capability. `ENOSYS` → no BPF support. This is a functional test, not a file check.

**cgroups v2 probe**: `unix.Statfs("/sys/fs/cgroup", &statfs)` and check `statfs.Type == CGROUP2_SUPER_MAGIC` (0x63677270). Then `os.OpenFile("/sys/fs/cgroup/cgroup.procs", O_RDONLY, 0)` to verify readability. Confirms the cgroup2 hierarchy is mounted and accessible.

**PID namespace probe**: Read `/proc/self/status` and find the `NSpid:` line. Multiple tab-separated values (e.g., `NSpid: 1234 1`) → process is in a PID namespace. One value → host namespace. Reliable and doesn't require root.

**Capability drop probe**: Call `unix.Capget()` — success means we can read capabilities (and therefore drop them). Makes the existing assumption explicit.

All probes are fast, side-effect-free, and run at detection time.

### 4. Output Format

The table output changes from a flat list to grouped domains:

```
Platform:         linux
Security Mode:    full
Protection Score: 85/100

FILE PROTECTION                                    25/25
  fuse               ✓  fusermount3      file interception, soft-delete
  landlock           ✓  ABI v5           kernel path restrictions
  seccomp-notify     ✓  file_monitor     openat/stat enforcement
  active backend:    fuse

COMMAND CONTROL                                    25/25
  seccomp-execve     ✓                   execve interception
  ptrace             -  EPERM            syscall tracing
  active backend:    seccomp-execve

NETWORK                                            20/20
  ebpf               ✓  cgroup_skb       network monitoring
  landlock-network   ✓  ABI v4+          TCP bind/connect filtering

RESOURCE LIMITS                                    0/15
  cgroups-v2         -  not mounted      CPU/memory/process limits

ISOLATION                                          15/15
  pid-namespace      ✓  NSpid: 2 levels  process isolation
  capability-drop    ✓                   privilege reduction

TIPS
  cgroups-v2: Enable cgroup v2 for resource limiting (+15 pts)
    -> Mount cgroup2 or run with --cgroupns=host
```

Key changes from current output:
- Grouped by domain with per-domain subtotal
- Each feature shows: name, status (✓/-), detection detail, what it enables
- Domain shows which backend is active (from config)
- Tips show point impact
- JSON/YAML output uses the same structure (nested by domain)

### 5. Cross-Platform Parity

Same domain model applied to Darwin and Windows with platform-specific backends:

**Darwin:**

| Domain | Backends | Detection |
|--------|----------|-----------|
| File Protection | FUSE-T | dylib path check + `dlopen` probe |
| | ESF | `codesign --display --entitlements` check |
| Command Control | ESF | Same entitlement check |
| | sandbox-exec | Always available (macOS built-in) |
| Network | Network Extension | Entitlement check |
| Resource Limits | launchd limits | Always available |
| Isolation | sandbox-exec | Always available |

**Windows:**

| Domain | Backends | Detection |
|--------|----------|-----------|
| File Protection | WinFsp | Registry query + `LoadLibrary` probe |
| | Minifilter | `OpenSCManager` + query minifilter driver service |
| Command Control | AppContainer | `CreateAppContainerProfile` API probe |
| Network | WinDivert | `LoadLibrary` probe |
| Resource Limits | Job Objects | Always available (Win8+) |
| Isolation | AppContainer | Same as command control probe |

Weight model (25/25/20/15/15) is identical across platforms. Score is always 0-100 computed the same way.

For stubs that can't easily become real probes (e.g., ESF requires entitlements that detection code won't have), keep the stub but mark detection as `"check": "entitlement"` rather than `"check": "probe"` so the output is honest about detection fidelity.

### 6. Testing

**Probe tests** (behind platform build tags):
1. `TestProbeEBPF` — verify BPF syscall runs without panic.
2. `TestProbeCgroupsV2` — verify statfs check runs.
3. `TestProbePIDNamespace` — parse NSpid from `/proc/self/status`.
4. `TestProbeCapabilityDrop` — verify capget succeeds.

**Score tests** (cross-platform, mock capabilities):
5. `TestWeightedScore` — all-available (100), none (0), partial combinations.
6. `TestDomainScoring` — each domain returns weight when any backend available.

**Format tests** (cross-platform):
7. `TestTableFormat_Grouped` — domain headers with subtotals.
8. `TestJSONFormat_Domains` — nested JSON structure by domain.

**Integration:**
9. `TestDetectFullCycle` — call `Detect()`, verify all fields, score 0-100, no panics.

## Data Model Changes

The `DetectResult` struct adds domain-level structure:

```go
type DetectResult struct {
    Platform        string
    SecurityMode    string
    ProtectionScore int              // now computed from domains
    Domains         []ProtectionDomain
    Capabilities    map[string]any   // kept for backward compat (JSON consumers)
    Summary         DetectSummary
    Tips            []Tip
}

type ProtectionDomain struct {
    Name     string           // "File Protection", "Command Control", etc.
    Weight   int              // 25, 25, 20, 15, 15
    Score    int              // weight if any backend available, else 0
    Backends []DetectedBackend
    Active   string           // which backend is currently in use
}

type DetectedBackend struct {
    Name        string // "fuse", "landlock", "ebpf", etc.
    Available   bool
    Detail      string // "fusermount3", "ABI v5", "EPERM", "not mounted"
    Description string // "file interception, soft-delete"
    CheckMethod string // "probe", "syscall", "binary", "entitlement"
}
```

The flat `Capabilities` map is still populated for backward compatibility with JSON consumers. The `Domains` field is the new structured representation.

## Dependencies

- `golang.org/x/sys/unix` (existing) — for BPF, statfs, capget syscalls
- No new dependencies

## Out of Scope

- Changing the `agentsh detect config` subcommand (it still generates config based on mode)
- Changing how modes are selected at runtime (SelectMode stays the same)
- Per-feature scoring within domains (domain is all-or-nothing based on any backend)
