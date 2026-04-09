# Detect Output Redesign: Feature Inventory + Weighted Score

**Date:** 2026-03-21
**Status:** Implemented
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
| FUSE | Open `/dev/fuse` (O_RDWR, close immediately) + fusermount/fsopen/mount probe. Detail shows method: "fusermount3", "new-api", or "direct" | Full file interception, soft-delete, redirect |
| Landlock | `landlock_create_ruleset` syscall probe (ABI 1-5) | Kernel-level path restrictions |
| Seccomp-notify file_monitor | Seccomp user-notify available (libseccomp `GetAPI() >= 6`, which maps to `SECCOMP_FILTER_FLAG_NEW_LISTENER` support) | openat/stat/unlink interception via user-notify |

**Command Control** (25 pts)

| Backend | Detection Method | Enables |
|---------|-----------------|---------|
| Seccomp execve | Same seccomp user-notify check as above | execve/execveat interception via user-notify |
| Ptrace | `PTRACE_SEIZE` on forked child (existing functional probe) | Syscall-level exec interception + redirect |

**Network** (20 pts)

| Backend | Detection Method | Enables |
|---------|-----------------|---------|
| eBPF | `ebpf.CheckSupport()` prerequisites + `BPF_PROG_LOAD` canary with `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` (see section 3 for details) | cgroup-level network monitoring |
| Landlock network | Landlock ABI >= 4 (from existing probe) | Kernel-level TCP bind/connect filtering |

**Resource Limits** (15 pts)

| Backend | Detection Method | Enables |
|---------|-----------------|---------|
| cgroups v2 | Stat `/sys/fs/cgroup` for type `cgroup2fs` + read test | CPU, memory, process count limits |

**Isolation** (15 pts)

| Backend | Detection Method | Enables |
|---------|-----------------|---------|
| PID namespace | Read `/proc/self/status` NSpid field (see section 3) | Process isolation |
| Capability drop | `capget()` + `prctl(PR_CAPBSET_READ, 0)` both succeed (see section 3) | Privilege reduction |

### 3. Real Detection Probes

Replace four stubs with actual probes:

**eBPF probe**: First call `internal/netmonitor/ebpf.CheckSupport()` to verify the runtime prerequisites that the real cgroup netmonitor depends on (cgroup v2 mounted, BTF present, `CAP_BPF` or `CAP_SYS_ADMIN`, kernel ≥ 5.8). If any of those fail, return the reason from `SupportStatus` without running the canary. Aligning with `CheckSupport()` keeps capability reporting consistent with runtime behavior — otherwise the probe can claim eBPF is available on hosts where the actual attach path will fail. Note: `CheckSupport()` intentionally does NOT grep `cgroup.controllers` for `"bpf"` — BPF is not a cgroup v2 resource controller, so that string is never present on any Linux system. The `CONFIG_CGROUP_BPF` kernel build option is verified implicitly by the canary below, since loading a `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program requires it.

Only if `CheckSupport()` passes, construct a minimal `bpf_attr` struct for `BPF_PROG_LOAD` and load it as a final sanity check that `BPF_PROG_LOAD` itself is not blocked by seccomp, lockdown, or an LSM:
- `prog_type`: `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` (18) — matches the program family the real netmonitor attaches (`cgroup/connect4`, `cgroup/sendmsg4`, etc.). NOTE: value 13 is `BPF_PROG_TYPE_SOCK_OPS`, and value 8 is `BPF_PROG_TYPE_CGROUP_SKB` — neither matches the runtime path.
- `expected_attach_type`: `BPF_CGROUP_INET4_CONNECT` (10) — required for `CGROUP_SOCK_ADDR`; the kernel rejects loads with `EINVAL` if `expected_attach_type` is not one of the valid bind/connect/sendmsg/recvmsg/getpeername/getsockname attach types.
- `insns`: pointer to a 2-instruction canary: `r0 = 0; exit;` (16 bytes: `0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00`). For `CGROUP_SOCK_ADDR`, r0 is the verdict (0 = deny, 1 = allow); both are valid return values, so `r0 = 0` satisfies the verifier. A lone `BPF_EXIT` is rejected because r0 is uninitialized.
- `insn_cnt`: 2
- `license`: pointer to `"GPL\0"`
- The `bpf_attr` struct must be extended through `expected_attach_type` (72 bytes on amd64), not the 48-byte variant that stops at `kern_version`.

Call `unix.Syscall(SYS_BPF, BPF_PROG_LOAD, uintptr(unsafe.Pointer(&attr)), size)`. Classify result:
- Valid fd → available (close immediately). Detail: `"cgroup_sock_addr"`
- `EPERM` → unavailable. Detail: `"EPERM (BPF_PROG_LOAD denied)"`
- `EACCES` → unavailable. Detail: `"EACCES (BPF verifier rejected canary)"`
- `ENOSYS` → unavailable. Detail: `"ENOSYS (kernel too old)"`
- Other error → unavailable. Detail: the error string

**cgroups v2 probe**: `unix.Statfs("/sys/fs/cgroup", &statfs)` and check `statfs.Type == CGROUP2_SUPER_MAGIC` (0x63677270). Then `os.OpenFile("/sys/fs/cgroup/cgroup.procs", O_RDONLY, 0)` to verify readability (close immediately). Classify:
- Both succeed → available. Detail: `"cgroup2"`
- Statfs fails or wrong type → unavailable. Detail: `"not mounted"` or `"cgroup v1"`
- File not readable → unavailable. Detail: `"not readable"`

**PID namespace probe**: Read `/proc/self/status` and find the `NSpid:` line. Classify:
- Multiple tab-separated values (e.g., `NSpid:\t1234\t1`) → available. Detail: `"NSpid: <N> levels"`
- Single value → unavailable. Detail: `"host namespace"`
- `NSpid` field absent (kernel < 4.1) → unavailable. Detail: `"NSpid not supported"`

**Capability drop probe**: Four steps:
1. `unix.Capget()` with `LINUX_CAPABILITY_VERSION_3` succeeds (the V3 buffer is a two-element `CapUserData` array per golang/go#44312; a single-element buffer under-allocates and the kernel writes past the end).
2. `prctl(PR_CAPBSET_READ, 0)` succeeds (the mechanism for reading/dropping the bounding set is accessible).
3. The **permitted** capability set from step 1 is compared against the full mask derived from `/proc/sys/kernel/cap_last_cap`.
4. The **bounding** set is read bit-by-bit via `PR_CAPBSET_READ` and compared against the same mask. The backend is reported *available* only when either `CapPrm` or `CapBnd` has at least one bit cleared within `[0, cap_last_cap]`.

The `CapEff` set is intentionally **not** consulted: a process can do `capset(eff=0, prm=full)` and instantly restore its effective set on the next syscall, so "CapEff reduced but CapPrm full" is a transient state, not a durable privilege drop. Tracking only the permitted and bounding sets matches the drop mechanisms actually used in the codebase (`PR_CAPBSET_DROP` in `capabilities.DropCapabilities`, systemd `CapabilityBoundingSet=`, `docker --cap-drop=...`).

Detail text:
- Permitted reduced: `"N/M caps dropped from permitted"`
- Bounding reduced: `"N/M caps dropped from bounding"`
- Both reduced: `"N/M dropped (prm) + X/M dropped (bnd)"`
- Neither reduced: `"process retains full CapPrm and CapBnd (M/M caps)"` → Available=false

Fallbacks:
1. If `/proc/sys/kernel/cap_last_cap` is unreadable (pre-2.6.25 kernels, restricted procfs), the probe reports Available=true with an explicit caveat so deployments on those environments do not silently regress.
2. If `PR_CAPBSET_READ` fails during the bit walk (uncommon; some lockdown or seccomp profiles block extended `prctl` args), the probe falls back to the permitted-set check and flags the bounding status as "unknown" in the detail text. This preserves correct reporting in environments where the process dropped its permitted set but bounding reads are blocked.

This is a behavioural check, not an infrastructure check: it answers "is capability-drop actually protecting this process?" rather than "does capability-drop exist on this kernel?". Issue #198 reported the previous infrastructure-only probe marking the backend active for a server running as root with `CapEff=0x1ffffffffff` (all 41 caps) — a false positive that the behavioural check eliminates. Bits above `cap_last_cap` are ignored so that kernel quirks (phantom high bits) cannot mask a genuine drop of a low capability.

**Mechanism vs. active — separate fields:** Because `SecurityCapabilities.Capabilities` is historically the *mechanism* flag ("can this platform drop caps at all" — always true on Linux) and is read by mode selection, configuration generation, and the startup log, the behavioural signal lives on a second field `SecurityCapabilities.CapabilitiesActive`. `CapabilitiesActive` is the single behavioural source of truth: detect output (`buildLinuxDomains`), the backward-compat `capabilities_drop` flat-map key, and the new `capabilities_active` log field all read this one field, and the raw `CapProbe` result is only consulted for human-readable detail text. Mode selection does NOT consult either field (the `minimal` mode is the fallback regardless), so splitting the two does not affect mode behaviour. The `LogSecurityCapabilities` log line records both under the keys `capabilities` (mechanism, legacy) and `capabilities_active` (behavioural, new).

**Mode description honesty:** Pre-#198 the `minimal` mode description always read "capability dropping only (~50% policy enforcement)", which contradicted a root server with `CapabilitiesActive=false`. A new `ModeDescriptionWithCaps(mode, caps)` is gated on the behavioural flag: `minimal + active` yields the old "capability dropping only" wording, `minimal + inactive` yields "no active enforcement primitives (privilege reduction inactive — process retains full Linux capabilities)", and `minimal + nil caps` falls back to "fallback mode" for callers that don't have a caps handle. Non-minimal modes bypass the caps-aware branch entirely. `LogSecurityCapabilities` and the degraded-mode warning both use the new form so operators no longer see contradictory startup lines.

**Tip guidance:** The remediation text points operators at startup-time mechanisms that actually lower `CapPrm`/`CapEff`: `systemd CapabilityBoundingSet= + User=`, `docker run --cap-drop=ALL`, or running under an unprivileged user. `capabilities.DropCapabilities()` is deliberately NOT recommended because it only calls `PR_CAPBSET_DROP` and leaves the current process's permitted/effective sets untouched — following that advice would satisfy the bounding-set half of the probe while leaving the process still able to use its existing caps, yielding a half-dropped state that is more misleading than helpful. The tip Action is structured as `"<recommendation sentence>. Note: <cautionary sentence>"` so `DropCapabilities` can be explained in the cautionary half without appearing as a primary recommendation.

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
  ebpf               ✓  cgroup_sock_addr network monitoring
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
- Domain shows which backend is active (derived from `SecurityCapabilities.FileEnforcement`, `SelectMode()`, and related existing fields — detection already computes this)
- Tips show point impact — only generated for backends in domains that score 0 (domains already scoring full weight don't generate tips since additional backends provide redundancy, not extra points)
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

For stubs that can't easily become real probes (e.g., ESF requires entitlements that detection code won't have), keep the stub but set `CheckMethod: "entitlement"` (not `"probe"`) so the output is honest about detection fidelity. On Darwin, `sandbox-exec` appears under both Command Control (execution sandboxing) and Isolation (process isolation) — these are distinct uses of the same underlying mechanism and both report as available.

On Windows, the existing `os.Stat` check for WinFsp DLL should be upgraded to `syscall.LoadLibrary` to verify the DLL actually loads (not just exists). This is deferred to platform-specific implementation — the spec defines the intent, not the exact Windows API calls.

### 6. Testing

**Probe tests** (behind platform build tags):
1. `TestProbeEBPF` — verify BPF syscall runs. Classify EPERM vs ENOSYS vs success.
2. `TestProbeCgroupsV2` — verify statfs check. Test CGROUP2_SUPER_MAGIC match and mismatch.
3. `TestProbePIDNamespace` — parse NSpid. Test single-value (host), multi-value (namespaced), and absent field (old kernel).
4. `TestProbeCapabilityDrop` — verify capget + prctl both succeed.

**Score tests** (cross-platform, mock capabilities):
5. `TestWeightedScore_AllAvailable` — all domains score full → 100.
6. `TestWeightedScore_NoneAvailable` — all domains empty → 0.
7. `TestWeightedScore_PartialCombinations`:
   - File + Command only → 50
   - Network + Resource + Isolation only → 50
   - Single backend in multi-backend domain (e.g., only Landlock in File) → domain still scores 25
   - All backends unavailable in one domain, rest available → 100 minus that domain's weight
8. `TestDomainScoring` — each domain returns weight when any single backend available, 0 when none.

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
    Active   string           // which backend is in use, derived from:
                              // File: SecurityCapabilities.FileEnforcement
                              // Command: SelectMode() result (seccomp vs ptrace)
                              // Network: "ebpf" if available, else "landlock-network"
                              // Resource: "cgroups-v2" if available
                              // Isolation: first available backend
}

type DetectedBackend struct {
    Name        string // "fuse", "landlock", "ebpf", etc.
    Available   bool
    Detail      string // "fusermount3", "ABI v5", "EPERM", "not mounted"
    Description string // "file interception, soft-delete"
    CheckMethod string // "probe", "syscall", "binary", "entitlement"
}
```

The flat `Capabilities` map is still populated for backward compatibility with JSON consumers. Mapping from new to old keys:

| Old key | Populated from |
|---------|---------------|
| `seccomp`, `seccomp_user_notify` | seccomp-execve backend available |
| `seccomp_basic` | same as `seccomp` |
| `landlock` | landlock backend available |
| `landlock_abi` | landlock backend detail (ABI version number) |
| `landlock_network` | landlock-network backend available |
| `fuse` | fuse backend available |
| `fuse_mount_method` | fuse backend detail |
| `ebpf` | ebpf backend available |
| `cgroups_v2` | cgroups-v2 backend available |
| `ptrace` | ptrace backend available |
| `pid_namespace` | pid-namespace backend available |
| `capabilities_drop` | capability-drop backend active (process has dropped ≥1 capability) |
| `file_enforcement` | File Protection domain active backend |

The `Domains` field is the new structured representation.

## Dependencies

- `golang.org/x/sys/unix` (existing) — for BPF, statfs, capget syscalls
- No new dependencies

## Out of Scope

- Changing the `agentsh detect config` subcommand (it still generates config based on mode)
- Changing how modes are selected at runtime (SelectMode stays the same)
- Per-feature scoring within domains (domain is all-or-nothing based on any backend)
