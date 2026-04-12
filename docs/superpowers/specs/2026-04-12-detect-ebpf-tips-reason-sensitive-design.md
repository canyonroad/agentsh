# Design: Reason-sensitive tips for `agentsh detect`

**Issue:** #217
**Date:** 2026-04-12

## Problem

`agentsh detect` shows a generic "Requires CAP_BPF and cgroups v2" tip for
eBPF regardless of the actual failure reason. When the real issue is missing
BTF (kernel built without `CONFIG_DEBUG_INFO_BTF=y`), the tip sends users
chasing capabilities and cgroups instead of the kernel build.

The detection row already carries the correct reason in
`DetectedBackend.Detail`, but `GenerateTipsFromDomains()` and `lookupTip()`
ignore it — they key tips solely on the backend name.

## Design

### Data model

Introduce a `reasonTip` struct and change `tipsByBackend` from
`map[string]Tip` to `map[string][]reasonTip`:

```go
type reasonTip struct {
    Contains string // substring to match against DetectedBackend.Detail; "" = fallback
    Tip      Tip
}
```

Each backend's slice is scanned in order. The first entry whose `Contains`
is a non-empty substring of `Detail` wins. An entry with `Contains: ""`
at the end of the slice acts as the fallback. Backends that don't need
reason-sensitivity keep a single fallback entry — behavior identical to
today.

### eBPF reason-specific tips

Five entries for the `"ebpf"` key, ordered to avoid ambiguous substring
matches (e.g. `"kernel version unknown"` before `"kernel"`):

| `Contains`               | Action                                                                                                                                                                       |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `"btf not present"`      | Kernel was built without `CONFIG_DEBUG_INFO_BTF=y`; cilium/ebpf CO-RE programs cannot relocate types without BTF. Rebuild the kernel with `CONFIG_DEBUG_INFO_BTF=y` (and ideally `CONFIG_DEBUG_INFO_BTF_MODULES=y`). |
| `"cgroup v2 not available"` | eBPF socket association requires cgroups v2. Mount a unified cgroup hierarchy or switch to a systemd-based init.                                                          |
| `"kernel version unknown"` | Could not determine kernel version. eBPF network monitoring requires kernel 5.8+.                                                                                        |
| `"kernel"`               | eBPF network monitoring requires kernel 5.8+ for BPF ring buffer and CO-RE support. Upgrade your kernel.                                                                    |
| `""` (fallback)          | Requires CAP_BPF (or CAP_SYS_ADMIN) and cgroups v2. Run as root or with elevated privileges.                                                                                |

All other backends keep a single fallback entry with their current tip
text — no behavior change.

### Code changes

Two functions change in `internal/capabilities/tips.go`:

1. **`lookupTip(backendName, detail string) *Tip`** — add `detail`
   parameter. Scan the backend's `[]reasonTip` slice: return the first
   entry where `Contains != ""` and `strings.Contains(detail, entry.Contains)`,
   or the first entry where `Contains == ""` (fallback).

2. **`GenerateTipsFromDomains()`** — one-line change at the call site:
   `lookupTip(b.Name)` becomes `lookupTip(b.Name, b.Detail)`.

No changes to `DetectedBackend`, `Tip`, `ProtectionDomain`, rendering
code, or the legacy `GenerateTips()` function. The `Detail` field is
already populated correctly by each platform's detection logic.

### Tests

Update existing tests in `tips_test.go`:

- **`TestLookupTip`**: pass a detail string; add subtests verifying each
  eBPF reason produces the correct action text.
- **`TestGenerateTipsFromDomains_ZeroScoreOnly`**: add `Detail` to the
  test backend and verify the tip action reflects the reason.
- **New: `TestLookupTip_ReasonFallback`**: verify that an unrecognized
  detail string for eBPF falls through to the generic fallback tip.
- **New: `TestLookupTip_NonEBPFUnchanged`**: verify a backend with only a
  fallback entry (e.g. `"fuse"`) still returns its tip regardless of
  detail content.

### Files touched

| File | Change |
|------|--------|
| `internal/capabilities/tips.go` | `reasonTip` type, new `tipsByBackend` shape, `lookupTip` signature, `GenerateTipsFromDomains` call site |
| `internal/capabilities/tips_test.go` | Update and add tests |
