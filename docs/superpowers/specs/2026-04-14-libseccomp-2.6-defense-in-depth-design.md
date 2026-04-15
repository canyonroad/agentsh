# libseccomp 2.6 Defense-in-Depth Design

**Date:** 2026-04-14
**Status:** Approved design — ready for implementation plan
**Related:** [2026-04-13 SIGURG seccomp preemption fix](./2026-04-13-sigurg-seccomp-preemption-fix-design.md), PR #225

## Problem

PR #225 introduced a two-layer fix for Go's SIGURG async preemption interrupting `seccomp_do_user_notification()` and causing ERESTARTSYS infinite-retry loops:

- **Layer 1 (kernel):** `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` via libseccomp's `SCMP_FLTATR_CTL_WAITKILL`, set through libseccomp-golang's `SetWaitKill()`. Requires kernel 5.19+ *and* libseccomp 2.6+ headers at build time.
- **Layer 2 (userspace):** `runtime.LockOSThread()` + `rt_sigprocmask(SIG_BLOCK, SIGURG)` in the unixwrap thread before `execve`.

The silent-disable hazard: libseccomp-golang v0.11.0 contains a preprocessor fallback:

```c
// seccomp_internal.go
#if SCMP_VER_MAJOR == 2 && SCMP_VER_MINOR < 6
#define SCMP_FLTATR_CTL_WAITKILL _SCMP_FLTATR_MIN
#endif
```

`_SCMP_FLTATR_MIN = 0` is a no-op sentinel. When built against pre-2.6 headers, `SetWaitKill(true)` returns success without setting the real kernel flag. Layer 1 is dead, and only Layer 2 protects the process.

Empirical state (verified via Docker):
- Ubuntu 24.04 LTS ships libseccomp **2.5.5** → Layer 1 dead
- Ubuntu 25.04 still on **2.5.5** → Layer 1 dead
- Alpine 3.23 ships **2.6.0** → Layer 1 works
- GitHub Actions `ubuntu-latest` = 24.04 → shipped deb/rpm/tar.gz binaries have Layer 1 dead

Layer 2 alone is functional but fragile: the blocked SIGURG mask is inherited across `execve`, degrading Go async preemption to cooperative preemption in all wrapped Go programs. Layer 1 is the preferred mechanism; losing it silently is a regression risk the current code cannot detect.

## Goals

1. **Guarantee Layer 1 is actually compiled in** for every shipped binary, across all architectures and package formats.
2. **Detect silent disable at runtime** when the kernel supports the flag but the libseccomp binding reports failure.
3. **Fail loudly at build time** if anyone builds against pre-2.6 libseccomp (local dev, vendor patch, CI regression).
4. **Verify Layer 1 actually engages** via automated tests that read back the filter attribute.
5. **Keep shipped binaries self-contained** — no runtime libseccomp version dependency on end-user hosts.

## Non-goals

- Fixing kernels < 5.19 (out of scope — Layer 2 covers).
- Automating the arm64 real-VM regression reproducer (documented as manual release gate).
- Migrating CI to `runs-on: ubuntu-26.04` (possible follow-up when GitHub ships it; not required here).

## Architecture

### 1. Static-linked libseccomp 2.6 everywhere

Match the existing Alpine pattern (`.github/workflows/release.yml:136,142`): `CGO_LDFLAGS="-static -lseccomp"`. Extend to amd64 and arm64 Linux builds.

Shipped binary surface after this change:
- `unixwrap-linux-amd64`: static libseccomp 2.6
- `unixwrap-linux-arm64`: static libseccomp 2.6
- `unixwrap-alpine-*`: static libseccomp 2.6 (unchanged)

Size impact: ~600KB per binary. Eliminates runtime `libseccomp.so` dependency on end-user hosts.

### 2. Source build in CI

New `scripts/build-libseccomp.sh`:
- Downloads libseccomp 2.6.0 release tarball
- Verifies signature against pinned upstream key
- Runs `./configure --disable-shared --enable-static --prefix=/usr/local`
- `make && make install`
- Cross-arch support via `--host=aarch64-linux-gnu` when invoked with `TARGET=arm64`

Runs in release.yml before the Go build step, once for amd64 and once for arm64.

**Reason this is source-build, not apt:** Ubuntu 24.04 (GitHub's `ubuntu-latest`) stays on libseccomp 2.5.5 through its LTS lifetime. Ubuntu 26.04 ships April 23, 2026 but GitHub's `ubuntu-latest` alias lags LTS flips by months. Source build removes the dependency on the runner's package pool entirely.

### 3. Build-time guard (`#error`)

New file `internal/netmonitor/unix/seccomp_version_check.go`:

```go
//go:build linux && cgo

package unix

// #include <seccomp.h>
// #if SCMP_VER_MAJOR < 2 || (SCMP_VER_MAJOR == 2 && SCMP_VER_MINOR < 6)
// #error "libseccomp >= 2.6.0 required for SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (Layer 1 SIGURG fix). See scripts/build-libseccomp.sh."
// #endif
import "C"
```

Duplicate in `cmd/agentsh-unixwrap/seccomp_version_check.go` — the wrapper binary links libseccomp independently through the `unix` package, but a standalone guard ensures the error surfaces even if the import graph changes.

Effect: any local dev / vendor build / CI regression against pre-2.6 headers fails compilation with a pointer to the fix script. No silent Layer 1 loss possible.

### 4. Runtime Warn on unexpected silent disable

Modify `internal/netmonitor/unix/seccomp_linux.go` (currently lines 236–242):

```go
waitKillSet := false
kernelSupports := ProbeWaitKillable()
if kernelSupports {
    if err := filt.SetWaitKill(true); err != nil {
        slog.Warn("seccomp: WaitKillable unexpectedly unavailable despite kernel 6.0+; falling back to SIGURG signal mask only",
            "error", err)
    } else {
        waitKillSet = true
    }
}
```

Rationale: the `#error` guard catches the build-time case. A runtime Warn catches:
- Custom/vendor kernels that report ≥6.0 but lack the flag
- Future libseccomp-golang regressions
- Someone shipping a binary built outside our CI

Log level is Warn (not Error) because Layer 2 continues to protect the process.

### 5. Automated verification

**New `internal/netmonitor/unix/seccomp_waitkill_test.go`** (white-box):
- Installs a filter with `UnixSocketEnabled: true`
- Calls `filt.GetWaitKill()` on the loaded filter
- Asserts the attribute readback == `true` on kernel ≥6.0 hosts
- Skips with clear reason on older kernels
- Also asserts `waitKillSet` path didn't hit the Load retry fallback on ≥6.0

**New `internal/netmonitor/unix/seccomp_retry_test.go`:**
- Simulates `Load()` failure with WaitKill set
- Verifies `filt.SetWaitKill(false)` + retry path (seccomp_linux.go:364–374) succeeds
- Protects the existing fallback against accidental removal

**Matrix expansion in `.github/workflows/release.yml` `docker-test`:**
- Add `ubuntu:22.04` (ships libseccomp 2.5.3, glibc 2.35 — oldest supported LTS userspace)
- Add `debian:bookworm` (ships libseccomp 2.5.4 — recent stable with pre-2.6 package)

Matrix intent: Docker containers share the host kernel (GitHub runner's), so the interesting variable is the container's userspace — glibc and the package-provided libseccomp. Static linking should make the container's libseccomp version irrelevant; the two new rows prove that by exercising binaries on hosts whose system libseccomp is pre-2.6.

### 6. Manual gate for arm64 VM

The original reproducer for PR #225 required an arm64 Linux VM with Go's SIGURG preemption triggering under load. This cannot be reduced to a Dockerfile-runnable test without a kernel + user-space workload setup that exceeds CI budget.

**Mitigation:** Add a release checklist item in the runbook:
> Before cutting a release that touches seccomp, run the arm64 VM smoke test documented in `docs/testing/arm64-sigurg-reproducer.md` (to be written). Record pass/fail in the release PR.

Write the runbook doc as part of this work.

## Error handling

| Failure | Detection | Behavior |
|---|---|---|
| Build against libseccomp < 2.6 | `#error` in `seccomp_version_check.go` | Compile fails with actionable message |
| `scripts/build-libseccomp.sh` fails (network, signature, configure) | Script exits non-zero | CI job fails immediately; no silent fallback |
| `SetWaitKill(true)` returns error on kernel ≥6.0 | `slog.Warn` | Continue with Layer 2; don't fail the process |
| `Load()` rejects WaitKill flag (custom kernel) | Existing retry at seccomp_linux.go:364–374 | Already handled; locked in by `seccomp_retry_test.go` |
| Attr readback test fails in CI | Unit test fails | Blocks merge — signals build did not link 2.6 |
| arm64 real-VM regression | Manual runbook | Recorded in release PR; not automated |

## Rollout (single PR)

1. Add `scripts/build-libseccomp.sh`
2. Add `internal/netmonitor/unix/seccomp_version_check.go` + duplicate in `cmd/agentsh-unixwrap/seccomp_version_check.go`
3. Update `.github/workflows/release.yml`:
   - Run `build-libseccomp.sh` for amd64 and arm64 before the Go build
   - Add `CGO_LDFLAGS="-static -lseccomp"` to unixwrap-linux-{amd64,arm64} build steps
   - Extend `docker-test` matrix with `ubuntu:22.04` and `debian:bookworm`
4. Update `.goreleaser.yml`: matching CGO_LDFLAGS for unixwrap-linux-{amd64,arm64}
5. Modify `internal/netmonitor/unix/seccomp_linux.go`: Warn-on-unexpected-disable (lines 236–242)
6. Add `internal/netmonitor/unix/seccomp_waitkill_test.go` (white-box attr readback)
7. Add `internal/netmonitor/unix/seccomp_retry_test.go` (Load retry fallback)
8. Add `docs/testing/arm64-sigurg-reproducer.md` (manual runbook)
9. Update `docs/superpowers/specs/2026-04-13-sigurg-seccomp-preemption-fix-design.md`: note libseccomp version is now enforced at build time

Single PR coupling rationale: the `#error` guard cannot land without `build-libseccomp.sh` (CI would fail immediately on 24.04-provided headers). The Warn path cannot land without tests verifying it. Splitting creates a broken intermediate state.

## Out of scope (deferred)

- **Migrating to `runs-on: ubuntu-26.04`** — possible when GitHub ships the image. At that point `scripts/build-libseccomp.sh` becomes redundant and can be deleted. Not required by this spec.
- **Layer 1 on BSD / macOS** — Linux-only concern.
- **Runtime downgrade detection** — the `#error` guard handles this at build; runtime Warn handles residual cases. No need for additional runtime logic.

## Reversibility

- Static-linking adds ~600KB to each unixwrap binary.
- No runtime behavior change on hosts where Layer 1 was already working.
- Revert: delete `scripts/build-libseccomp.sh`, `seccomp_version_check.go` (×2), and the release.yml / .goreleaser.yml additions. No data migration, no protocol change, no user-visible breakage.
