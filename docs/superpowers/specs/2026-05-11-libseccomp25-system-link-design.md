# libseccomp 2.5 System-Link Design

**Date:** 2026-05-11
**Status:** Approved design — ready for implementation plan
**Related:** [2026-04-14 libseccomp 2.6 defense-in-depth](./2026-04-14-libseccomp-2.6-defense-in-depth-design.md) (this design supersedes the source-build + static-link approach), PR #225 (SIGURG fix), Issue #296 (vendor libseccomp 2.6).

## Problem

We require libseccomp 2.6 at build time for one filter attribute: `SCMP_FLTATR_CTL_WAITKILL`, which sets the kernel flag `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (value `0x20`, kernel ≥5.19). This is Layer 1 of the SIGURG preemption fix from PR #225 — without it, Go's async preemption can hit `seccomp_do_user_notification()` mid-flight and trigger ERESTARTSYS infinite-retry loops.

The reason libseccomp 2.6 is required today is libseccomp-golang's silent-no-op preprocessor trap:

```c
#if SCMP_VER_MAJOR == 2 && SCMP_VER_MINOR < 6
#define SCMP_FLTATR_CTL_WAITKILL _SCMP_FLTATR_MIN   // == 0, a no-op
#endif
```

Building against 2.5 headers makes `SetWaitKill(true)` return success without setting the kernel flag — Layer 1 dies silently. The 2026-04-14 design responded by source-building libseccomp 2.6 in CI, statically linking it into the unixwrap binary (~600KB bloat per arch), and guarding the headers with `#error`.

**The kernel flag itself is not a libseccomp feature.** It's a kernel ABI number (`0x20`, present in `golang.org/x/sys/unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` since x/sys v0.17). libseccomp 2.6 only added a convenience wrapper; libseccomp ≥2.0 has always been able to *build* a BPF program that we can then load ourselves with whatever flags we want.

Issue #296 surfaces the cost of the current approach: RHEL 10 ships libseccomp 2.5.x, and EPEL has nothing newer. Anyone building from source on RHEL/Debian-stable/Ubuntu-LTS hits the `#error` and is told to run our source-build script.

## Goals

1. Default Linux builds link against system libseccomp 2.5.x (`apt install libseccomp-dev`, `dnf install libseccomp-devel`) — no source build, no static link, no `#error` guard.
2. Layer 1 (WAIT_KILLABLE_RECV) stays alive on kernel ≥5.19 regardless of libseccomp version on either build host or runtime host.
3. Binary is ABI-portable: built against 2.5 headers, runs on 2.5.x and 2.6.x hosts identically.
4. Issue #296 closes — source builds on RHEL 10 / Debian-stable / Ubuntu-LTS work out of the box.
5. CI proves full feature parity (Layer 1 engaged + functional notify behavior) across a matrix of build-vs-runtime libseccomp versions.

## Non-goals

- Replacing libseccomp-golang for rule modeling. We keep it for `ScmpFilter` construction.
- Changing Layer 2 (SIGURG mask in `cmd/agentsh-unixwrap/main.go`). It stays as belt-and-suspenders.
- Touching the Alpine musl build, which keeps its static link against `libseccomp-static` 2.6.0 (Alpine ships 2.6 in `apk`).
- Adding a kernel-<5.19 CI lane (GitHub runners are kernel 6.x; unit-test stub covers the degradation path).
- Vendoring libseccomp source into the repo (the design eliminates the need entirely).

## Architecture

### Today's load pipeline

In `internal/netmonitor/unix/seccomp_linux.go` (lines 297–525):

1. Build `*seccomp.ScmpFilter` and register rules via `AddRule` / `AddRuleConditional`.
2. `ProbeWaitKillable()` → kernel ≥6.0 check.
3. `filt.SetWaitKill(true)` — silently no-ops on pre-2.6 headers.
4. `filt.Load()` — internally does `prctl(PR_SET_NO_NEW_PRIVS)` + `seccomp(SET_MODE_FILTER, flags, prog)` where `flags` is computed from filter attributes (including WAITKILL if set).
5. `loadWithRetryOnWaitKillFailure` — on EINVAL, clears WAITKILL and retries once.
6. `filt.GetNotifFd()` — pulls out the listener fd from libseccomp-golang's internal state.

### New load pipeline

Rule registration unchanged (steps 1, 2 above). The fork happens at load time:

1. Build `*seccomp.ScmpFilter` and register rules — unchanged.
2. `ProbeWaitKillable()` — unchanged.
3. **Export BPF via `filt.ExportBPF(pipeWriter)`.** Create `pipe2(O_CLOEXEC)`, run a goroutine reading the read end into a `bytes.Buffer`, pass the write end to `ExportBPF`, close it, join the goroutine. Works on libseccomp ≥2.0 — does *not* use the 2.6-only `ExportBPFMem`.
4. **`filt.Release()`** the ScmpFilter — its C context is no longer needed; we own the BPF bytes now.
5. **Load via raw syscall** with a new helper `loadRawFilter(prog []byte, withWaitKill bool) (listenerFD int, err error)`:
   - `unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`
   - Parse the exported bytes into `[]unix.SockFilter` (each is 8 bytes: `code uint16, jt uint8, jf uint8, k uint32`) and build `unix.SockFprog{Len: uint16(n), Filter: &filter[0]}`.
   - `flags := unix.SECCOMP_FILTER_FLAG_NEW_LISTENER`; if `withWaitKill`, `flags |= unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`.
   - `fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, uintptr(flags), uintptr(unsafe.Pointer(&fprog)))`.
   - On success, return `int(fd)`. On EINVAL, return wrapped errno (caller decides retry).
6. **Retry on EINVAL** in a new wrapper `loadFilterWithRetry(prog []byte, withWaitKill bool, snapshot []any) (int, error)` — same retry shape as today's `loadWithRetryOnWaitKillFailure`: drop the WAIT_KILLABLE flag, retry once, emit the existing `slog.Warn("seccomp: WaitKillable rejected at filter load time…")`.
7. `Filter.fd` is set from the syscall return value directly — no `GetNotifFd()` call.

### Files

**New:**
- `internal/netmonitor/unix/seccomp_load_linux.go` (~120 lines): `exportFilterBPF(filt *ScmpFilter) ([]byte, error)` (pipe-based), `loadRawFilter(prog []byte, withWaitKill bool) (int, error)`, `loadFilterWithRetry(prog []byte, withWaitKill bool, snapshot []any) (int, error)`.

**Modified:**
- `internal/netmonitor/unix/seccomp_linux.go`: replace lines ~297–534 (SetWaitKill block + Load + GetNotifFd) with the new export+load sequence. Emit the startup log line described in the testing section.

**Deleted:**
- `internal/netmonitor/unix/seccomp_version_check.go` — `#error` guard no longer needed.
- `cmd/agentsh-unixwrap/seccomp_version_check.go` — duplicate guard, same reason.
- `scripts/build-libseccomp.sh` — no source build.
- `scripts/libseccomp-signing-key.asc` — used only by the build script.

## Error handling

| Failure | Detection | Behavior |
|---|---|---|
| `pipe2` fails | errno from syscall | Return wrapped error; load aborted |
| `ExportBPF` fails | libseccomp returns non-zero | Return wrapped error |
| Exported BPF is empty (0 instructions) | `len(prog) == 0` | Return `fmt.Errorf("seccomp export produced empty filter")` — guards against libseccomp regressions |
| `prctl(PR_SET_NO_NEW_PRIVS)` fails | errno | Return wrapped error |
| `seccomp(SET_MODE_FILTER, NEW_LISTENER\|WAIT_KILLABLE, …)` returns EINVAL | errno | Retry once with `withWaitKill=false`; emit existing `slog.Warn("seccomp: WaitKillable rejected at filter load time…")` |
| Retry also fails | errno | Emit existing `slog.Warn("seccomp: filter Load failed on retry without WaitKill…")` with diagnostic snapshot; return error |
| Kernel < 5.19 (probe returns false) | `ProbeWaitKillable() == false` | Load with `withWaitKill=false` from the start; no retry needed; Layer 2 in `unixwrap` provides degraded protection |
| Other errno (E2BIG, EFAULT, EPERM) | errno | Return as-is — same surface as today's `Load()` failures (#282-class), pre-load diagnostic snapshot already logged at WARN |

`filterDiagnosticFields` and the WARN snapshot logic in `seccomp_linux.go` stay unchanged.

## Tests & verification

### How "Layer 1 engaged" is measured

Emit one startup log line in `seccomp_linux.go` right after the raw load returns:

```
seccomp: filter loaded fd=N wait_killable=true|false kernel_supports=true|false libseccomp_runtime=2.5.5
```

- `wait_killable=true` iff the syscall succeeded with `WAIT_KILLABLE_RECV` set. By construction the kernel accepted both `NEW_LISTENER` and `WAIT_KILLABLE_RECV` (or it would have returned EINVAL and we'd be in the retry path).
- `libseccomp_runtime` comes from `seccomp.GetLibraryVersion()` — the *runtime-linked* version, not the build-time version.

Docker tests assert this line.

### Unit tests (`internal/netmonitor/unix/seccomp_load_linux_test.go`)

- `TestRawLoad_AcceptsWaitKillOnSupportedKernel` — skip on kernel <6.0; build minimal filter; `loadRawFilter(prog, true)`; assert fd > 0 and no error.
- `TestRawLoad_FallsBackOnEinval` — inject a fake syscall seam returning EINVAL once then succeed; assert second call drops the WAIT_KILLABLE flag and the WARN log fires.
- `TestRawLoad_RejectsEmptyProgram` — zero-length prog → explicit "empty filter" error.
- `TestRawLoad_KernelLT519_SkipsFlag` — stub `ProbeWaitKillable` to false; assert syscall flags == `NEW_LISTENER` only.
- `TestExportBPFViaPipe` — end-to-end exporter exercise: build trivial filter, export, parse first instruction, assert it's a `BPF_LD | BPF_W | BPF_ABS` loading the seccomp_data nr field (libseccomp's standard prologue).

### Existing tests

- `seccomp_retry_test.go` — adapt to the new helper signature; retry semantics stay locked in.
- `seccomp_waitkill_test.go` — **delete**. It relied on `filt.GetWaitKill()` readback; that's never true under the new path because we set the flag on the syscall, not on the libseccomp filter attribute.
- `internal/api/seccomp_wrapper_shim_install_test.go` — audit and update references to the deleted version-check file.

### Docker test matrix (`.github/workflows/release.yml` `docker-test` job)

Runners are GitHub `ubuntu-latest` (Ubuntu 24.04, kernel 6.x). Container userspace varies, kernel stays ≥6.0 in every cell:

| Container | Build → Runtime libseccomp | Startup log assertion | Closes |
|---|---|---|---|
| `ubuntu:22.04` | 2.5.5 → 2.5.3 | `wait_killable=true` | |
| `ubuntu:24.04` | 2.5.5 → 2.5.5 | `wait_killable=true` | |
| `debian:bookworm` | 2.5.5 → 2.5.4 | `wait_killable=true` | |
| `debian:trixie` | 2.5.5 → 2.6.x | `wait_killable=true` | forward-ABI: newer runtime than build |
| `rockylinux:10` | 2.5.5 → 2.5.x | `wait_killable=true` | #296 |
| `fedora:40` | 2.5.5 → 2.5.x | `wait_killable=true` | |
| `alpine:3.23` | 2.6.0 → 2.6.0 (static, musl) | `wait_killable=true` | unchanged Alpine path |

Seven rows. Six exercise the new default 2.5-build path against five distinct runtime libseccomp versions including one *newer* than build (debian:trixie) — proves forward ABI compatibility. The seventh keeps Alpine honest.

### Functional smoke test in each cell

Beyond the log assertion, each container runs a scripted scenario that exercises every Layer-1-relevant code path:

1. `unixwrap` launches a child that opens a unix socket — exercises `UnixSocketEnabled` ActNotify rule. Asserts the supervisor handles the notify (existing assertion).
2. `unixwrap` blocks a syscall via `OnBlockKill` — exercises kernel fast-path action; proves the filter is live (no Layer 1 dependency, but the most reliable "is it installed" signal).
3. **SIGURG sanity check (best-effort).** A small Go program issues a notify-trapping syscall in a tight loop while another goroutine spams `SIGURG` at the same OS thread. Asserts the program terminates with exit 0 within 5 s. On kernel ≥5.19 with WAIT_KILLABLE_RECV engaged, this completes deterministically. On the original failing setup (arm64 real VM under load, PR #225), the ERESTARTSYS loop manifested reliably; on amd64 Docker the race window is small enough that absence-of-hang is not a hard regression-catcher — false-negatives are possible. Treat this as a sanity probe, not a guarantee.

Item 3 is the new piece, with caveats. The startup log line (kernel accepted the flag) plus the existing notify smoke (filter is functional end-to-end) are the primary assertions; item 3 catches the most catastrophic regressions where the flag is accepted but completely broken.

### Why not a hard SIGURG regression test in docker

The original PR #225 repro required an arm64 real VM under sustained workload to make Go's async preemption land inside `seccomp_do_user_notification()` with high probability. The 2026-04-14 design called this out: "cannot be reduced to a Dockerfile-runnable test without a kernel + user-space workload setup that exceeds CI budget." That assessment still stands. The arm64-VM reproducer remains the manual release gate (see `docs/testing/arm64-sigurg-reproducer.md`); the docker sanity probe is a cheap addition that catches gross breakage without claiming to replace it.

### Kernel-too-old coverage

GitHub runners are kernel 6.x; we can't get a <5.19 host kernel in CI without a self-hosted runner. `TestRawLoad_KernelLT519_SkipsFlag` covers the degradation path via probe-stub. Layer 2 SIGURG mask is the operative mitigation on old kernels and that path doesn't change.

### Manual gate

The arm64-VM SIGURG reproducer from the 2026-04-14 design stays a release-checklist item (`docs/testing/arm64-sigurg-reproducer.md`). No automation change.

## CI changes

### `.github/workflows/release.yml`

- **Delete** the "Build static libseccomp 2.6 (amd64 + arm64)" step (~lines 73–78).
- **Replace** `CGO_LDFLAGS="-static -lseccomp"` and `PKG_CONFIG_LIBDIR=/opt/libseccomp/...` on the amd64/arm64 unixwrap build steps with the default dynamic link. Base image already has `libseccomp-dev` 2.5.5 via apt.
- **Drop** the `hashFiles('scripts/build-libseccomp.sh')` cache-key salt (script's gone).
- **Keep** Alpine `unixwrap-alpine-*` build steps with `-static -lseccomp` — Alpine ships static libseccomp 2.6 by default; musl static binaries are the value-add of the Alpine artifact.
- **Expand** `docker-test` matrix per the table above (add `ubuntu:24.04`, `debian:trixie`, `rockylinux:10`, `fedora:40`; keep `ubuntu:22.04`, `debian:bookworm`, `alpine:3.23`).

### `.goreleaser.yml`

Mirror the release.yml changes — drop the static CGO_LDFLAGS for amd64/arm64 Linux unixwrap entries.

## Rollout (single PR)

1. Add `internal/netmonitor/unix/seccomp_load_linux.go` (new raw loader + pipe exporter).
2. Modify `internal/netmonitor/unix/seccomp_linux.go`: replace SetWaitKill+Load+GetNotifFd block with ExportBPF+loadFilterWithRetry; emit the startup log line.
3. Delete `internal/netmonitor/unix/seccomp_version_check.go` and `cmd/agentsh-unixwrap/seccomp_version_check.go`.
4. Delete `scripts/build-libseccomp.sh` and `scripts/libseccomp-signing-key.asc`.
5. Update `.github/workflows/release.yml` (build steps + docker-test matrix) and `.goreleaser.yml`.
6. Add `seccomp_load_linux_test.go`; adapt `seccomp_retry_test.go`; delete `seccomp_waitkill_test.go`; audit `seccomp_wrapper_shim_install_test.go`.
7. Add the SIGURG functional repro script run in each docker-test cell.
8. Update `docs/superpowers/specs/2026-04-14-libseccomp-2.6-defense-in-depth-design.md` with a "superseded by 2026-05-11-libseccomp25-system-link-design.md" header.
9. PR description: closes #296.

Single PR coupling: the deletes can't land without the new load path, and the new load path can't be tested without the matrix expansion. Splitting creates a broken intermediate state.

## Risks

- **Runtime dependency on `libseccomp.so.2`.** Mitigation: the library is in the base package set of every modern Linux distro (`libseccomp2` on Debian/Ubuntu, `libseccomp` on RHEL/Fedora). Truly minimal containers (`FROM scratch`, distroless) would have already broken on the cgo binary regardless of static link. No new failure mode for realistic deployments.
- **Pipe-export goroutine adds a concurrent surface.** Mitigation: synchronous read into a bounded `bytes.Buffer` from a `*os.File` read end; goroutine exits when writer closes; no error channel needed. Plumbing covered by `TestExportBPFViaPipe`.
- **Losing the 2.6 transaction APIs / `seccomp_precompute`.** We don't use them today. Acceptable; revisit if we ever need them.
- **Forward compatibility with libseccomp 3.x.** ABI break unlikely (libseccomp has been ABI-stable for a decade), but the design is also forward-compatible — we use the kernel ABI directly for load, so libseccomp only needs to build BPF.

## Reversibility

`git revert` restores the static-link + `#error` design end-to-end. No data migration, ABI change, or protocol change. Downstream packagers benefit immediately; nothing they relied on disappears (the binary still links libseccomp, just dynamically and against the system version).
