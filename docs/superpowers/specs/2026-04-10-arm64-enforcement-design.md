# arm64 Enforcement + Detect Accuracy

**Date:** 2026-04-10
**Status:** Draft

## Problem

arm64 Linux releases ship with kernel-level enforcement effectively off:

1. `agentsh-unixwrap` is not built for arm64 — `.goreleaser.yml` only has an amd64 target because cross-compiling requires `libseccomp-dev:arm64`.
2. The arm64 server binary is built with `CGO_ENABLED=0`, so seccomp/signal/notify handlers compile as no-op stubs.
3. On arm64, the server logs "running without seccomp enforcement" at startup and skips seccomp filter installation and Landlock setup.
4. `agentsh detect` still reports 100/100 because it probes kernel capabilities (seccomp, Landlock, FUSE support), not whether the wrapper binary is present or enforcement is active.

Net effect: arm64 installs have no seccomp interception, no Landlock scoping, and no signal filtering — but the self-test reports full capability.

## Solution

Two changes:

1. **Build unixwrap and server for arm64 with CGO enabled** by cross-compiling on the existing release runner.
2. **Make `detect` check for the wrapper binary** and mark seccomp/Landlock backends as unavailable when it's missing.

## Part 1: arm64 Cross-Compilation

### CI Changes (`release.yml`)

Add multi-arch apt support and `libseccomp-dev:arm64` to the goreleaser job's "Install build deps" step:

```yaml
- name: Install build deps (envshim, fuse, seccomp)
  run: |
    sudo dpkg --add-architecture arm64
    sudo apt-get update
    sudo apt-get install -y \
      libseccomp-dev \
      libseccomp-dev:arm64 \
      libfuse-dev \
      pkg-config \
      gcc-aarch64-linux-gnu \
      make
```

`gcc-aarch64-linux-gnu` is already installed. The only new package is `libseccomp-dev:arm64` (plus the `dpkg --add-architecture` setup).

The `ci.yml` cross-compile matrix keeps `CGO_ENABLED=0` for arm64 — that job is build-verification, not release.

### GoReleaser Changes (`.goreleaser.yml`)

**New build target — unixwrap for arm64:**

```yaml
- id: unixwrap-linux-arm64
  main: ./cmd/agentsh-unixwrap
  binary: agentsh-unixwrap
  env:
    - CGO_ENABLED=1
    - CC=aarch64-linux-gnu-gcc
    - PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
  goos:
    - linux
  goarch:
    - arm64
  ldflags:
    - -s -w
```

This mirrors how `build-envshim.sh` and `build-ptracer.sh` already cross-compile for arm64: same `CC=aarch64-linux-gnu-gcc`, with `PKG_CONFIG_PATH` pointing to the arm64 sysroot so `pkg-config` finds the correct `libseccomp.pc`.

**Flip server arm64 build to CGO_ENABLED=1:**

```yaml
- id: agentsh-linux-arm64
  main: ./cmd/agentsh
  binary: agentsh
  env:
    - CGO_ENABLED=1
    - CC=aarch64-linux-gnu-gcc
    - PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
  goos:
    - linux
  goarch:
    - arm64
  ldflags:
    - -s -w -X main.version={{.Version}} -X main.commit={{.ShortCommit}}
```

The arm64 server binary now compiles with real signal/notify handlers instead of stubs.

**Add unixwrap-linux-arm64 to packaging:**

Archives section — add `unixwrap-linux-arm64` to the `agentsh-linux` archive's `ids` list. Remove `allow_different_binary_count: true` since both architectures now produce the same binary set.

nfpms section — add `unixwrap-linux-arm64` to the `agentsh` package's `ids` list. Remove the "unixwrap not available for arm64" comment.

## Part 2: Detect Wrapper Check

### Location

`internal/capabilities/detect_linux.go`, in the `Detect()` function.

### Logic

After building domains from `buildLinuxDomains()` but before calling `ComputeScore()`, check whether `agentsh-unixwrap` is on PATH via `exec.LookPath`. If not found, mark the following backends as unavailable:

| Domain | Backend | Why |
|--------|---------|-----|
| File Protection | `seccomp-notify` | Wrapper installs the BPF user-notify filter |
| File Protection | `landlock` | Wrapper calls `applyLandlock()` |
| Command Control | `seccomp-execve` | Wrapper installs the execve BPF filter |

**Backends NOT affected:**

| Domain | Backend | Why |
|--------|---------|-----|
| File Protection | `fuse` | Mounted by the server process |
| Command Control | `ptrace` | Server-side `PTRACE_SEIZE`, independent of wrapper |
| Network | all | Independent of wrapper |
| Resource Limits | all | Independent of wrapper |
| Isolation | all | Independent of wrapper |

### Implementation

Add a helper function `applyWrapperAvailability(domains []ProtectionDomain)` that:

1. Calls `exec.LookPath("agentsh-unixwrap")`.
2. If the binary is not found, iterates over domains and sets `Available = false` for the three affected backends (`seccomp-notify`, `landlock`, `seccomp-execve`).
3. Returns a boolean indicating whether the wrapper was found (used for tip generation).

Call this in `Detect()` between `buildLinuxDomains()` and `ComputeScore()`.

The function must also update the `Active` field for affected domains. If the currently active backend is one of the three being disabled, `Active` should fall back to the next available backend in the domain (e.g., Command Control falls back from `seccomp-execve` to `ptrace` if ptrace is available, or to `""` if not). This keeps the `Active` field consistent with backend availability.

### Tip

When the wrapper is missing, add a tip to the result:

```
Feature: seccomp-wrapper
Status:  missing
Impact:  seccomp and Landlock enforcement disabled — processes run without kernel-level interception
Action:  install agentsh-unixwrap or rebuild the package with CGO_ENABLED=1
```

### FileEnforcement Update

`SecurityCapabilities.FileEnforcement` is set before `buildLinuxDomains()` by `detectFileEnforcementBackend()`. If the wrapper is missing and `FileEnforcement` is `"landlock"` or `"seccomp-notify"`, `applyWrapperAvailability()` must also update it to the next available backend (`"fuse"` if available, otherwise `"none"`). This keeps the `backwardCompatCaps` output and the domain's `Active` field consistent.

### Score Impact

On a system with full kernel support but no wrapper:
- File Protection (25): remains 25 if FUSE is available (FUSE is server-side)
- Command Control (25): remains 25 if ptrace is available (ptrace is server-side)
- Other domains: unaffected

The main value is per-backend accuracy — `seccomp-notify: -` instead of `seccomp-notify: ✓` — and the explicit tip. The score drops meaningfully only on systems that also lack FUSE and ptrace.

### Test

Add a unit test in `detect_linux_test.go` (or the existing test file for detect) that:
- Mocks `exec.LookPath` to return an error (wrapper not found)
- Calls `Detect()`
- Asserts that `seccomp-notify`, `landlock`, and `seccomp-execve` backends are `Available = false`
- Asserts that `fuse` and `ptrace` backends retain their probed values
- Asserts that the tip for `seccomp-wrapper` is present

## Files Changed

| File | Change |
|------|--------|
| `.goreleaser.yml` | New `unixwrap-linux-arm64` build; flip `agentsh-linux-arm64` to CGO=1; update archives + nfpms |
| `.github/workflows/release.yml` | Add `dpkg --add-architecture arm64` + `libseccomp-dev:arm64` |
| `internal/capabilities/detect_linux.go` | Add `applyWrapperAvailability()`, call from `Detect()` |
| `internal/capabilities/detect_linux_test.go` | Test for wrapper-missing scenario |

## Out of Scope

- Build-time CGO flag embedding (checking whether the binary itself was built with CGO)
- Runtime server health probing from detect
- Changes to `ci.yml` (build-verification only, not release)
