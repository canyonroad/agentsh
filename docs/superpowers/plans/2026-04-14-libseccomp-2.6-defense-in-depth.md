# libseccomp 2.6 Defense-in-Depth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Guarantee the Layer 1 SIGURG fix (`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`) is actually compiled into every shipped Linux binary — via static-linked libseccomp 2.6, compile-time `#error` guard, runtime warn-on-unexpected-disable, and attr-readback tests.

**Architecture:** Build libseccomp 2.6 from source in CI (amd64 + cross arm64), static-link it into the unixwrap binaries, and install a CGo `#error` guard so any build against pre-2.6 headers fails loudly. Add a runtime `slog.Warn` for the residual "kernel supports it but libseccomp didn't" case, plus unit tests that confirm the attribute actually round-trips on kernels ≥6.0.

**Tech Stack:** Go 1.25, CGo, libseccomp 2.6.0 (built from source tarball), libseccomp-golang v0.11.0, GoReleaser v2.13.1, GitHub Actions `ubuntu-latest` (currently Ubuntu 24.04 = libseccomp 2.5.5 from apt), Docker (integration test matrix).

**Spec:** `docs/superpowers/specs/2026-04-14-libseccomp-2.6-defense-in-depth-design.md`

---

## File Structure

| Path | Disposition | Purpose |
|---|---|---|
| `scripts/build-libseccomp.sh` | Create | Source-build libseccomp 2.6.0 statically for amd64 or arm64 |
| `internal/netmonitor/unix/seccomp_version_check.go` | Create | CGo `#error` guard in the shared package |
| `cmd/agentsh-unixwrap/seccomp_version_check.go` | Create | Duplicate guard so the wrapper binary fails independently |
| `internal/netmonitor/unix/seccomp_linux.go` | Modify (lines ~236–242, 359–375) | Warn on unexpected Layer 1 disable; extract `loadWithRetryOnWaitKillFailure` helper |
| `internal/netmonitor/unix/seccomp_retry_test.go` | Create | Unit test for the retry-without-WaitKill fallback helper |
| `internal/netmonitor/unix/seccomp_waitkill_test.go` | Create | White-box test: install filter, `GetWaitKill()` readback == true on kernel ≥6.0 |
| `.goreleaser.yml` | Modify (unixwrap-linux-amd64/arm64 envs) | CGO_LDFLAGS + PKG_CONFIG_PATH pointing at our static build |
| `.github/workflows/release.yml` | Modify (build deps + docker-test matrix) | Run `build-libseccomp.sh` before goreleaser; add ubuntu:22.04 row to matrix |
| `Dockerfile.test.ubuntu2204` | Create | New test image — oldest LTS userspace, pre-2.6 libseccomp installed |
| `docs/testing/arm64-sigurg-reproducer.md` | Create | Manual release runbook for the arm64-VM regression check |
| `docs/superpowers/specs/2026-04-13-sigurg-seccomp-preemption-fix-design.md` | Modify (append note) | Record that libseccomp version is now enforced at build time |

Note on `debian:bookworm` from the spec: the existing `Dockerfile.test` already uses `debian:bookworm-slim`, so that row is already present in the matrix. Only `ubuntu:22.04` is additive.

---

## Task 1: Add `scripts/build-libseccomp.sh`

**Files:**
- Create: `scripts/build-libseccomp.sh`

- [ ] **Step 1: Write the build script**

Write `scripts/build-libseccomp.sh`:

```bash
#!/usr/bin/env bash
# Build libseccomp 2.6.0 as a static library for either amd64 or arm64.
# Installs to /opt/libseccomp/<arch>/{lib,include,lib/pkgconfig}.
#
# Usage:
#   TARGET=amd64 ./scripts/build-libseccomp.sh
#   TARGET=arm64 ./scripts/build-libseccomp.sh
#
# Requires on the build host (for arm64):
#   gcc-aarch64-linux-gnu make pkg-config
#
# Requires (for both):
#   curl gpg tar make gcc

set -euo pipefail

VERSION="${LIBSECCOMP_VERSION:-2.6.0}"
TARGET="${TARGET:-amd64}"
PREFIX="/opt/libseccomp/${TARGET}"
SRC_URL="https://github.com/seccomp/libseccomp/releases/download/v${VERSION}/libseccomp-${VERSION}.tar.gz"
SIG_URL="${SRC_URL}.asc"
# Paul Moore <paul@paul-moore.com> — libseccomp release signing key
# Fingerprint pinned to block key-substitution attacks. Verify upstream at
# https://github.com/seccomp/libseccomp — README lists the signing key.
GPG_FPR="7100AADFAE6E6E940D2E0AD655E45A5AE8CA7C8A"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "=== libseccomp ${VERSION} static build for ${TARGET} → ${PREFIX} ==="

# Skip rebuild if artifact already present (CI caching).
if [ -f "${PREFIX}/lib/libseccomp.a" ] && [ -f "${PREFIX}/lib/pkgconfig/libseccomp.pc" ]; then
    echo "Already installed at ${PREFIX}; skipping."
    exit 0
fi

cd "$WORKDIR"

# Download tarball + signature.
curl -fsSL "$SRC_URL" -o "libseccomp-${VERSION}.tar.gz"
curl -fsSL "$SIG_URL" -o "libseccomp-${VERSION}.tar.gz.asc"

# Verify signature — fail the build rather than risk a supply-chain compromise.
export GNUPGHOME="${WORKDIR}/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$GPG_FPR"
gpg --batch --verify "libseccomp-${VERSION}.tar.gz.asc" "libseccomp-${VERSION}.tar.gz"

tar -xzf "libseccomp-${VERSION}.tar.gz"
cd "libseccomp-${VERSION}"

# Configure for static-only build.
CONFIGURE_ARGS=(
    --prefix="$PREFIX"
    --disable-shared
    --enable-static
    --disable-python
)

case "$TARGET" in
    amd64)
        ./configure "${CONFIGURE_ARGS[@]}"
        ;;
    arm64)
        CC=aarch64-linux-gnu-gcc \
        ./configure --host=aarch64-linux-gnu "${CONFIGURE_ARGS[@]}"
        ;;
    *)
        echo "ERROR: unknown TARGET=${TARGET} (expected amd64 or arm64)" >&2
        exit 1
        ;;
esac

make -j"$(nproc)"
sudo make install

# Sanity check the install.
test -f "${PREFIX}/lib/libseccomp.a" || { echo "missing libseccomp.a"; exit 1; }
test -f "${PREFIX}/lib/pkgconfig/libseccomp.pc" || { echo "missing pkgconfig"; exit 1; }
echo "=== OK: ${PREFIX}/lib/libseccomp.a ($(stat -c %s "${PREFIX}/lib/libseccomp.a") bytes) ==="
```

- [ ] **Step 2: Make executable**

```bash
chmod +x scripts/build-libseccomp.sh
```

- [ ] **Step 3: Smoke-test the script locally for amd64**

```bash
TARGET=amd64 ./scripts/build-libseccomp.sh
```

Expected: script completes successfully, prints `=== OK: /opt/libseccomp/amd64/lib/libseccomp.a (<some bytes>) ===`. Verify:

```bash
ls -la /opt/libseccomp/amd64/lib/libseccomp.a /opt/libseccomp/amd64/lib/pkgconfig/libseccomp.pc
```

Expected: both files exist.

If the script fails because `gcc-aarch64-linux-gnu` is not installed on your local machine, note: you only need to test amd64 locally. arm64 cross-build runs in CI where the cross-toolchain is installed.

**Host prerequisites:** Also `gperf` must be installed on the build host (libseccomp 2.6 uses it at `./configure` time for hash-table generation). On Arch: `sudo pacman -S gperf`. On Debian/Ubuntu: `sudo apt-get install -y gperf`. Task 9 adds `gperf` to the CI apt-install list.

- [ ] **Step 4: Commit**

```bash
git add scripts/build-libseccomp.sh
git commit -m "build: add source-build script for static libseccomp 2.6.0"
```

---

## Task 2: Add compile-time `#error` guard in `internal/netmonitor/unix`

**Files:**
- Create: `internal/netmonitor/unix/seccomp_version_check.go`

- [ ] **Step 1: Create the guard file**

Write `internal/netmonitor/unix/seccomp_version_check.go`:

```go
//go:build linux && cgo

package unix

// Compile-time assertion that libseccomp >= 2.6.0 headers are in use.
//
// Why this matters: libseccomp-golang v0.11.0 contains a preprocessor
// fallback that remaps SCMP_FLTATR_CTL_WAITKILL to _SCMP_FLTATR_MIN (a
// no-op sentinel) when built against pre-2.6 headers. In that state the
// Go-level SetWaitKill(true) call silently succeeds but sets no real
// kernel flag — Layer 1 of the SIGURG preemption fix dies silently.
//
// This #error ensures any build against pre-2.6 headers fails loudly
// with an actionable message pointing at scripts/build-libseccomp.sh.

// #include <seccomp.h>
// #if SCMP_VER_MAJOR < 2 || (SCMP_VER_MAJOR == 2 && SCMP_VER_MINOR < 6)
// #error "libseccomp >= 2.6.0 required for SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (Layer 1 SIGURG fix). Run scripts/build-libseccomp.sh and set PKG_CONFIG_PATH=/opt/libseccomp/<arch>/lib/pkgconfig."
// #endif
import "C"
```

- [ ] **Step 2: Verify the build succeeds with current libseccomp linkage**

```bash
PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig CGO_ENABLED=1 go build ./internal/netmonitor/unix/...
```

Expected: success (exit 0). Our script installed 2.6, so the guard passes.

- [ ] **Step 3: Verify the guard fires against a pre-2.6 header path**

Temporarily create a fake old header to confirm the guard triggers:

```bash
mkdir -p /tmp/fake-old-seccomp/include /tmp/fake-old-seccomp/lib/pkgconfig
cat > /tmp/fake-old-seccomp/include/seccomp.h <<'EOF'
#ifndef _SECCOMP_H
#define _SECCOMP_H
#define SCMP_VER_MAJOR 2
#define SCMP_VER_MINOR 5
#define SCMP_VER_MICRO 5
#endif
EOF
cat > /tmp/fake-old-seccomp/lib/pkgconfig/libseccomp.pc <<'EOF'
prefix=/tmp/fake-old-seccomp
includedir=${prefix}/include
libdir=${prefix}/lib
Name: libseccomp
Version: 2.5.5
Libs: -lseccomp
Cflags: -I${includedir}
EOF
PKG_CONFIG_PATH=/tmp/fake-old-seccomp/lib/pkgconfig CGO_ENABLED=1 go build ./internal/netmonitor/unix/... 2>&1 | head -5
```

Expected: compile error mentioning `libseccomp >= 2.6.0 required`. Clean up the fake headers afterwards:

```bash
rm -rf /tmp/fake-old-seccomp
```

- [ ] **Step 4: Commit**

```bash
git add internal/netmonitor/unix/seccomp_version_check.go
git commit -m "seccomp: add #error guard for pre-2.6 libseccomp headers"
```

---

## Task 3: Duplicate guard in `cmd/agentsh-unixwrap`

**Files:**
- Create: `cmd/agentsh-unixwrap/seccomp_version_check.go`

- [ ] **Step 1: Create the duplicate guard**

Write `cmd/agentsh-unixwrap/seccomp_version_check.go`:

```go
//go:build linux && cgo

package main

// Duplicate of internal/netmonitor/unix/seccomp_version_check.go.
// Kept here independently so the wrapper binary fails to build even if
// the import graph changes and this package stops pulling in the unix
// package's CGo compilation unit.

// #include <seccomp.h>
// #if SCMP_VER_MAJOR < 2 || (SCMP_VER_MAJOR == 2 && SCMP_VER_MINOR < 6)
// #error "libseccomp >= 2.6.0 required for SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (Layer 1 SIGURG fix). Run scripts/build-libseccomp.sh and set PKG_CONFIG_PATH=/opt/libseccomp/<arch>/lib/pkgconfig."
// #endif
import "C"
```

- [ ] **Step 2: Verify the wrapper builds with it**

```bash
PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig CGO_ENABLED=1 go build -o /tmp/agentsh-unixwrap ./cmd/agentsh-unixwrap
```

Expected: success; `/tmp/agentsh-unixwrap` exists.

- [ ] **Step 3: Commit**

```bash
git add cmd/agentsh-unixwrap/seccomp_version_check.go
git commit -m "seccomp: duplicate #error guard in unixwrap main package"
```

---

## Task 4: Write failing retry test (TDD red)

**Files:**
- Create: `internal/netmonitor/unix/seccomp_retry_test.go`

- [ ] **Step 1: Write the test file calling a helper that does not exist yet**

Write `internal/netmonitor/unix/seccomp_retry_test.go`:

```go
//go:build linux && cgo

package unix

import (
	"errors"
	"testing"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// TestLoadWithRetryOnWaitKillFailure_RetriesOnWaitKillFailure verifies that
// when the first Load() call fails with WaitKill set, the helper calls
// SetWaitKill(false) and retries — reproducing the fallback path used for
// custom kernels that report >=6.0 but reject WAIT_KILLABLE_RECV.
func TestLoadWithRetryOnWaitKillFailure_RetriesOnWaitKillFailure(t *testing.T) {
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filt.Release()

	if err := filt.SetWaitKill(true); err != nil {
		t.Skipf("SetWaitKill unsupported on this libseccomp build: %v", err)
	}

	calls := 0
	loadFn := func() error {
		calls++
		if calls == 1 {
			return errors.New("simulated: kernel rejected WAIT_KILLABLE_RECV")
		}
		return nil
	}

	if err := loadWithRetryOnWaitKillFailure(filt, true, loadFn); err != nil {
		t.Fatalf("loadWithRetryOnWaitKillFailure: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 load calls (initial + retry), got %d", calls)
	}

	// After retry, WaitKill must be cleared so callers can observe it.
	got, err := filt.GetWaitKill()
	if err != nil {
		t.Fatalf("GetWaitKill: %v", err)
	}
	if got {
		t.Fatalf("expected WaitKill to be cleared after retry, got true")
	}
}

// TestLoadWithRetryOnWaitKillFailure_NoRetryWhenWaitKillNotSet verifies that
// a failure without WaitKill set surfaces the original error — no retry
// attempted, no silent recovery.
func TestLoadWithRetryOnWaitKillFailure_NoRetryWhenWaitKillNotSet(t *testing.T) {
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filt.Release()

	origErr := errors.New("simulated: transient load error")
	calls := 0
	loadFn := func() error {
		calls++
		return origErr
	}

	err = loadWithRetryOnWaitKillFailure(filt, false, loadFn)
	if !errors.Is(err, origErr) {
		t.Fatalf("expected original error to propagate, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 load call, got %d", calls)
	}
}

// TestLoadWithRetryOnWaitKillFailure_SuccessFirstCall verifies that when
// the first load succeeds, no retry is attempted and no WaitKill state
// change happens.
func TestLoadWithRetryOnWaitKillFailure_SuccessFirstCall(t *testing.T) {
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filt.Release()

	if err := filt.SetWaitKill(true); err != nil {
		t.Skipf("SetWaitKill unsupported on this libseccomp build: %v", err)
	}

	calls := 0
	loadFn := func() error {
		calls++
		return nil
	}

	if err := loadWithRetryOnWaitKillFailure(filt, true, loadFn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 load call (no retry on success), got %d", calls)
	}

	// WaitKill must still be set — the happy path must not clear it.
	got, err := filt.GetWaitKill()
	if err != nil {
		t.Fatalf("GetWaitKill: %v", err)
	}
	if !got {
		t.Fatalf("expected WaitKill to remain true after successful load, got false")
	}
}
```

- [ ] **Step 2: Run test to confirm it fails (compile error)**

```bash
PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig go test ./internal/netmonitor/unix/ -run TestLoadWithRetryOnWaitKillFailure 2>&1 | head -20
```

Expected: compile error — `undefined: loadWithRetryOnWaitKillFailure`. This is the TDD red state.

- [ ] **Step 3: Do NOT commit yet — the helper in the next task is what makes this compile**

---

## Task 5: Extract `loadWithRetryOnWaitKillFailure` helper (TDD green)

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_linux.go` (lines 359–375 area)

- [ ] **Step 1: Read the current retry code at `seccomp_linux.go:359–375`**

```bash
sed -n '355,385p' internal/netmonitor/unix/seccomp_linux.go
```

You should see the `if err := filt.Load(); err != nil {` block with the WaitKill fallback. This is what we extract.

- [ ] **Step 2: Add the helper at the bottom of `seccomp_linux.go`**

Append to `internal/netmonitor/unix/seccomp_linux.go`:

```go
// loadWithRetryOnWaitKillFailure loads a seccomp filter and, if the load
// fails with WaitKill set, clears WaitKill and retries once. This handles
// custom or vendor kernels that report 6.0+ but reject
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV at filter load time.
//
// loadFn is injected so tests can simulate Load() failures deterministically.
// Production call sites pass `filt.Load`.
func loadWithRetryOnWaitKillFailure(filt *seccomp.ScmpFilter, waitKillSet bool, loadFn func() error) error {
	err := loadFn()
	if err == nil {
		return nil
	}
	if !waitKillSet {
		return err
	}
	slog.Debug("seccomp: Load with WaitKill failed, retrying without", "error", err)
	if clearErr := filt.SetWaitKill(false); clearErr != nil {
		return err
	}
	return loadFn()
}
```

- [ ] **Step 3: Replace the inline retry with a call to the helper**

Replace lines 359–375 of `seccomp_linux.go` (the `if err := filt.Load(); err != nil { ... }` block, ending before `fd, err := filt.GetNotifFd()`) with:

```go
	if err := loadWithRetryOnWaitKillFailure(filt, waitKillSet, filt.Load); err != nil {
		return nil, err
	}
```

The exact lines to delete are the existing block that starts with `if err := filt.Load(); err != nil {` and ends with its matching `}`. Show the file before editing:

```bash
sed -n '355,380p' internal/netmonitor/unix/seccomp_linux.go
```

Edit by matching on the full block (use the Edit tool with the exact text from the file).

- [ ] **Step 4: Run the retry test — should now pass**

```bash
PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig go test ./internal/netmonitor/unix/ -run TestLoadWithRetryOnWaitKillFailure -v
```

Expected:
```
=== RUN   TestLoadWithRetryOnWaitKillFailure_RetriesOnWaitKillFailure
--- PASS: TestLoadWithRetryOnWaitKillFailure_RetriesOnWaitKillFailure
=== RUN   TestLoadWithRetryOnWaitKillFailure_NoRetryWhenWaitKillNotSet
--- PASS: TestLoadWithRetryOnWaitKillFailure_NoRetryWhenWaitKillNotSet
=== RUN   TestLoadWithRetryOnWaitKillFailure_SuccessFirstCall
--- PASS: TestLoadWithRetryOnWaitKillFailure_SuccessFirstCall
PASS
```

- [ ] **Step 5: Run full package tests to confirm no regressions**

```bash
PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig go test ./internal/netmonitor/unix/ -v 2>&1 | tail -30
```

Expected: all tests pass.

- [ ] **Step 6: Commit test + refactor together**

```bash
git add internal/netmonitor/unix/seccomp_linux.go internal/netmonitor/unix/seccomp_retry_test.go
git commit -m "seccomp: extract loadWithRetryOnWaitKillFailure helper + tests"
```

---

## Task 6: Write `GetWaitKill` attr-readback test (white-box verification)

**Files:**
- Create: `internal/netmonitor/unix/seccomp_waitkill_test.go`

- [ ] **Step 1: Write the test file**

Write `internal/netmonitor/unix/seccomp_waitkill_test.go`:

```go
//go:build linux && cgo

package unix

import (
	"testing"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// TestInstallFilterWithConfig_WaitKillEnabled is a white-box regression
// test ensuring Layer 1 of the SIGURG fix is actually applied when the
// kernel supports it. On pre-2.6 libseccomp headers, the
// SCMP_FLTATR_CTL_WAITKILL constant resolves to _SCMP_FLTATR_MIN (a no-op
// sentinel) and SetWaitKill silently does nothing. Combined with the
// compile-time #error guard in seccomp_version_check.go, this test
// catches any future regression at runtime.
//
// Skips on kernels <6.0 where the flag is not available (Layer 1 is
// expected to be off; Layer 2 signal mask protects).
func TestInstallFilterWithConfig_WaitKillEnabled(t *testing.T) {
	if !ProbeWaitKillable() {
		t.Skip("kernel <6.0: WAIT_KILLABLE_RECV not supported, Layer 1 expected off")
	}

	// Fresh filter we inspect directly, bypassing the (non-exported)
	// Filter wrapper so we can call GetWaitKill without plumbing it
	// through the public API.
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filt.Release()

	if err := filt.SetWaitKill(true); err != nil {
		t.Fatalf("SetWaitKill: %v — libseccomp likely built without 2.6 headers "+
			"(the #error guard in seccomp_version_check.go should have prevented this)", err)
	}

	got, err := filt.GetWaitKill()
	if err != nil {
		t.Fatalf("GetWaitKill: %v", err)
	}
	if !got {
		t.Fatalf("GetWaitKill returned false after SetWaitKill(true) — "+
			"Layer 1 is silently disabled, the kernel flag will NOT be applied. "+
			"Check libseccomp version (want >=2.6) and PKG_CONFIG_PATH.")
	}
}

// TestInstallFilterWithConfig_WaitKillLoadsCleanly verifies that a
// filter built via InstallFilterWithConfig actually loads with the
// WaitKill flag on kernels >=6.0 (no retry-without-WaitKill fallback
// triggered). This is an end-to-end smoke that the production path
// engages Layer 1.
func TestInstallFilterWithConfig_WaitKillLoadsCleanly(t *testing.T) {
	if !ProbeWaitKillable() {
		t.Skip("kernel <6.0: WAIT_KILLABLE_RECV not supported")
	}

	// InstallFilterWithConfig loads a filter into THIS process. Run it
	// in a subtest with a fresh subprocess to avoid polluting the test
	// process's filter state. The Go test runner shares process state
	// across tests, so once a seccomp filter is installed it cannot be
	// removed.
	//
	// Keep this test minimal — the fact that InstallFilterWithConfig
	// returns a non-nil Filter on a >=6.0 kernel is sufficient: if the
	// initial load had failed with WaitKill set, the retry path (tested
	// separately in seccomp_retry_test.go) would have cleared WaitKill
	// and produced a Filter we can't distinguish from a no-WaitKill
	// filter. For a definitive end-to-end check, use the Docker matrix.
	t.Skip("skipped to avoid polluting test process filter state; see docker-test matrix for end-to-end verification")
}
```

- [ ] **Step 2: Run the new test**

```bash
PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig go test ./internal/netmonitor/unix/ -run TestInstallFilterWithConfig_WaitKill -v
```

Expected on kernel ≥6.0: `TestInstallFilterWithConfig_WaitKillEnabled` PASS (and the second test SKIP).
Expected on kernel <6.0: both SKIP.

Check your kernel:

```bash
uname -r
```

If the first test FAILs with "Layer 1 is silently disabled", your libseccomp is not 2.6 — re-run Task 1 and ensure PKG_CONFIG_PATH is exported.

- [ ] **Step 3: Commit**

```bash
git add internal/netmonitor/unix/seccomp_waitkill_test.go
git commit -m "seccomp: add white-box test verifying WAIT_KILLABLE_RECV attr round-trips"
```

---

## Task 7: Upgrade SetWaitKill failure log to Warn when kernel supports it

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_linux.go` (lines 236–242)

- [ ] **Step 1: Inspect the current lines**

```bash
sed -n '230,245p' internal/netmonitor/unix/seccomp_linux.go
```

Current code:

```go
	waitKillSet := false
	if ProbeWaitKillable() {
		if err := filt.SetWaitKill(true); err != nil {
			slog.Debug("seccomp: SetWaitKill failed", "error", err)
		} else {
			waitKillSet = true
		}
	}
```

- [ ] **Step 2: Replace with the Warn-on-unexpected-failure variant**

Use the Edit tool to replace the 7-line block above (including the preceding comment block that ends at `// handles custom kernels that report 6.x but lack the flag.`) with:

```go
	// Enable SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (kernel 6.0+).
	// When active, non-fatal signals (including Go's ~10ms SIGURG preemption)
	// cannot interrupt seccomp_do_user_notification, preventing ERESTARTSYS loops.
	// The compile-time #error in seccomp_version_check.go guarantees the
	// libseccomp headers are >=2.6 and SetWaitKill is not a silent no-op.
	// If ProbeWaitKillable reports the kernel supports it but SetWaitKill
	// still fails, something is unexpected — warn loudly so operators can
	// investigate. Load() retry at the end of this function handles the
	// case where SetWaitKill succeeds but the kernel rejects the flag at
	// load time (custom/vendor kernels).
	waitKillSet := false
	if ProbeWaitKillable() {
		if err := filt.SetWaitKill(true); err != nil {
			slog.Warn("seccomp: WaitKillable unexpectedly unavailable despite kernel 6.0+; falling back to SIGURG signal mask only",
				"error", err)
		} else {
			waitKillSet = true
		}
	}
```

(Replace the full block including the original multi-line comment. See the source at `internal/netmonitor/unix/seccomp_linux.go:230-242` for the exact text to match.)

- [ ] **Step 3: Build to confirm no syntax errors**

```bash
PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig go build ./internal/netmonitor/unix/...
```

Expected: success.

- [ ] **Step 4: Run tests**

```bash
PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig go test ./internal/netmonitor/unix/ -v 2>&1 | tail -20
```

Expected: all passing.

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/seccomp_linux.go
git commit -m "seccomp: Warn on unexpected WaitKill failure when kernel supports it"
```

---

## Task 8: Update `.goreleaser.yml` unixwrap builds to link our static libseccomp

**Files:**
- Modify: `.goreleaser.yml` (unixwrap-linux-amd64 and unixwrap-linux-arm64 sections, lines 91–117)

- [ ] **Step 1: Read the current unixwrap build config**

```bash
sed -n '91,118p' .goreleaser.yml
```

- [ ] **Step 2: Update `unixwrap-linux-amd64` env block**

Use the Edit tool to change the `unixwrap-linux-amd64` env block from:

```yaml
  - id: unixwrap-linux-amd64
    main: ./cmd/agentsh-unixwrap
    binary: agentsh-unixwrap
    env:
      - CGO_ENABLED=1
    goos:
      - linux
    goarch:
      - amd64
```

to:

```yaml
  - id: unixwrap-linux-amd64
    main: ./cmd/agentsh-unixwrap
    binary: agentsh-unixwrap
    env:
      - CGO_ENABLED=1
      # Link the static libseccomp 2.6 built by scripts/build-libseccomp.sh.
      # Only libseccomp.a is installed (no .so), so the linker picks it
      # statically despite the plain -lseccomp. Leave glibc dynamic —
      # Alpine builds are the fully-static variant.
      - PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig
    goos:
      - linux
    goarch:
      - amd64
```

- [ ] **Step 3: Update `unixwrap-linux-arm64` env block**

Change from:

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
```

to:

```yaml
  - id: unixwrap-linux-arm64
    main: ./cmd/agentsh-unixwrap
    binary: agentsh-unixwrap
    env:
      - CGO_ENABLED=1
      - CC=aarch64-linux-gnu-gcc
      # Point PKG_CONFIG_PATH at our static libseccomp 2.6 for arm64.
      # The previous /usr/lib/aarch64-linux-gnu/pkgconfig picked up the
      # 2.5.x from apt, which silently disabled Layer 1 of the SIGURG fix.
      - PKG_CONFIG_PATH=/opt/libseccomp/arm64/lib/pkgconfig
    goos:
      - linux
    goarch:
      - arm64
```

- [ ] **Step 4: Commit**

```bash
git add .goreleaser.yml
git commit -m "release: point unixwrap CGO linking at static libseccomp 2.6"
```

---

## Task 9: Update `.github/workflows/release.yml` to build libseccomp before goreleaser

**Files:**
- Modify: `.github/workflows/release.yml` (build deps step around line 43–72)

- [ ] **Step 1: Remove `libseccomp-dev` from the apt-install list and add `gpg`**

Edit `.github/workflows/release.yml`. Current step (around line 43–72) installs `libseccomp-dev libseccomp-dev:arm64`. Replace the apt-get install block with:

```yaml
          sudo apt-get install -y \
            libfuse-dev \
            pkg-config \
            gcc-aarch64-linux-gnu \
            make \
            gpg \
            gperf
```

(Dropped `libseccomp-dev` and `libseccomp-dev:arm64`; added `gpg` for tarball signature verification and `gperf` which libseccomp 2.6 requires at configure time.)

- [ ] **Step 2: Add a new step "Build static libseccomp 2.6 (amd64 + arm64)" right after the build-deps step**

Insert after the apt-install step (before the `Test` step):

```yaml
      - name: Build static libseccomp 2.6 (amd64 + arm64)
        run: |
          TARGET=amd64 ./scripts/build-libseccomp.sh
          TARGET=arm64 ./scripts/build-libseccomp.sh
          echo "=== libseccomp artifacts ==="
          ls -la /opt/libseccomp/amd64/lib/libseccomp.a /opt/libseccomp/arm64/lib/libseccomp.a
```

- [ ] **Step 3: Make the `Test` step aware of the new libseccomp location**

Find the `Test` step and add `PKG_CONFIG_PATH` so the unix package tests use 2.6:

```yaml
      - name: Test
        run: |
          mkdir -p "$GOTMPDIR"
          go test -p=1 ./...
        env:
          GOTMPDIR: ${{ runner.temp }}/go-tmp
          PKG_CONFIG_PATH: /opt/libseccomp/amd64/lib/pkgconfig
```

- [ ] **Step 4: Validate the workflow YAML**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" && echo "YAML valid"
```

Expected: `YAML valid`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: build static libseccomp 2.6 from source before goreleaser"
```

---

## Task 10: Create `Dockerfile.test.ubuntu2204`

**Files:**
- Create: `Dockerfile.test.ubuntu2204`

- [ ] **Step 1: Copy the Ubuntu 24.04 test image as a starting point**

```bash
cp Dockerfile.test.ubuntu Dockerfile.test.ubuntu2204
```

- [ ] **Step 2: Edit the FROM and the comment header**

Open `Dockerfile.test.ubuntu2204` and change:

Line 1 comment:
```
# Self-contained integration test for agentsh on Ubuntu 24.04.
```
to:
```
# Self-contained integration test for agentsh on Ubuntu 22.04.
# Exercises the production sandbox on the oldest supported LTS
# userspace: glibc 2.35 and (pre-installed) libseccomp 2.5.3. Our
# unixwrap binary must work here because we statically link libseccomp
# 2.6 into the binary — the system package is irrelevant.
```

The `FROM ubuntu:24.04` line:
```
FROM ubuntu:24.04
```
to:
```
FROM ubuntu:22.04
```

Leave the rest of the script identical — the test suite is the same.

- [ ] **Step 3: Local smoke test (optional but recommended)**

If you have a published release tag, you can build the image locally:

```bash
docker build -f Dockerfile.test.ubuntu2204 \
  --build-arg AGENTSH_TAG=v0.10.1 \
  -t agentsh-test-ubuntu2204:latest . || echo "(skipping if tag missing)"
```

This will fail if that tag doesn't exist yet. Not required for the plan — CI will exercise it on the next release.

- [ ] **Step 4: Commit**

```bash
git add Dockerfile.test.ubuntu2204
git commit -m "test: add Ubuntu 22.04 integration test image"
```

---

## Task 11: Add `ubuntu2204` to the docker-test matrix

**Files:**
- Modify: `.github/workflows/release.yml` (docker-test matrix, lines 521–540)

- [ ] **Step 1: Locate the matrix**

```bash
sed -n '516,557p' .github/workflows/release.yml
```

- [ ] **Step 2: Add a new matrix entry**

Edit the `include:` block of the `docker-test` matrix. After the existing `- name: ubuntu` entry, add:

```yaml
          - name: ubuntu2204
            dockerfile: Dockerfile.test.ubuntu2204
            docker_run_flags: "--device /dev/fuse --cap-add SYS_ADMIN"
```

- [ ] **Step 3: Validate workflow YAML**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" && echo "YAML valid"
```

Expected: `YAML valid`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add ubuntu:22.04 to docker-test matrix"
```

---

## Task 12: Write arm64 SIGURG reproducer runbook

**Files:**
- Create: `docs/testing/arm64-sigurg-reproducer.md`

- [ ] **Step 1: Ensure the directory exists**

```bash
mkdir -p docs/testing
```

- [ ] **Step 2: Write the runbook**

Write `docs/testing/arm64-sigurg-reproducer.md`:

```markdown
# arm64 SIGURG preemption reproducer

Manual regression test for the Go SIGURG / seccomp user-notify interaction
fixed in PR #225 and hardened in the libseccomp 2.6 defense-in-depth
change. Run this before cutting any release that touches `internal/netmonitor/unix/`
or `cmd/agentsh-unixwrap/`.

## What this verifies

- Layer 1 (`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`, kernel ≥6.0) is actually
  engaged on arm64 — not just compiled in.
- Under Go async preemption (~10ms SIGURG cadence), seccomp notifications
  are not interrupted by ERESTARTSYS loops.

## Environment

- arm64 Linux VM (bare-metal or qemu-system-aarch64).
- Kernel ≥6.0 (`uname -r` to confirm).
- agentsh binaries built by the release workflow (deb or tar.gz for arm64).

A suitable test host is a stock Ubuntu 24.04 arm64 cloud instance — the
Docker test matrix does not exercise this case because GitHub does not
offer an arm64 runner with FUSE and seccomp user-notify permissions in the
same image.

## Procedure

1. Install the release deb:

   ```bash
   sudo dpkg -i agentsh_<version>_linux_arm64.deb
   ```

2. Install the shell shim:

   ```bash
   sudo agentsh shim install-shell \
     --root / \
     --shim /usr/bin/agentsh-shell-shim \
     --bash \
     --i-understand-this-modifies-the-host
   ```

3. Start a server with seccomp execve enabled:

   ```bash
   sudo agentsh server --config /etc/agentsh/config.yaml &
   ```

4. Create a session and run a Go workload that stresses preemption:

   ```bash
   sid=$(agentsh session create --workspace /tmp --json | jq -r .id)
   agentsh exec "$sid" -- go run -gcflags=all=-N ./cmd/agentsh --help
   ```

   Expected: completes in well under 10 seconds with exit code 0.

5. Repeat step 4 in a tight loop for 100 iterations:

   ```bash
   for i in $(seq 1 100); do
     agentsh exec "$sid" -- /bin/true >/dev/null || { echo "FAIL iter $i"; exit 1; }
   done
   echo "PASS: 100 iterations"
   ```

   Expected: 100 PASS. A hang or high failure rate indicates Layer 1 is
   not engaged and Layer 2 alone is insufficient — investigate which
   layer is broken (check `journalctl` for the
   `WaitKillable unexpectedly unavailable` warning).

## Recording results

Paste the output of `uname -a`, `dpkg -l libseccomp2 | tail -1` (on the
host — note we do not depend on this but it's useful context), and the
PASS line from step 5 into the release PR description under a
`### arm64 SIGURG reproducer` heading.
```

- [ ] **Step 3: Commit**

```bash
git add docs/testing/arm64-sigurg-reproducer.md
git commit -m "docs: add arm64 SIGURG manual reproducer runbook"
```

---

## Task 13: Annotate the PR-#225 design spec

**Files:**
- Modify: `docs/superpowers/specs/2026-04-13-sigurg-seccomp-preemption-fix-design.md`

- [ ] **Step 1: Read the top of the spec**

```bash
head -50 docs/superpowers/specs/2026-04-13-sigurg-seccomp-preemption-fix-design.md
```

Find the line documenting "Requires kernel 6.0+ and libseccomp >= 2.6.0" (around line 26).

- [ ] **Step 2: Append a post-hoc note near the libseccomp version requirement**

Edit the line (or the paragraph containing) the libseccomp >= 2.6.0 requirement to add a cross-reference:

Add immediately after the sentence mentioning "libseccomp >= 2.6.0":

```markdown
> **Follow-up (2026-04-14):** The libseccomp version requirement is now enforced at
> build time via the `#error` guards in `internal/netmonitor/unix/seccomp_version_check.go`
> and `cmd/agentsh-unixwrap/seccomp_version_check.go`, and CI builds a static libseccomp
> 2.6 via `scripts/build-libseccomp.sh`. See
> `docs/superpowers/specs/2026-04-14-libseccomp-2.6-defense-in-depth-design.md`
> for the hardening rationale.
```

(Same addition near the "build system" requirement at line ~44 if that's a separate callout.)

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-04-13-sigurg-seccomp-preemption-fix-design.md
git commit -m "docs: cross-reference libseccomp 2.6 hardening follow-up"
```

---

## Task 14: Full local verification

**Files:** none

- [ ] **Step 1: Clean build from scratch with the new pkg-config path**

```bash
go clean -cache
PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig CGO_ENABLED=1 go build ./...
```

Expected: success.

- [ ] **Step 2: Run the full test suite**

```bash
PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig go test -p=1 ./... 2>&1 | tail -30
```

Expected: all passing. Key tests to confirm:
- `TestLoadWithRetryOnWaitKillFailure_*` (3 subtests PASS)
- `TestInstallFilterWithConfig_WaitKillEnabled` PASS (or SKIP on <6.0 kernel)

- [ ] **Step 3: Cross-compile check (matches CLAUDE.md guidance)**

```bash
GOOS=windows go build ./...
```

Expected: success (unixwrap is Linux-only, so it's not built for Windows — but the other packages must still compile).

- [ ] **Step 4: Verify the built unixwrap binary links libseccomp statically**

```bash
PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig CGO_ENABLED=1 go build -o /tmp/agentsh-unixwrap ./cmd/agentsh-unixwrap
ldd /tmp/agentsh-unixwrap | grep -i seccomp || echo "OK: libseccomp statically linked (not listed in ldd)"
nm /tmp/agentsh-unixwrap 2>/dev/null | grep -c seccomp_ | head -1
```

Expected: `OK: libseccomp statically linked (not listed in ldd)` and a non-zero count of `seccomp_` symbols in the binary (proving the static lib was pulled in).

- [ ] **Step 5: Run make smoke (if it runs locally)**

```bash
PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig make smoke 2>&1 | tail -20
```

Expected: PASS. If smoke needs env that isn't present locally, note the skipped subtests and move on.

- [ ] **Step 6: Final commit (if any stray changes)**

```bash
git status
```

Expected: clean working tree. If there are stray changes, review and commit or revert as appropriate.

---

## Self-review checklist

Before handing off:

- [ ] Spec coverage: every item in Section "Architecture" of the spec has a task:
  - Static-link libseccomp 2.6 everywhere → Tasks 1, 8, 9
  - Source build in CI → Tasks 1, 9
  - Build-time `#error` guard → Tasks 2, 3
  - Runtime Warn on unexpected silent disable → Task 7
  - Automated verification (attr readback + retry test + matrix) → Tasks 4, 5, 6, 10, 11
  - Manual gate for arm64 VM → Task 12
- [ ] No "TBD", "TODO", "fill in details" in any step
- [ ] Every code-changing step shows complete code
- [ ] Function/type names match across tasks (e.g., `loadWithRetryOnWaitKillFailure` used consistently in Tasks 4 and 5)
- [ ] Commands are literal — `PKG_CONFIG_PATH=/opt/libseccomp/amd64/lib/pkgconfig` repeated wherever CGo runs
