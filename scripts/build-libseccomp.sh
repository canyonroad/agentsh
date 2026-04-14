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
#   curl gpg tar make gcc gperf

set -euo pipefail

VERSION="${LIBSECCOMP_VERSION:-2.6.0}"
TARGET="${TARGET:-amd64}"
case "${TARGET}" in
    amd64|arm64) ;;
    *)
        echo "ERROR: unknown TARGET=${TARGET} (expected amd64 or arm64)" >&2
        exit 1
        ;;
esac

PREFIX="/opt/libseccomp/${TARGET}"
SRC_URL="https://github.com/seccomp/libseccomp/releases/download/v${VERSION}/libseccomp-${VERSION}.tar.gz"
SIG_URL="${SRC_URL}.asc"
# Paul Moore <paul@paul-moore.com> — libseccomp release signing key
# Fingerprint pinned to block key-substitution attacks. Verify upstream at
# https://github.com/seccomp/libseccomp — README lists the signing key.
GPG_FPR="7100AADFAE6E6E940D2E0AD655E45A5AE8CA7C8A"
# Bundled signing key — committed alongside this script so the release
# build does not depend on a keyserver being reachable at build time.
# The pinned fingerprint above is checked after import, so swapping the
# bundled key without updating the fingerprint will fail the build.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_FILE="${SCRIPT_DIR}/libseccomp-signing-key.asc"

# check_installed: returns 0 when PREFIX already holds a clean
# static-only install of the requested VERSION, non-zero otherwise.
# Callable more than once — we run it twice: before acquiring the
# per-arch flock (cheap early exit) and again after acquiring it
# (the flock winner may have populated the prefix while we waited).
check_installed() {
    [ -f "${PREFIX}/lib/libseccomp.a" ] \
        && [ -f "${PREFIX}/lib/pkgconfig/libseccomp.pc" ] \
        && [ -f "${PREFIX}/include/seccomp.h" ] \
        && grep -qx "Version: ${VERSION}" "${PREFIX}/lib/pkgconfig/libseccomp.pc" \
        || return 1
    # Portable stale-.so probe — bash glob expansion, no `find` so we
    # don't depend on GNU `find -maxdepth` (BSD find on macOS rejects
    # it). When no file matches, bash leaves the glob literal, so both
    # `-e` and `-L` on the first element return false. `-e` follows
    # symlinks (misses dangling ones), so we also test `-L` to catch
    # symlinks — live or dangling — as stale artifacts. Any real file
    # or any symlink falls through to rebuild.
    local cached_so=("${PREFIX}"/lib/libseccomp.so*)
    if [ ! -e "${cached_so[0]}" ] && [ ! -L "${cached_so[0]}" ]; then
        return 0
    fi
    return 1
}

# Cache-hit fast path: if the requested version is already installed
# at PREFIX and the install is static-only (no libseccomp.so* present),
# exit 0 immediately — with NO side effects, so direct callers don't
# need any build prerequisite installed for the idempotent "second run
# no-ops" contract to hold. A stale shared object in the prefix makes
# us fall through to the full build path, which wipes and rebuilds.
if check_installed; then
    echo "Already installed at ${PREFIX} (version ${VERSION}); skipping."
    exit 0
fi

# Host-OS gate: this script builds a Linux static library via
# ./configure + make, so it cannot run on darwin/windows. The
# default is fail-closed (exit 1) so direct callers — CI jobs,
# operators invoking the script manually — see a clear error when
# the host is wrong. GoReleaser's per-build hooks.pre set
# SKIP_IF_UNSUPPORTED=1 so filtered runs (e.g. darwin-only snapshot
# from a macOS dev machine) succeed without us, since the sysroot is
# irrelevant to the selected targets. Reached only when the cache-hit
# fast path above did not apply, so a rebuild is actually needed.
if [ "$(uname -s)" != "Linux" ]; then
    if [ "${SKIP_IF_UNSUPPORTED:-0}" = "1" ]; then
        echo "build-libseccomp: host is $(uname -s); SKIP_IF_UNSUPPORTED=1, skipping Linux ${TARGET} sysroot." >&2
        exit 0
    fi
    echo "ERROR: build-libseccomp requires a Linux host (got $(uname -s)). Set SKIP_IF_UNSUPPORTED=1 to no-op on non-Linux." >&2
    exit 1
fi

# Cross-compiler gate (arm64 only): fail-closed when
# aarch64-linux-gnu-gcc is absent, so direct callers see the real
# problem. GoReleaser's per-build hooks.pre set SKIP_IF_UNSUPPORTED=1
# so amd64-only dev hosts don't break filtered runs that never touch
# linux/arm64. Reached only when the cache-hit fast path above did not
# apply, so a rebuild is actually needed.
if [ "${TARGET}" = "arm64" ] && ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    if [ "${SKIP_IF_UNSUPPORTED:-0}" = "1" ]; then
        echo "build-libseccomp: aarch64-linux-gnu-gcc not found; SKIP_IF_UNSUPPORTED=1, skipping arm64 sysroot." >&2
        exit 0
    fi
    echo "ERROR: TARGET=arm64 requires aarch64-linux-gnu-gcc in PATH. Install gcc-aarch64-linux-gnu or set SKIP_IF_UNSUPPORTED=1 to no-op." >&2
    exit 1
fi

# Per-arch concurrency lock. GoReleaser runs per-build hooks in
# parallel with the build itself, and multiple Linux CGO builds share
# the same sysroot dependency (agentsh-linux-<arch> and
# unixwrap-linux-<arch>). Without a lock two instances could both
# race past the cache-hit fast path above, both `sudo rm -rf` the
# prefix, and both `sudo make install` into the same directory —
# nondeterministic failure. flock serializes the work per arch; the
# loser blocks until the winner finishes, then re-checks the cache
# below and exits 0 without repeating it.
#
# Placed after the host and cross-compiler gates so macOS invocations
# (which don't ship flock in util-linux by default) never reach it —
# they've already exited via SKIP_IF_UNSUPPORTED. flock is standard
# on every Linux distro we target (util-linux on glibc distros,
# busybox applet on Alpine).
#
# Lock file is cross-user shared — the protected resource is
# /opt/libseccomp/${TARGET}, which is a single system-wide path, so
# the lock must be too. `exec 9>FILE` truncates the file (requires
# write access), so we create it mode 0666 on first use via install(1)
# so any user on the host can subsequently acquire the lock. If the
# file already exists with tighter perms (upgrade from an older version
# of this script), operator remediation is `rm -f` of the lock file —
# locks in /tmp are transient state, not data.
LOCK_FILE="/tmp/agentsh-build-libseccomp-${TARGET}.lock"
if [ ! -e "${LOCK_FILE}" ]; then
    install -m 0666 /dev/null "${LOCK_FILE}" 2>/dev/null || true
fi
exec 9>"${LOCK_FILE}"
flock -x 9

# Second cache-hit check, after the flock. If we lost the race, the
# winner installed while we waited — skip the rebuild.
if check_installed; then
    echo "Already installed at ${PREFIX} (version ${VERSION}) after lock wait; skipping."
    exit 0
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "=== libseccomp ${VERSION} static build for ${TARGET} → ${PREFIX} ==="

# Stale-.so cleanup: only runs on the rebuild path (the cache-hit fast
# path above already exited 0 for a clean static-only cache). If a
# previous install left a libseccomp.so* behind, the later `-lseccomp`
# link could silently prefer the shared object and undo the "static
# libseccomp 2.6" guarantee, so wipe the prefix before rebuilding.
if [ -d "${PREFIX}" ]; then
    STALE_SO="$(find "${PREFIX}" -maxdepth 3 -name 'libseccomp.so*' -print 2>/dev/null || true)"
    if [ -n "${STALE_SO}" ]; then
        echo "WARN: stale shared libseccomp found in ${PREFIX}; removing prefix for clean rebuild:" >&2
        echo "${STALE_SO}" >&2
        sudo rm -rf "${PREFIX}"
    fi
fi

cd "$WORKDIR"

# Download tarball + signature.
curl -fsSL "$SRC_URL" -o "libseccomp-${VERSION}.tar.gz"
curl -fsSL "$SIG_URL" -o "libseccomp-${VERSION}.tar.gz.asc"

# Verify signature — fail the build rather than risk a supply-chain compromise.
# We use --status-fd to parse gpg's machine-readable output and assert the
# tarball was signed by exactly the pinned fingerprint. A membership check on
# the keyring is not enough: gpg --verify would accept a signature from ANY
# key in the keyring, so if the bundled key file were ever extended with a
# second key the guarantee would silently degrade.
export GNUPGHOME="${WORKDIR}/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
test -f "$KEY_FILE" || { echo "ERROR: missing bundled signing key at ${KEY_FILE}" >&2; exit 1; }
gpg --batch --import "$KEY_FILE"
# Re-assert the pinned fingerprint is present in our temp keyring before trusting any signature.
gpg --batch --list-keys --with-colons "$GPG_FPR" >/dev/null \
    || { echo "ERROR: bundled key does not contain pinned fingerprint ${GPG_FPR}" >&2; exit 1; }
# Capture gpg's status output (machine-readable) and assert VALIDSIG reports
# the pinned primary-key fingerprint. Status line layout:
#   [GNUPG:] VALIDSIG <signing-key-fpr> <date> ... <primary-key-fpr>
# The primary-key fingerprint (last field) is what we pin — the signing key
# is a subkey that may rotate without the primary changing.
GPG_STATUS="${WORKDIR}/gpg-status"
gpg --batch --status-fd 3 --verify "libseccomp-${VERSION}.tar.gz.asc" "libseccomp-${VERSION}.tar.gz" 3>"$GPG_STATUS"
grep -qE "^\[GNUPG:\] VALIDSIG [0-9A-F]{40} .* ${GPG_FPR}\$" "$GPG_STATUS" \
    || { echo "ERROR: signature did not verify against pinned fingerprint ${GPG_FPR}" >&2; cat "$GPG_STATUS" >&2; exit 1; }

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

# Post-install guard: enforce the --disable-shared invariant. If any
# libseccomp.so* snuck through (e.g. a future configure flag change,
# a packager's autotools override, or a dirty prefix), fail the build
# rather than let `-lseccomp` silently prefer the shared object.
LEAKED_SO="$(find "${PREFIX}" -maxdepth 3 -name 'libseccomp.so*' -print 2>/dev/null || true)"
if [ -n "${LEAKED_SO}" ]; then
    echo "ERROR: libseccomp.so* present in ${PREFIX} — static-only invariant violated:" >&2
    echo "${LEAKED_SO}" >&2
    exit 1
fi

# Sanity check the install.
test -f "${PREFIX}/lib/libseccomp.a" || { echo "missing libseccomp.a"; exit 1; }
test -f "${PREFIX}/lib/pkgconfig/libseccomp.pc" || { echo "missing pkgconfig"; exit 1; }
test -f "${PREFIX}/include/seccomp.h" || { echo "missing headers"; exit 1; }
echo "=== OK: ${PREFIX}/lib/libseccomp.a ($(stat -c %s "${PREFIX}/lib/libseccomp.a") bytes) ==="
