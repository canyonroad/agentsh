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

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "=== libseccomp ${VERSION} static build for ${TARGET} → ${PREFIX} ==="

# Detect any stale libseccomp.so* left by a previous install — if the
# prefix is not static-only the later `-lseccomp` link could silently
# prefer the shared object and undo the "static libseccomp 2.6"
# guarantee. Wipe the prefix so the cache-hit check falls through to a
# clean rebuild.
if [ -d "${PREFIX}" ]; then
    STALE_SO="$(find "${PREFIX}" -maxdepth 3 -name 'libseccomp.so*' -print 2>/dev/null || true)"
    if [ -n "${STALE_SO}" ]; then
        echo "WARN: stale shared libseccomp found in ${PREFIX}; removing prefix for clean rebuild:" >&2
        echo "${STALE_SO}" >&2
        sudo rm -rf "${PREFIX}"
    fi
fi

# Skip rebuild if artifact already present AND the installed version
# matches the requested VERSION. Checking .pc's Version: line prevents
# silent reuse of a stale install after a version bump or a partial
# previous run.
if [ -f "${PREFIX}/lib/libseccomp.a" ] \
   && [ -f "${PREFIX}/lib/pkgconfig/libseccomp.pc" ] \
   && [ -f "${PREFIX}/include/seccomp.h" ] \
   && grep -qx "Version: ${VERSION}" "${PREFIX}/lib/pkgconfig/libseccomp.pc"; then
    echo "Already installed at ${PREFIX} (version ${VERSION}); skipping."
    exit 0
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
