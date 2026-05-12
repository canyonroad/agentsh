# Vendored libseccomp source

The libseccomp release tarball + detached signature are committed in
`scripts/` alongside the build script. The build no longer fetches them
from the network at run time.

## Why vendor

- **Offline / air-gapped / restricted-network builds.** Some sites
  (e.g. RHEL build farms — see issue #296) cannot reach
  `github.com/seccomp/libseccomp/releases` at build time. EPEL ships
  only libseccomp 2.5.x, so building agentsh on RHEL previously
  required either an outbound network exception or hand-vendoring the
  tarball.
- **Reproducibility.** Bit-exact source across every build, regardless
  of upstream mirror availability or release-asset rewrites.
- **Smaller supply-chain surface.** One fewer network dependency at
  build time. The GPG signature against the pinned fingerprint is still
  verified — it is the security guarantee, independent of how the
  tarball arrived on disk.

## Files

| Path | Purpose |
|---|---|
| `scripts/libseccomp-2.6.0.tar.gz` | Upstream source tarball |
| `scripts/libseccomp-2.6.0.tar.gz.asc` | Detached GPG signature |
| `scripts/libseccomp-signing-key.asc` | Paul Moore's release signing key |
| `scripts/build-libseccomp.sh` | Build script (pins VERSION + SRC_SHA256) |

## Verification chain

`build-libseccomp.sh` performs three independent checks at run time:

1. **SHA256 pin** (`SRC_SHA256` in the script) — fails fast if the
   in-tree tarball was swapped without updating the script. Cheap,
   no external dependency.
2. **GPG fingerprint pin** (`GPG_FPR` in the script) — the bundled
   signing key is imported into a temp keyring and the pinned
   primary-key fingerprint is asserted before any signature check.
3. **GPG signature** — the tarball's `.asc` is verified against the
   signing subkey, and `gpg --status-fd`'s `VALIDSIG` line is parsed
   to confirm the primary-key fingerprint matches the pin.

Each check is sufficient on its own; together they make a swap of any
single file in the chain fail closed.

## Refreshing when bumping VERSION

When updating to a new libseccomp release (e.g. 2.6.1, 2.7.0):

```bash
NEW=2.6.1     # for example
cd scripts/
curl -fsSL "https://github.com/seccomp/libseccomp/releases/download/v${NEW}/libseccomp-${NEW}.tar.gz" -o "libseccomp-${NEW}.tar.gz"
curl -fsSL "https://github.com/seccomp/libseccomp/releases/download/v${NEW}/libseccomp-${NEW}.tar.gz.asc" -o "libseccomp-${NEW}.tar.gz.asc"

# Verify the new tarball with the bundled key BEFORE staging.
TMP=$(mktemp -d) && chmod 700 "$TMP"
GNUPGHOME="$TMP" gpg --batch --import libseccomp-signing-key.asc
GNUPGHOME="$TMP" gpg --batch --status-fd 1 --verify \
    "libseccomp-${NEW}.tar.gz.asc" "libseccomp-${NEW}.tar.gz" \
    | grep -E "^\[GNUPG:\] VALIDSIG [0-9A-F]{40} .* 7100AADFAE6E6E940D2E0AD655E45A5AE8CA7C8A$"
rm -rf "$TMP"

# Compute the new SHA256 and update SRC_SHA256 in build-libseccomp.sh.
sha256sum "libseccomp-${NEW}.tar.gz"

# Bump VERSION in build-libseccomp.sh to match.
# Remove the old tarball + .asc.
git rm "libseccomp-${OLD}.tar.gz" "libseccomp-${OLD}.tar.gz.asc"
git add "libseccomp-${NEW}.tar.gz" "libseccomp-${NEW}.tar.gz.asc" build-libseccomp.sh
```

The signing key (`libseccomp-signing-key.asc`) does not need to be
updated unless upstream rotates the primary key. The pinned fingerprint
(`GPG_FPR` in the script) covers the primary key; the signing subkey
can rotate freely without touching either.

## Upstream provenance

- Project: https://github.com/seccomp/libseccomp
- Release URL pattern: `https://github.com/seccomp/libseccomp/releases/download/v<VERSION>/`
- Signing key (Paul Moore, libseccomp release manager):
  `7100AADFAE6E6E940D2E0AD655E45A5AE8CA7C8A`
- Tarball SHA256 (2.6.0):
  `83b6085232d1588c379dc9b9cae47bb37407cf262e6e74993c61ba72d2a784dc`
