#!/bin/sh
# install-agentsh.sh — install AgentSH into a Linux container/VM.
#
# Used by the Docker Sandboxes mixin kit; also safe to run interactively
# on any supported Linux. Detects the host's package manager and
# downloads the matching release artifact from the latest AgentSH
# GitHub release.
#
# Package manager support:
#   dpkg  — downloads the .deb artifact
#   rpm   — downloads the .rpm artifact
#   apk   — Alpine Linux; GoReleaser produces no .apk, so the tar.gz
#             archive is downloaded and the binaries extracted manually
#             into /usr/bin.
#
# Env knobs (all optional):
#   AGENTSH_VERSION    Pinned release tag, e.g. v0.1.2 (default: latest)
#   AGENTSH_ARCH       amd64 | arm64 (default: detected via uname -m)
#   AGENTSH_DRY_RUN    1 = print actions without downloading/installing
#   AGENTSH_FORCE_DETECT  dpkg | rpm | apk | none (test hook)
#
# Exit codes:
#   0 success
#   1 detection failure (unsupported arch or no supported package manager)
#   2 download failure
#   3 install failure

set -eu

GITHUB_REPO="erans/agentsh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

detect_arch() {
  if [ -n "${AGENTSH_ARCH:-}" ]; then
    printf '%s' "$AGENTSH_ARCH"
    return
  fi
  case "$(uname -m)" in
    x86_64|amd64)  printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    *) printf 'unsupported' ;;
  esac
}

detect_pm() {
  if [ -n "${AGENTSH_FORCE_DETECT:-}" ]; then
    printf '%s' "$AGENTSH_FORCE_DETECT"
    return
  fi
  if command -v dpkg >/dev/null 2>&1; then printf 'dpkg'; return; fi
  if command -v rpm  >/dev/null 2>&1; then printf 'rpm';  return; fi
  if command -v apk  >/dev/null 2>&1; then printf 'apk';  return; fi
  printf 'none'
}

# Resolve the version to install.  If AGENTSH_VERSION is set, use it
# verbatim.  Otherwise hit the GitHub Releases API and parse the tag from
# the JSON response using only sed — no jq dependency required.
resolve_version() {
  if [ -n "${AGENTSH_VERSION:-}" ]; then
    printf '%s' "$AGENTSH_VERSION"
    return
  fi
  ver=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
    | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p')
  if [ -z "$ver" ]; then
    echo "install-agentsh: failed to resolve latest version from GitHub API" >&2
    exit 2
  fi
  printf '%s' "$ver"
}

# Wrap every side-effecting command so that AGENTSH_DRY_RUN=1 prints
# rather than executes.  Never bypass this wrapper.
run() {
  if [ "${AGENTSH_DRY_RUN:-}" = "1" ]; then
    echo "DRY: $*"
  else
    "$@"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  arch=$(detect_arch)
  if [ "$arch" = "unsupported" ]; then
    echo "install-agentsh: unsupported architecture $(uname -m)" >&2
    exit 1
  fi

  pm=$(detect_pm)

  # Resolve version once — this may make a network call, so skip it in
  # dry-run mode if AGENTSH_VERSION is not set, to keep tests offline.
  if [ "${AGENTSH_DRY_RUN:-}" = "1" ] && [ -z "${AGENTSH_VERSION:-}" ]; then
    ver="VERSION"
  else
    ver=$(resolve_version)
  fi

  base="https://github.com/${GITHUB_REPO}/releases/download/${ver}"

  case "$pm" in
    dpkg)
      # GoReleaser nfpms deb default: agentsh_<version>_linux_<arch>.deb
      fname="agentsh_${ver}_linux_${arch}.deb"
      url="${base}/${fname}"
      tmp="/tmp/agentsh.deb"
      echo "install-agentsh: using dpkg (${url})"
      run curl -fsSL "$url" -o "$tmp" || exit 2
      run dpkg -i "$tmp"              || exit 3
      ;;

    rpm)
      # GoReleaser nfpms rpm default: agentsh-<version>-1.<arch>.rpm
      rpmarch=$([ "$arch" = "amd64" ] && echo x86_64 || echo aarch64)
      fname="agentsh-${ver}-1.${rpmarch}.rpm"
      url="${base}/${fname}"
      tmp="/tmp/agentsh.rpm"
      echo "install-agentsh: using rpm (${url})"
      run curl -fsSL "$url" -o "$tmp" || exit 2
      run rpm -Uvh --replacepkgs "$tmp" || exit 3
      ;;

    apk)
      # GoReleaser does not produce .apk; use the tar.gz archive and
      # extract binaries manually into /usr/bin.
      fname="agentsh_${ver}_linux_${arch}.tar.gz"
      url="${base}/${fname}"
      tmp="/tmp/agentsh.tar.gz"
      echo "install-agentsh: using apk (${url})"
      run curl -fsSL "$url" -o "$tmp"                                    || exit 2
      run tar -xzf "$tmp" -C /usr/bin --strip-components=0               \
          agentsh agentsh-shell-shim agentsh-unixwrap agentsh-stub       \
          agentsh-sbx-bootstrap 2>/dev/null || run tar -xzf "$tmp" -C /usr/bin --strip-components=0 agentsh || exit 3
      ;;

    none)
      echo "install-agentsh: no supported package manager (dpkg/rpm/apk) found" >&2
      exit 1
      ;;

    *)
      echo "install-agentsh: unknown package manager '${pm}'" >&2
      exit 1
      ;;
  esac

  echo "install-agentsh: done"
}

main "$@"
