#!/usr/bin/env bash
# Sign the macOS app bundle inside-out (nested code first, outer app last).
# Single source of truth for local (Makefile) and release (release.yml)
# signing — fix signing here, not in the callers (issue #442).
#
# Usage: SIGNING_IDENTITY="Developer ID Application: ..." \
#          sign-macos-bundle.sh <app-bundle-path>
#
# Must run from the repository root (entitlements paths are repo-relative).
set -euo pipefail

APP="${1:?usage: SIGNING_IDENTITY=... sign-macos-bundle.sh <app-bundle-path>}"
SYSEXT="ai.canyonroad.agentsh.SysExt.systemextension"

if [ -z "${SIGNING_IDENTITY:-}" ]; then
  echo "error: SIGNING_IDENTITY must be set (see 'security find-identity -v -p codesigning')" >&2
  exit 1
fi

# 1. Go binaries. agentsh-shell-shim uses minimal (no) entitlements; every
# other binary gets the app entitlements — this matches the release
# pipeline's historical per-binary selection exactly.
for bin in "${APP}/Contents/MacOS"/*; do
  # Skip the bundle's main executable (CFBundleExecutable): step 5 signs it
  # with the bundle, using the same entitlements. Signing/verifying it here,
  # before its siblings are signed, fails with "code object is not signed
  # at all ... In subcomponent: .../agentsh-shell-shim" (v0.20.6-rc1).
  [ "$(basename "$bin")" = "agentsh" ] && continue
  echo "Signing $(basename "$bin")"
  if [ "$(basename "$bin")" = "agentsh-shell-shim" ]; then
    codesign --force --sign "$SIGNING_IDENTITY" \
      --options runtime --timestamp \
      "$bin"
  else
    codesign --force --sign "$SIGNING_IDENTITY" \
      --entitlements macos/AgentSH/agentsh/agentsh.entitlements \
      --options runtime --timestamp \
      "$bin"
  fi
  codesign --verify --strict "$bin"
done

# 2. System Extension
echo "Signing System Extension"
codesign --force --sign "$SIGNING_IDENTITY" \
  --entitlements macos/AgentSH/SysExt.entitlements \
  --options runtime --timestamp \
  "${APP}/Contents/Library/SystemExtensions/${SYSEXT}"

# 3. XPC Service
echo "Signing XPC Service"
codesign --force --sign "$SIGNING_IDENTITY" \
  --options runtime --timestamp \
  "${APP}/Contents/XPCServices/xpc.xpc"

# 4. Approval Dialog
echo "Signing Approval Dialog"
codesign --force --sign "$SIGNING_IDENTITY" \
  --entitlements macos/AgentSH/approval-dialog/approval-dialog.entitlements \
  --options runtime --timestamp \
  "${APP}/Contents/Resources/approval-dialog.app"

# 5. Main app bundle
echo "Signing app bundle"
codesign --force --sign "$SIGNING_IDENTITY" \
  --entitlements macos/AgentSH/agentsh/agentsh.entitlements \
  --options runtime --timestamp \
  "${APP}"

# 6. Verify
codesign --verify --deep --strict --verbose=2 "${APP}"
