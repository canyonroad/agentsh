#!/usr/bin/env bash
# Smoke test for scripts/install-agentsh.sh.
# Runs the script with AGENTSH_DRY_RUN=1 and asserts it picks the right
# package manager + URL based on AGENTSH_FORCE_DETECT.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script="$here/install-agentsh.sh"

# Test 1: detects dpkg
out=$(AGENTSH_DRY_RUN=1 AGENTSH_FORCE_DETECT=dpkg AGENTSH_ARCH=amd64 "$script" 2>&1 || true)
echo "$out" | grep -q "dpkg.*agentsh_.*_linux_amd64.deb" || {
  echo "FAIL: dpkg branch missing or wrong URL"
  echo "----- output -----"
  echo "$out"
  exit 1
}

# Test 2: detects rpm
out=$(AGENTSH_DRY_RUN=1 AGENTSH_FORCE_DETECT=rpm AGENTSH_ARCH=amd64 "$script" 2>&1 || true)
echo "$out" | grep -q "rpm.*agentsh-.*\.x86_64\.rpm" || {
  echo "FAIL: rpm branch missing or wrong URL"
  echo "----- output -----"
  echo "$out"
  exit 1
}

# Test 3: detects apk
out=$(AGENTSH_DRY_RUN=1 AGENTSH_FORCE_DETECT=apk AGENTSH_ARCH=amd64 "$script" 2>&1 || true)
echo "$out" | grep -q "apk.*agentsh_.*_linux_amd64.apk" || {
  echo "FAIL: apk branch missing or wrong URL"
  echo "----- output -----"
  echo "$out"
  exit 1
}

# Test 4: unknown package manager fails fast
if AGENTSH_DRY_RUN=1 AGENTSH_FORCE_DETECT=none "$script" 2>/dev/null; then
  echo "FAIL: expected non-zero exit when no package manager detected"
  exit 1
fi

# Test 5: arm64 selects arm64 artifact
out=$(AGENTSH_DRY_RUN=1 AGENTSH_FORCE_DETECT=dpkg AGENTSH_ARCH=arm64 "$script" 2>&1 || true)
echo "$out" | grep -q "agentsh_.*_linux_arm64.deb" || {
  echo "FAIL: arm64 URL not generated"
  echo "----- output -----"
  echo "$out"
  exit 1
}

echo "OK install-agentsh.sh"
