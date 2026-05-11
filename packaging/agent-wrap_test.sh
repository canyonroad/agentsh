#!/usr/bin/env bash
# Smoke test for packaging/agent-wrap.sh. Sets up an isolated tempdir with a
# fake agent binary at <symlink>.real, fake agentsh, and fake tier file, then
# drives the wrapper through all 5 scenarios.
#
# Layout matches the move-aside-and-replace design: the wrapper symlink lives
# at $tmp/local-bin/claude and the real binary lives at
# $tmp/local-bin/claude.real (a sibling with .real suffix).

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
wrap="$here/agent-wrap.sh"

if [ ! -x "$wrap" ]; then
    echo "FAIL: $wrap missing or not executable"
    exit 1
fi

# Create an isolated harness.
tmp=$(mktemp -d -t agent-wrap-test.XXXXXX)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/local-bin" "$tmp/agentsh-bin" "$tmp/run/agentsh" "$tmp/empty-bin"

# Fake real agent binary placed at <symlink>.real (sibling of the symlink).
cat >"$tmp/local-bin/claude.real" <<'EOF'
#!/bin/sh
echo "REAL-CLAUDE: $*"
EOF
chmod +x "$tmp/local-bin/claude.real"

# Fake agentsh that announces itself when called as `agentsh wrap`.
cat >"$tmp/agentsh-bin/agentsh" <<'EOF'
#!/bin/sh
echo "AGENTSH-WRAP: $*"
EOF
chmod +x "$tmp/agentsh-bin/agentsh"

# Symlink the wrapper at the original agent location.
ln -s "$wrap" "$tmp/local-bin/claude"

# Helper: run the symlinked wrapper with FAKE_ROOT for tier-file relocation.
run_wrap() {
    AGENTSH_TEST=1 FAKE_ROOT="$tmp" PATH="$tmp/agentsh-bin:$PATH" "$tmp/local-bin/claude" "$@"
}

run_wrap_no_agentsh() {
    # Restrict PATH to an empty dir so `command -v agentsh` fails
    # regardless of what is installed on the host system.
    AGENTSH_TEST=1 FAKE_ROOT="$tmp" PATH="$tmp/empty-bin" "$tmp/local-bin/claude" "$@"
}

# Test 1: ${0}.real missing → exit 127
rm "$tmp/local-bin/claude.real"
out=$(run_wrap --version 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 127 ]; then
    echo "FAIL: missing-real-binary should exit 127; got rc=$rc out=$out"
    exit 1
fi
# Restore for subsequent tests.
cat >"$tmp/local-bin/claude.real" <<'EOF'
#!/bin/sh
echo "REAL-CLAUDE: $*"
EOF
chmod +x "$tmp/local-bin/claude.real"
echo "PASS: missing-real-binary exits 127"

# Test 2: agentsh missing → exit 1
echo "shim" >"$tmp/run/agentsh/tier"
out=$(run_wrap_no_agentsh --version 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 1 ]; then
    echo "FAIL: missing-agentsh should exit 1; got rc=$rc out=$out"
    exit 1
fi
echo "PASS: missing-agentsh exits 1"

# Test 3: tier=none → exit 1
echo "none" >"$tmp/run/agentsh/tier"
out=$(run_wrap --version 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 1 ]; then
    echo "FAIL: tier=none should exit 1; got rc=$rc out=$out"
    exit 1
fi
echo "PASS: tier=none exits 1"

# Test 4: tier file missing → exit 1
rm "$tmp/run/agentsh/tier"
out=$(run_wrap --version 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 1 ]; then
    echo "FAIL: tier-missing should exit 1; got rc=$rc out=$out"
    exit 1
fi
echo "PASS: tier-missing exits 1"

# Test 5: everything green → exec'd agentsh wrap -- <symlink>.real <args>
echo "shim" >"$tmp/run/agentsh/tier"
out=$(run_wrap --version --foo bar 2>&1)
expected="AGENTSH-WRAP: wrap -- $tmp/local-bin/claude.real --version --foo bar"
if [ "$out" != "$expected" ]; then
    echo "FAIL: engage path wrong"
    echo "  want: $expected"
    echo "  got:  $out"
    exit 1
fi
echo "PASS: engages wrap with args"

echo
echo "OK agent-wrap.sh (5/5)"
