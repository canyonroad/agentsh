#!/usr/bin/env bash
# Smoke test for packaging/install-agent-wrappers.sh.
# Drives the installer through 6 scenarios using AGENTSH_TEST=1 / FAKE_ROOT /
# FAKE_TEST_PATH (v2 harness — move-aside-and-replace mechanism).

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
installer="$here/install-agent-wrappers.sh"

if [ ! -x "$installer" ]; then
    echo "FAIL: $installer missing or not executable"
    exit 1
fi

# tmp dir shared across tests; each test resets state inside it.
tmp=$(mktemp -d -t install-wrappers.XXXXXX)
trap 'rm -rf "$tmp"' EXIT

WRAP="$tmp/usr/lib/agentsh/agent-wrap"

setup_root() {
    rm -rf "$tmp"
    mkdir -p "$tmp/usr/lib/agentsh"
    mkdir -p "$tmp/searchable-bin"
    cat >"$WRAP" <<'EOF'
#!/bin/sh
exit 0
EOF
    chmod +x "$WRAP"
}

make_agent() {
    local name="$1"
    local dir="${2:-$tmp/searchable-bin}"
    mkdir -p "$dir"
    printf '#!/bin/sh\nexit 0\n' >"$dir/$name"
    chmod +x "$dir/$name"
}

run_installer() {
    # FAKE_TEST_PATH scopes the agent command -v lookup to our fake bin dir only.
    # System utilities (mv, ln, echo) use the outer PATH — not affected.
    AGENTSH_TEST=1 FAKE_ROOT="$tmp" FAKE_TEST_PATH="$tmp/searchable-bin" \
        "$installer" "$@"
}

# ---------------------------------------------------------------------------
# Test 1: No agents on PATH → nothing moved/created, exit 0
# ---------------------------------------------------------------------------
setup_root
run_installer >/dev/null 2>&1
if [ -n "$(ls -A "$tmp/searchable-bin" 2>/dev/null)" ]; then
    echo "FAIL test1: searchable-bin should be empty; found: $(ls "$tmp/searchable-bin")"
    exit 1
fi
echo "PASS: 1 — no agents → nothing created"

# ---------------------------------------------------------------------------
# Test 2: One agent on PATH → claude is now a symlink, claude.real exists
# ---------------------------------------------------------------------------
setup_root
make_agent "claude"
run_installer >/dev/null 2>&1
link_target=$(readlink "$tmp/searchable-bin/claude" 2>/dev/null || echo MISSING)
if [ "$link_target" != "$WRAP" ]; then
    echo "FAIL test2: claude should be symlink to WRAP; got: $link_target"
    exit 1
fi
if [ ! -x "$tmp/searchable-bin/claude.real" ]; then
    echo "FAIL test2: claude.real missing or not executable"
    exit 1
fi
echo "PASS: 2 — one agent wrapped (symlink + .real)"

# ---------------------------------------------------------------------------
# Test 3: Multiple agents on PATH → all wrapped
# ---------------------------------------------------------------------------
setup_root
for a in claude opencode; do
    make_agent "$a"
done
run_installer >/dev/null 2>&1
for a in claude opencode; do
    link=$(readlink "$tmp/searchable-bin/$a" 2>/dev/null || echo MISSING)
    if [ "$link" != "$WRAP" ]; then
        echo "FAIL test3: $a not wrapped; link=$link"
        exit 1
    fi
    if [ ! -e "$tmp/searchable-bin/$a.real" ]; then
        echo "FAIL test3: $a.real missing"
        exit 1
    fi
done
echo "PASS: 3 — multiple agents wrapped"

# ---------------------------------------------------------------------------
# Test 4: Foreign .real conflict → installer skips, warns, leaves files intact
# ---------------------------------------------------------------------------
setup_root
make_agent "claude"
# Simulate something else already claiming the .real slot
echo "foreign" >"$tmp/searchable-bin/claude.real"
chmod +x "$tmp/searchable-bin/claude.real"
out=$(run_installer 2>&1) || true
# claude should still be a regular file, NOT a symlink
if [ -L "$tmp/searchable-bin/claude" ]; then
    echo "FAIL test4: claude was overwritten with a symlink despite conflict"
    exit 1
fi
if ! echo "$out" | grep -q "not our symlink"; then
    echo "FAIL test4: expected 'not our symlink' warning; got: $out"
    exit 1
fi
echo "PASS: 4 — foreign .real conflict → skip with warning"

# ---------------------------------------------------------------------------
# Test 5: Wrap script missing → exit 0, warning, no agents touched
# ---------------------------------------------------------------------------
setup_root
rm "$WRAP"
make_agent "claude"
out=$(run_installer 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 0 ]; then
    echo "FAIL test5: missing-wrap should exit 0; got rc=$rc"
    exit 1
fi
if [ -L "$tmp/searchable-bin/claude" ]; then
    echo "FAIL test5: claude was symlinked despite missing wrap"
    exit 1
fi
if ! echo "$out" | grep -q "agent-wrap missing"; then
    echo "FAIL test5: expected 'agent-wrap missing' warning; got: $out"
    exit 1
fi
echo "PASS: 5 — missing wrap exits 0 with warning"

# ---------------------------------------------------------------------------
# Test 6: Idempotency — already-wrapped state is not double-renamed
# ---------------------------------------------------------------------------
setup_root
# Manually set up wrapped state: claude.real is the original, claude is symlink
make_agent "claude.real"  # the renamed-aside original
ln -s "$WRAP" "$tmp/searchable-bin/claude"
out=$(run_installer 2>&1)
# Should be silent (no warning lines about claude)
if echo "$out" | grep -q "claude"; then
    echo "FAIL test6: idempotent re-run produced output about claude: $out"
    exit 1
fi
# claude should still be symlink → WRAP
link=$(readlink "$tmp/searchable-bin/claude" 2>/dev/null || echo MISSING)
if [ "$link" != "$WRAP" ]; then
    echo "FAIL test6: claude no longer points to WRAP after re-run; link=$link"
    exit 1
fi
# claude.real must still exist
if [ ! -e "$tmp/searchable-bin/claude.real" ]; then
    echo "FAIL test6: claude.real vanished after re-run"
    exit 1
fi
echo "PASS: 6 — idempotent (silent, no double-rename)"

echo
echo "OK install-agent-wrappers.sh (6/6)"
