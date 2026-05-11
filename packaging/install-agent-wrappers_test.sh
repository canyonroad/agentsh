#!/usr/bin/env bash
# Smoke test for packaging/install-agent-wrappers.sh.
# Drives the installer through 6 scenarios using a FAKE_ROOT.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
installer="$here/install-agent-wrappers.sh"

if [ ! -x "$installer" ]; then
    echo "FAIL: $installer missing or not executable"
    exit 1
fi

setup_root() {
    local root="$1"
    rm -rf "$root"
    mkdir -p "$root/usr/bin" "$root/usr/local/bin" "$root/usr/lib/agentsh"
    cat >"$root/usr/lib/agentsh/agent-wrap" <<'EOF'
#!/bin/sh
exit 0
EOF
    chmod +x "$root/usr/lib/agentsh/agent-wrap"
}

# Test 1: no agents present → no symlinks created
tmp=$(mktemp -d -t install-wrappers-1.XXXXXX); trap 'rm -rf "$tmp"' EXIT
setup_root "$tmp"
FAKE_ROOT="$tmp" "$installer" >/dev/null 2>&1
if [ -n "$(ls -A "$tmp/usr/local/bin")" ]; then
    echo "FAIL: empty /usr/bin should produce no symlinks; found: $(ls "$tmp/usr/local/bin")"
    exit 1
fi
echo "PASS: no agents → no symlinks"

# Test 2: one agent present → one symlink to agent-wrap
setup_root "$tmp"
touch "$tmp/usr/bin/claude"; chmod +x "$tmp/usr/bin/claude"
FAKE_ROOT="$tmp" "$installer" >/dev/null 2>&1
link_target=$(readlink "$tmp/usr/local/bin/claude" 2>/dev/null || echo MISSING)
if [ "$link_target" != "$tmp/usr/lib/agentsh/agent-wrap" ]; then
    echo "FAIL: one-agent case: link=$link_target"
    exit 1
fi
echo "PASS: one agent → one symlink"

# Test 3: multiple agents → all wrapped
setup_root "$tmp"
for a in claude opencode gemini; do
    touch "$tmp/usr/bin/$a"; chmod +x "$tmp/usr/bin/$a"
done
FAKE_ROOT="$tmp" "$installer" >/dev/null 2>&1
for a in claude opencode gemini; do
    if [ ! -L "$tmp/usr/local/bin/$a" ]; then
        echo "FAIL: $a was not wrapped"
        exit 1
    fi
done
echo "PASS: multiple agents → all wrapped"

# Test 4: pre-existing entry skipped (file)
setup_root "$tmp"
touch "$tmp/usr/bin/claude"; chmod +x "$tmp/usr/bin/claude"
echo "preexisting" >"$tmp/usr/local/bin/claude"
out=$(FAKE_ROOT="$tmp" "$installer" 2>&1)
if [ ! -f "$tmp/usr/local/bin/claude" ] || [ -L "$tmp/usr/local/bin/claude" ]; then
    echo "FAIL: pre-existing file at /usr/local/bin/claude was overwritten"
    exit 1
fi
content=$(cat "$tmp/usr/local/bin/claude")
if [ "$content" != "preexisting" ]; then
    echo "FAIL: pre-existing file content changed; got: $content"
    exit 1
fi
if ! echo "$out" | grep -q "exists; not overwriting"; then
    echo "FAIL: expected 'exists; not overwriting' message; got: $out"
    exit 1
fi
echo "PASS: pre-existing file skipped with warning"

# Test 5: missing wrap script → exit 0, warning, no symlinks
setup_root "$tmp"
rm "$tmp/usr/lib/agentsh/agent-wrap"
touch "$tmp/usr/bin/claude"; chmod +x "$tmp/usr/bin/claude"
out=$(FAKE_ROOT="$tmp" "$installer" 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 0 ]; then
    echo "FAIL: missing-wrap should exit 0 (fail-open); got rc=$rc"
    exit 1
fi
if [ -n "$(ls -A "$tmp/usr/local/bin")" ]; then
    echo "FAIL: missing-wrap should produce no symlinks"
    exit 1
fi
if ! echo "$out" | grep -q "agent-wrap missing"; then
    echo "FAIL: expected 'agent-wrap missing' warning; got: $out"
    exit 1
fi
echo "PASS: missing-wrap exits 0 with warning, no symlinks"

# Test 6: idempotent (run twice on multi-agent setup → same end state)
setup_root "$tmp"
for a in claude opencode; do
    touch "$tmp/usr/bin/$a"; chmod +x "$tmp/usr/bin/$a"
done
FAKE_ROOT="$tmp" "$installer" >/dev/null 2>&1
state1=$(find "$tmp/usr/local/bin" -maxdepth 1 | sort)
FAKE_ROOT="$tmp" "$installer" >/dev/null 2>&1
state2=$(find "$tmp/usr/local/bin" -maxdepth 1 | sort)
if [ "$state1" != "$state2" ]; then
    echo "FAIL: not idempotent"
    diff <(echo "$state1") <(echo "$state2") || true
    exit 1
fi
echo "PASS: idempotent"

echo
echo "OK install-agent-wrappers.sh (6/6)"
