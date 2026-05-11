#!/usr/bin/env bash
# Manual smoke test exercised inside a Docker Sandbox that has the AgentSH
# mixin kit installed. Run via:
#   sbx exec <session> bash /workspace/.claude/skills/agentsh/coding-agent-smoke.sh
#
# Or copy this file into the sandbox manually and run it as the agent user.
#
# Each check prints PASS / FAIL. Exits non-zero on any FAIL.

set -u

pass=0
fail=0

assert() {
  local label="$1"
  local got="$2"
  local want="$3"
  if [ "$got" = "$want" ]; then
    echo "PASS: $label"
    pass=$((pass+1))
  else
    printf 'FAIL: %s (got=%q, want=%q)\n' "$label" "$got" "$want" >&2
    fail=$((fail+1))
  fi
}

assert_contains() {
  local label="$1"
  local got="$2"
  local want="$3"
  if printf '%s' "$got" | grep -q -- "$want"; then
    echo "PASS: $label"
    pass=$((pass+1))
  else
    echo "FAIL: $label (output did not contain $want)"
    echo "----- got: -----"
    printf '%s\n' "$got"
    echo "----------------"
    fail=$((fail+1))
  fi
}

# Check 1: tier file says shim
got=$(cat /run/agentsh/tier 2>/dev/null || echo missing)
assert "tier file = shim" "$got" "shim"

# Check 2: curl resolves under the shim dir
resolved=$(command -v curl)
assert_contains "curl resolves under shim dir" "$resolved" "/usr/lib/agentsh/shims"

# Check 3: cat ~/.ssh/id_rsa is denied (no such file is fine; we expect either ENOENT or EACCES via deny)
mkdir -p "$HOME/.ssh"
printf 'fake-key\n' > "$HOME/.ssh/id_rsa.smoke"
out=$(cat "$HOME/.ssh/id_rsa.smoke" 2>&1) && rc=0 || rc=$?
rm -f "$HOME/.ssh/id_rsa.smoke"
if [ "$rc" -ne 0 ]; then
  echo "PASS: cat ~/.ssh/id_rsa.smoke denied (rc=$rc)"
  pass=$((pass+1))
else
  echo "FAIL: cat ~/.ssh/id_rsa.smoke succeeded — deny rule did not fire"
  echo "----- got: -----"
  echo "$out"
  echo "----------------"
  fail=$((fail+1))
fi

# Check 4: sudo is denied
out=$(sudo whoami 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "PASS: sudo denied (rc=$rc)"
  pass=$((pass+1))
else
  echo "FAIL: sudo succeeded — deny rule did not fire"
  echo "----- got: -----"
  echo "$out"
  echo "----------------"
  fail=$((fail+1))
fi

# Check 5: soft-delete on /workspace
mkdir -p /workspace
echo "$$" > /workspace/smoke.tmp
rm /workspace/smoke.tmp 2>/dev/null || true
if [ -f /workspace/smoke.tmp ]; then
  echo "FAIL: /workspace/smoke.tmp still present after rm"
  fail=$((fail+1))
else
  # Look for it in the trash directory
  if find /var/lib/agentsh/trash -name smoke.tmp 2>/dev/null | grep -q smoke.tmp; then
    echo "PASS: soft-delete recoverable"
    pass=$((pass+1))
  else
    echo "FAIL: soft-delete trash entry not found"
    fail=$((fail+1))
  fi
fi

echo
echo "summary: $pass pass, $fail fail"
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
