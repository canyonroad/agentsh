#!/usr/bin/env bash
set -euo pipefail

# DNS integration test for agentsh
# Tests that DNS resolution works correctly through the ptrace DNS proxy:
#   - Allowed domains resolve successfully
#   - Denied domains are blocked

PASS=0
FAIL=0
ERRORS=""

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); ERRORS="${ERRORS}\n  - $1"; }

tmp="$(mktemp -d)"
cleanup() {
  set +e
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    sleep 0.2
    kill -9 "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

# --- Config ---
mkdir -p "$tmp/policies" "$tmp/sessions"

cat >"$tmp/config.yml" <<YAML
server:
  http:
    addr: "127.0.0.1:9876"
  grpc:
    enabled: false
  unix_socket:
    enabled: false

auth:
  type: "none"

metrics:
  enabled: false

health:
  path: "/health"
  readiness_path: "/ready"

policies:
  dir: "$tmp/policies"
  default: "dns-test"

sessions:
  base_dir: "$tmp/sessions"
  max_sessions: 10

audit:
  enabled: false

sandbox:
  ptrace:
    enabled: true
    attach_mode: children
    trace:
      execve: true
      file: true
      network: true
      signal: false
    performance:
      seccomp_prefilter: true
      max_tracees: 500
      max_hold_ms: 5000
    mask_tracer_pid: "off"
    on_attach_failure: fail_open
  fuse:
    enabled: false
  network:
    enabled: false
  unix_sockets:
    enabled: false
  seccomp:
    execve:
      enabled: false
YAML

cat >"$tmp/policies/dns-test.yaml" <<YAML
version: 1
name: dns-test
description: DNS integration test policy

network_rules:
  - name: allow-github
    description: Allow github.com DNS and connections
    domains:
      - "github.com"
      - "*.github.com"
    ports: [443, 80, 53]
    decision: allow

  - name: allow-localhost
    description: Allow localhost connections (for proxy)
    cidrs:
      - "127.0.0.1/32"
    decision: allow

  - name: deny-evil
    description: Block evil.com
    domains:
      - "evil.com"
      - "*.evil.com"
    decision: deny

  - name: default-deny
    description: Deny everything else
    domains:
      - "*"
    decision: deny

command_rules:
  - name: allow-all
    description: Allow all commands for testing
    commands:
      - "*"
    decision: allow

file_rules:
  - name: deny-etc
    paths: ["/etc/**"]
    decision: deny
  - name: allow-all
    paths: ["/**"]
    decision: allow
YAML

# --- Start server ---
echo "Starting agentsh server..."
export AGENTSH_SERVER="http://127.0.0.1:9876"
agentsh server --config "$tmp/config.yml" >"$tmp/server.log" 2>&1 &
SERVER_PID="$!"

# Wait for health
for _ in $(seq 1 200); do
  if curl -fsS "${AGENTSH_SERVER}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
if ! curl -fsS "${AGENTSH_SERVER}/health" >/dev/null 2>&1; then
  echo "FATAL: server failed to become ready"
  cat "$tmp/server.log" >&2 || true
  exit 1
fi
echo "Server ready."

# --- Create session ---
sid_json="$(agentsh session create --workspace /root --policy dns-test --json)"
sid="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])' <<<"$sid_json")"
if [[ -z "$sid" ]]; then
  echo "FATAL: failed to parse session id"
  echo "$sid_json" >&2
  exit 1
fi
echo "Session created: $sid"
echo ""

# --- Test 1: DNS resolution for allowed domain ---
# This test requires upstream DNS connectivity; skip gracefully if unavailable.
echo "Test 1: DNS resolution for allowed domain (github.com)"
set +e
dns_allow_out="$(agentsh exec "$sid" -- python3 -c "
import socket
try:
    result = socket.getaddrinfo('github.com', 443)
    print('RESOLVED:' + result[0][4][0])
except Exception as e:
    print('ERROR:' + str(e))
" 2>&1)"
dns_allow_rc=$?
set -e

if echo "$dns_allow_out" | grep -q "^RESOLVED:"; then
  ip="$(echo "$dns_allow_out" | grep "^RESOLVED:" | head -1 | cut -d: -f2)"
  pass "github.com resolved to $ip"
elif echo "$dns_allow_out" | grep -qE "Temporary failure in name resolution|connection refused"; then
  echo "  SKIP: no upstream DNS available (expected in isolated containers)"
else
  fail "github.com DNS resolution failed: $dns_allow_out (rc=$dns_allow_rc)"
fi

# --- Test 2: DNS resolution for denied domain ---
echo "Test 2: DNS resolution for denied domain (evil.com)"
set +e
dns_deny_out="$(agentsh exec "$sid" -- python3 -c "
import socket
try:
    result = socket.getaddrinfo('evil.com', 443)
    print('RESOLVED:' + result[0][4][0])
except socket.gaierror as e:
    print('BLOCKED:' + str(e))
except Exception as e:
    print('ERROR:' + str(e))
" 2>&1)"
dns_deny_rc=$?
set -e

if echo "$dns_deny_out" | grep -q "^BLOCKED:"; then
  pass "evil.com correctly blocked"
elif echo "$dns_deny_out" | grep -q "^RESOLVED:"; then
  fail "evil.com should have been blocked but resolved: $dns_deny_out"
else
  fail "evil.com test returned unexpected output: $dns_deny_out (rc=$dns_deny_rc)"
fi

# --- Test 3: Symlink escape (file policy) ---
echo "Test 3: Symlink escape (/tmp/escape -> /etc/passwd should be denied)"
set +e
ln -sf /etc/passwd /tmp/escape 2>/dev/null || true
symlink_out="$(agentsh exec "$sid" -- cat /tmp/escape 2>&1)"
symlink_rc=$?
rm -f /tmp/escape
set -e

if [[ $symlink_rc -ne 0 ]]; then
  pass "symlink escape correctly denied (rc=$symlink_rc)"
elif echo "$symlink_out" | grep -q "root:"; then
  fail "symlink escape allowed read of /etc/passwd through /tmp/escape"
else
  pass "symlink escape blocked (no /etc/passwd content)"
fi

# --- Test 4: Python subprocess sudo ---
echo "Test 4: Python subprocess running sudo (should not hang)"
set +e
sudo_out="$(timeout 60 agentsh exec "$sid" -- python3 -c "
import subprocess
r = subprocess.run(['sudo','echo','hi'], capture_output=True, timeout=30)
print('RC:'+str(r.returncode))
" 2>&1)"
sudo_rc=$?
set -e

if [[ $sudo_rc -eq 124 ]]; then
  fail "python subprocess sudo timed out"
elif echo "$sudo_out" | grep -q "^RC:"; then
  pass "python subprocess sudo completed ($(echo "$sudo_out" | grep '^RC:' | head -1))"
else
  fail "python subprocess sudo unexpected output: $sudo_out (rc=$sudo_rc)"
fi

# --- Test 5: Python subprocess ls ---
echo "Test 5: Python subprocess running ls (should not hang)"
set +e
ls_out="$(timeout 60 agentsh exec "$sid" -- python3 -c "
import subprocess
r = subprocess.run(['ls','/tmp'], capture_output=True, timeout=30)
print('OK:'+r.stdout.decode()[:20])
" 2>&1)"
ls_rc=$?
set -e

if [[ $ls_rc -eq 124 ]]; then
  fail "python subprocess ls timed out"
elif echo "$ls_out" | grep -q "^OK:"; then
  pass "python subprocess ls completed"
else
  fail "python subprocess ls unexpected output: $ls_out (rc=$ls_rc)"
fi

# --- Summary ---
echo ""
echo "========================================="
echo "DNS Integration Test Results"
echo "========================================="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
if [[ $FAIL -gt 0 ]]; then
  echo -e "\nFailures:$ERRORS"
  echo ""
  echo "Server log (last 50 lines):"
  tail -n 50 "$tmp/server.log" 2>/dev/null || true
  exit 1
fi
echo ""
echo "All tests passed!"
