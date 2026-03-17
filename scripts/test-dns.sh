#!/usr/bin/env bash
set -euo pipefail

# DNS integration test for agentsh
# Tests that DNS resolution works correctly through the ptrace DNS proxy:
#   - Allowed domains resolve successfully
#   - Denied domains are blocked

PASS=0
FAIL=0
ERRORS=""

pass() { echo "  PASS: $1"; ((PASS++)); }
fail() { echo "  FAIL: $1"; ((FAIL++)); ERRORS="${ERRORS}\n  - $1"; }

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
      file: false
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
sid_json="$(agentsh session create --workspace /root --json)"
sid="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])' <<<"$sid_json")"
if [[ -z "$sid" ]]; then
  echo "FATAL: failed to parse session id"
  echo "$sid_json" >&2
  exit 1
fi
echo "Session created: $sid"
echo ""

# --- Test 1: DNS resolution for allowed domain ---
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
