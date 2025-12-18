#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v python >/dev/null 2>&1; then
  echo "smoke: SKIP (python not found)" >&2
  exit 0
fi

socket_ok() {
  python - <<'PY' >/dev/null 2>&1
import socket
socket.socket()
PY
}

if ! socket_ok; then
  echo "smoke: SKIP (socket syscall not permitted in this environment)" >&2
  exit 0
fi

free_port() {
  python - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

tmp="$(mktemp -d)"
cleanup() {
  set +e
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    sleep 0.1
    kill -9 "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

export GOCACHE="${GOCACHE:-$repo_root/.gocache}"
export GOMODCACHE="${GOMODCACHE:-$repo_root/.gomodcache}"
export GOPATH="${GOPATH:-$repo_root/.gopath}"

make build >/dev/null

port="$(free_port)"
base_url="http://127.0.0.1:${port}"
export AGENTSH_SERVER="$base_url"

cat >"$tmp/config.yml" <<YAML
server:
  http:
    addr: "127.0.0.1:${port}"
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
  dir: "./configs/policies"
  default: "default"

sessions:
  base_dir: "${tmp}/sessions"
  max_sessions: 10

audit:
  enabled: true
  output: "${tmp}/audit.jsonl"
  storage:
    sqlite_path: "${tmp}/events.db"

sandbox:
  fuse:
    enabled: false
  network:
    enabled: false
YAML

./bin/agentsh server --config "$tmp/config.yml" >"$tmp/server.log" 2>&1 &
SERVER_PID="$!"

for _ in $(seq 1 200); do
  if curl -fsS "${base_url}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
if ! curl -fsS "${base_url}/health" >/dev/null 2>&1; then
  echo "smoke: server failed to become ready" >&2
  sed -n '1,200p' "$tmp/server.log" >&2 || true
  exit 1
fi

sid_json="$(./bin/agentsh session create --workspace .)"
sid="$(python -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])' <<<"$sid_json")"
if [[ -z "$sid" ]]; then
  echo "smoke: failed to parse session id" >&2
  echo "$sid_json" >&2
  exit 1
fi

out="$(./bin/agentsh exec "$sid" -- sh -lc 'echo hi' | tr -d '\r' | tail -n 1)"
if [[ "$out" != "hi" ]]; then
  echo "smoke: exec output mismatch: got=$out" >&2
  exit 1
fi

pty_out="$(./bin/agentsh exec --pty "$sid" -- sh -lc 'printf pty_hi' | tr -d '\r')"
if [[ "$pty_out" != *"pty_hi"* ]]; then
  echo "smoke: pty output mismatch: got=$pty_out" >&2
  exit 1
fi

# Shim delegation (simulated install).
shim_dir="$tmp/shim"
mkdir -p "$shim_dir"
cp -f ./bin/agentsh-shell-shim "$shim_dir/sh"
chmod +x "$shim_dir/sh"
ln -sf "$(command -v sh)" "$shim_dir/sh.real"

shim_out="$(AGENTSH_BIN="$repo_root/bin/agentsh" AGENTSH_SESSION_ID="$sid" AGENTSH_SERVER="$base_url" "$shim_dir/sh" -lc 'echo shim_hi' | tr -d '\r' | tail -n 1)"
if [[ "$shim_out" != "shim_hi" ]]; then
  echo "smoke: shim output mismatch: got=$shim_out" >&2
  exit 1
fi

echo "smoke: ok (sid=$sid url=$base_url)"

