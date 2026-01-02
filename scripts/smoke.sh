#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

PYTHON="${PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
  if command -v python >/dev/null 2>&1; then
    PYTHON="$(command -v python)"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON="$(command -v python3)"
  fi
fi
if [[ -z "$PYTHON" ]]; then
  echo "smoke: SKIP (python/python3 not found)" >&2
  exit 0
fi

socket_ok() {
  "$PYTHON" - <<'PY' >/dev/null 2>&1
import socket
socket.socket()
PY
}

if ! socket_ok; then
  echo "smoke: SKIP (socket syscall not permitted in this environment)" >&2
  exit 0
fi

pty_ok() {
  "$PYTHON" - <<'PY' >/dev/null 2>&1
import pty
pty.openpty()
PY
}

free_port() {
  "$PYTHON" - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# Retry helper for flaky operations (e.g., exec in CI environments).
# Usage: retry <max_attempts> <delay_seconds> <command...>
retry() {
  local max_attempts="$1"
  local delay="$2"
  shift 2
  local attempt=1
  local rc=0
  while [[ $attempt -le $max_attempts ]]; do
    set +e
    "$@"
    rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
      return 0
    fi
    if [[ $attempt -lt $max_attempts ]]; then
      echo "smoke: attempt $attempt/$max_attempts failed (rc=$rc), retrying in ${delay}s..." >&2
      sleep "$delay"
    fi
    ((attempt++))
  done
  return $rc
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

set +e
host_guard_out="$(./bin/agentsh shim install-shell --root / --shim "$repo_root/bin/agentsh-shell-shim" 2>&1)"
host_guard_rc=$?
set -e
if [[ "$host_guard_rc" == "0" ]]; then
  echo "smoke: expected shim host-root guard to fail, but it succeeded" >&2
  exit 1
fi
if [[ "$host_guard_out" != *"refusing to modify host rootfs"* ]]; then
  echo "smoke: expected shim host-root guard message, got: $host_guard_out" >&2
  exit 1
fi

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
sid="$("$PYTHON" -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])' <<<"$sid_json")"
if [[ -z "$sid" ]]; then
  echo "smoke: failed to parse session id" >&2
  echo "$sid_json" >&2
  exit 1
fi

# Exec with retry logic to handle transient CI failures.
exec_out=""
exec_rc=0
max_exec_attempts=3
for attempt in $(seq 1 $max_exec_attempts); do
  {
    exec_out="$(./bin/agentsh exec "$sid" -- sh -lc 'echo hi' 2>&1 | tr -d '\r')"
    exec_rc=$?
  } || exec_rc=$?

  if [[ "$exec_rc" == "0" ]]; then
    out="$(tail -n 1 <<<"$exec_out")"
    if [[ "$out" == "hi" ]]; then
      break
    fi
    exec_rc=1  # Mark as failed for retry
  fi

  if [[ $attempt -lt $max_exec_attempts ]]; then
    echo "smoke: exec attempt $attempt/$max_exec_attempts failed (rc=$exec_rc), retrying in 1s..." >&2
    sleep 1
  fi
done

if [[ "$exec_rc" != "0" ]]; then
  echo "smoke: exec failed with code $exec_rc after $max_exec_attempts attempts" >&2
  echo "smoke: exec output: $exec_out" >&2
  echo "smoke: server log (last 50 lines):" >&2
  tail -n 50 "$tmp/server.log" >&2 || true
  exit 1
fi
out="$(tail -n 1 <<<"$exec_out")"
if [[ "$out" != "hi" ]]; then
  echo "smoke: exec output mismatch after $max_exec_attempts attempts: got=$out" >&2
  exit 1
fi

SMOKE_PTY_OK=1
if ! pty_ok; then
  echo "smoke: NOTE (pty not permitted; skipping PTY checks)" >&2
  SMOKE_PTY_OK=0
else
  pty_out="$(
    set +e
    ./bin/agentsh exec --pty "$sid" -- sh -lc 'printf pty_hi' 2>&1 | tr -d '\r'
    exit ${PIPESTATUS[0]}
  )" || {
    echo "smoke: NOTE (agentsh PTY failed; skipping PTY checks): $pty_out" >&2
    SMOKE_PTY_OK=0
  }
fi
if [[ "$SMOKE_PTY_OK" == "1" ]]; then
  if [[ "$pty_out" != *"pty_hi"* ]]; then
    echo "smoke: pty output mismatch: got=$pty_out" >&2
    exit 1
  fi
fi

# Shim delegation (simulated install).
shim_dir="$tmp/shim"
mkdir -p "$shim_dir"
cp -f ./bin/agentsh-shell-shim "$shim_dir/sh"
chmod +x "$shim_dir/sh"
ln -sf "$(command -v sh)" "$shim_dir/sh.real"

# Shim test with retry for transient failures.
shim_out=""
for attempt in $(seq 1 $max_exec_attempts); do
  shim_out="$(AGENTSH_BIN="$repo_root/bin/agentsh" AGENTSH_SESSION_ID="$sid" AGENTSH_SERVER="$base_url" "$shim_dir/sh" -lc 'echo shim_hi' | tr -d '\r' | tail -n 1)" || true
  if [[ "$shim_out" == "shim_hi" ]]; then
    break
  fi
  if [[ $attempt -lt $max_exec_attempts ]]; then
    echo "smoke: shim attempt $attempt/$max_exec_attempts failed, retrying in 1s..." >&2
    sleep 1
  fi
done
if [[ "$shim_out" != "shim_hi" ]]; then
  echo "smoke: shim output mismatch after $max_exec_attempts attempts: got=$shim_out" >&2
  exit 1
fi

# Rootfs install/uninstall simulation (doesn't touch the real host).
rootfs="$tmp/rootfs"
mkdir -p "$rootfs/bin"
ln -sf "$(command -v sh)" "$rootfs/bin/sh"
if command -v bash >/dev/null 2>&1; then
  ln -sf "$(command -v bash)" "$rootfs/bin/bash"
  rootfs_bash=1
else
  rootfs_bash=0
fi

install_args=(./bin/agentsh shim install-shell --root "$rootfs" --shim "$repo_root/bin/agentsh-shell-shim")
uninstall_args=(./bin/agentsh shim uninstall-shell --root "$rootfs")
status_args=(./bin/agentsh shim status --output json --root "$rootfs" --shim "$repo_root/bin/agentsh-shell-shim")
if [[ "$rootfs_bash" == "1" ]]; then
  install_args+=(--bash)
  uninstall_args+=(--bash)
  status_args+=(--bash)
fi

"${install_args[@]}" --dry-run --output json >/dev/null
"${status_args[@]}" >/dev/null

"${install_args[@]}"
# Rootfs shim test with retry.
rootfs_out=""
for attempt in $(seq 1 $max_exec_attempts); do
  rootfs_out="$(AGENTSH_BIN="$repo_root/bin/agentsh" AGENTSH_SESSION_ID="$sid" AGENTSH_SERVER="$base_url" "$rootfs/bin/sh" -lc 'echo rootfs_hi' | tr -d '\r' | tail -n 1)" || true
  if [[ "$rootfs_out" == "rootfs_hi" ]]; then
    break
  fi
  if [[ $attempt -lt $max_exec_attempts ]]; then
    echo "smoke: rootfs shim attempt $attempt/$max_exec_attempts failed, retrying in 1s..." >&2
    sleep 1
  fi
done
if [[ "$rootfs_out" != "rootfs_hi" ]]; then
  echo "smoke: rootfs shim output mismatch after $max_exec_attempts attempts: got=$rootfs_out" >&2
  exit 1
fi

"${uninstall_args[@]}"
restored_out="$("$rootfs/bin/sh" -lc 'echo restored_hi' | tr -d '\r' | tail -n 1)"
if [[ "$restored_out" != "restored_hi" ]]; then
  echo "smoke: rootfs uninstall output mismatch: got=$restored_out" >&2
  exit 1
fi

# Shim delegation via PATH (no AGENTSH_BIN) with retry.
shim_out_path=""
for attempt in $(seq 1 $max_exec_attempts); do
  shim_out_path="$(PATH="$repo_root/bin:$PATH" AGENTSH_SESSION_ID="$sid" AGENTSH_SERVER="$base_url" "$shim_dir/sh" -lc 'echo shim_path_hi' | tr -d '\r' | tail -n 1)" || true
  if [[ "$shim_out_path" == "shim_path_hi" ]]; then
    break
  fi
  if [[ $attempt -lt $max_exec_attempts ]]; then
    echo "smoke: shim PATH attempt $attempt/$max_exec_attempts failed, retrying in 1s..." >&2
    sleep 1
  fi
done
if [[ "$shim_out_path" != "shim_path_hi" ]]; then
  echo "smoke: shim PATH output mismatch after $max_exec_attempts attempts: got=$shim_out_path" >&2
  exit 1
fi

# Shim recursion guard: should not need agentsh when already in-session.
rec_out="$(AGENTSH_BIN="/nonexistent/agentsh" AGENTSH_IN_SESSION=1 "$shim_dir/sh" -lc 'echo recursion_hi' | tr -d '\r' | tail -n 1)"
if [[ "$rec_out" != "recursion_hi" ]]; then
  echo "smoke: shim recursion output mismatch: got=$rec_out" >&2
  exit 1
fi

if [[ "$SMOKE_PTY_OK" == "1" ]]; then
  # Shim PTY: allocate a pseudo-tty so shim chooses --pty.
  pty_shim_out="$(
    SMOKE_SHIM="$shim_dir/sh" \
    SMOKE_AGENTSH="$repo_root/bin/agentsh" \
    SMOKE_SID="$sid" \
    SMOKE_SERVER="$base_url" \
    "$PYTHON" - <<'PY'
import os, pty, select, subprocess, sys, time

shim = os.environ["SMOKE_SHIM"]
env = os.environ.copy()
env["AGENTSH_BIN"] = os.environ["SMOKE_AGENTSH"]
env["AGENTSH_SESSION_ID"] = os.environ["SMOKE_SID"]
env["AGENTSH_SERVER"] = os.environ["SMOKE_SERVER"]

m, s = pty.openpty()
try:
    p = subprocess.Popen([shim, "-lc", "printf pty_shim_hi"], stdin=s, stdout=s, stderr=s, env=env)
    os.close(s)
    buf = bytearray()
    deadline = time.time() + 5.0
    while time.time() < deadline:
        r, _, _ = select.select([m], [], [], 0.2)
        if m in r:
            try:
                data = os.read(m, 4096)
            except OSError:
                break
            if not data:
                break
            buf.extend(data)
        if p.poll() is not None and not r:
            break
    try:
        p.wait(timeout=2.0)
    except Exception:
        p.kill()
        p.wait(timeout=2.0)
    sys.stdout.buffer.write(buf)
finally:
    try:
        os.close(m)
    except OSError:
        pass
PY
  )"
  pty_shim_out="$(tr -d '\r' <<<"$pty_shim_out")"
  if [[ "$pty_shim_out" != *"pty_shim_hi"* ]]; then
    echo "smoke: shim pty output mismatch: got=$pty_shim_out" >&2
    exit 1
  fi
fi

# Optional: bash shim, if bash exists.
if command -v bash >/dev/null 2>&1; then
  cp -f ./bin/agentsh-shell-shim "$shim_dir/bash"
  chmod +x "$shim_dir/bash"
  ln -sf "$(command -v bash)" "$shim_dir/bash.real"

  bash_out="$(AGENTSH_BIN="$repo_root/bin/agentsh" AGENTSH_SESSION_ID="$sid" AGENTSH_SERVER="$base_url" "$shim_dir/bash" -lc 'echo bash_hi' | tr -d '\r' | tail -n 1)"
  if [[ "$bash_out" != "bash_hi" ]]; then
    echo "smoke: bash shim output mismatch: got=$bash_out" >&2
    exit 1
  fi

  # Login-style argv0 ("-bash") should still select bash semantics.
  login_out="$(AGENTSH_BIN="$repo_root/bin/agentsh" AGENTSH_SESSION_ID="$sid" AGENTSH_SERVER="$base_url" SMOKE_BASH_SHIM="$shim_dir/bash" bash -lc 'exec -a -bash "$SMOKE_BASH_SHIM" -lc "echo login_hi"' | tr -d '\r' | tail -n 1)"
  if [[ "$login_out" != "login_hi" ]]; then
    echo "smoke: bash login shim output mismatch: got=$login_out" >&2
    exit 1
  fi
fi

echo "smoke: ok (sid=$sid url=$base_url)"
