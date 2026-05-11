#!/usr/bin/env bash
# E2E test for the AgentSH Docker Sandboxes mixin kit.
#
# Verifies kit mechanics against a real Docker Sandboxes agent template
# (docker/sandbox-templates:shell-docker) without requiring `sbx` itself.
# Builds the binaries on the host, mounts them into the agent-template
# container, simulates what `sbx run --kit` would do (install layout
# + initFiles + startup), and runs verification checks.
#
# What this proves works:
#   1. The bootstrap binary merges /usr/share/agentsh/coding-agent.template.yaml
#      with /home/agent/.agentsh/policy.yaml into /etc/agentsh/policies/default.yaml.
#   2. The merged file contains both baked rules AND user-override rules
#      (replace-by-name + append semantics, exercised end-to-end).
#   3. The PATH wiring from /etc/profile.d/agentsh.sh resolves `command -v curl`
#      under /usr/lib/agentsh/shims/.
#   4. /run/agentsh/tier is written with the active tier name.
#
# Out of scope here (still gated on a real `sbx run` + tagged release):
#   - In-sandbox enforcement of file/command/signal rules (the agentsh server's
#     denial paths). The bootstrap is fail-open on a missing or unstartable
#     daemon, so this test side-steps starting the daemon and instead asserts
#     the bootstrap's deterministic outputs.
#   - The `install` step actually downloading install.sh — that needs a tagged
#     release. See docker/sbx-kit/README.md for the manual `sbx run` recipe.
#
# Usage:
#   docker/sbx-kit/tests/run-e2e.sh
#   make sbx-e2e
#
# Exit codes:
#   0 — all checks passed
#   1 — host prerequisite missing (docker, go)
#   2 — build failed
#   3 — one or more verification checks failed

set -euo pipefail

# Resolve repo root regardless of caller's CWD.
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
cd "$REPO"

IMAGE="docker/sandbox-templates:shell-docker"
CONTAINER="agentsh-sbx-e2e-$$"
STAGE="$(mktemp -d -t agentsh-sbx-e2e.XXXXXX)"

PASS=0
FAIL=0

log()    { printf '%s\n' "$*"; }
pass()   { printf 'PASS: %s\n' "$*"; PASS=$((PASS + 1)); }
fail()   { printf 'FAIL: %s\n' "$*" >&2; FAIL=$((FAIL + 1)); }

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$STAGE"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Host prerequisites
# ---------------------------------------------------------------------------

command -v docker >/dev/null 2>&1 || { log "docker not found"; exit 1; }
command -v go     >/dev/null 2>&1 || { log "go not found"; exit 1; }

# ---------------------------------------------------------------------------
# 2. Build the binaries we'll mount into the container
# ---------------------------------------------------------------------------
# Build with GOOS=linux GOARCH=amd64 so the binary runs in the linux/amd64
# sandbox image regardless of what we're building on. CGO_ENABLED=0 keeps
# the binary statically linked — we don't need libseccomp because this test
# does not start the agentsh server.

log "Building binaries for linux/amd64 (CGO_ENABLED=0)..."
mkdir -p "$STAGE/bin"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$STAGE/bin/agentsh-shell-shim" ./cmd/agentsh-shell-shim
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$STAGE/bin/agentsh-sbx-bootstrap" ./cmd/agentsh-sbx-bootstrap

# Empty stub for /usr/bin/agentsh so the bootstrap's spawnDaemon doesn't
# exec a missing binary. The bootstrap is fail-open on socket-wait, so a
# no-op server is acceptable for the mechanics test.
cat >"$STAGE/bin/agentsh" <<'STUB'
#!/bin/sh
# E2E test stub: the agentsh server is not exercised in this test.
exec sleep 600
STUB
chmod +x "$STAGE/bin/agentsh"

# ---------------------------------------------------------------------------
# 3. Stage the user override that we'll bind-mount into the container.
#    Choose rules that exercise BOTH replace-by-name AND append semantics
#    so the merge step is genuinely tested, not just executed.
# ---------------------------------------------------------------------------

mkdir -p "$STAGE/home-overrides"
cat >"$STAGE/home-overrides/policy.yaml" <<'YAML'
version: 1
name: e2e-overrides
file_rules:
  # New rule, must APPEND after the baked set.
  - name: e2e-allow-data
    paths: ["/data/**"]
    operations: ["*"]
    decision: allow

  # Same name as a baked rule — must REPLACE the baked allow-tmp in place.
  - name: allow-tmp
    paths: ["/tmp/**", "/var/tmp/**", "/srv/scratch/**"]
    operations: ["*"]
    decision: allow
YAML

# ---------------------------------------------------------------------------
# 4. Start the container with the kit's pieces bind-mounted in.
#    --user 0 is required because we touch /usr, /etc, /run, /var/log.
# ---------------------------------------------------------------------------

log "Starting container ($IMAGE)..."
docker run -d --rm --name "$CONTAINER" --user 0 \
  -v "$STAGE/bin:/sbx-e2e/bin:ro" \
  -v "$REPO/configs/policies/coding-agent.yaml:/sbx-e2e/coding-agent.yaml:ro" \
  -v "$REPO/packaging/config.yaml:/sbx-e2e/server-config.yaml:ro" \
  -v "$REPO/docker/sbx-kit/files:/sbx-e2e/kit-files:ro" \
  -v "$STAGE/home-overrides/policy.yaml:/sbx-e2e/user-override.yaml:ro" \
  -v "$REPO/packaging/agent-wrap.sh:/sbx-e2e/agent-wrap:ro" \
  -v "$REPO/packaging/install-agent-wrappers.sh:/sbx-e2e/install-agent-wrappers:ro" \
  "$IMAGE" \
  sleep 600 >/dev/null

# Helper: run a command inside the container as root.
in_container() {
  docker exec --user 0 "$CONTAINER" /bin/bash -c "$1"
}

# ---------------------------------------------------------------------------
# 5. Simulate what `sbx run --kit ./docker/sbx-kit/` would do at install
#    time: copy binaries to /usr/bin, the policy template to /usr/share,
#    the server config to /etc, set up shim symlinks, drop the override
#    fragment into the agent's home, and write the kit's initFiles.
# ---------------------------------------------------------------------------

log "Installing kit payload inside the container..."
in_container '
set -e

# Binaries
install -m 0755 /sbx-e2e/bin/agentsh-shell-shim /usr/bin/agentsh-shell-shim
install -m 0755 /sbx-e2e/bin/agentsh-sbx-bootstrap /usr/bin/agentsh-sbx-bootstrap
install -m 0755 /sbx-e2e/bin/agentsh /usr/bin/agentsh

# Policy template (read-only system path)
install -D -m 0644 /sbx-e2e/coding-agent.yaml /usr/share/agentsh/coding-agent.template.yaml

# Server config
install -D -m 0644 /sbx-e2e/server-config.yaml /etc/agentsh/config.yaml
mkdir -p /etc/agentsh/policies

# Shim directory + symlinks (the .goreleaser.yml ships these on real packages;
# we recreate them here from the canonical list).
mkdir -p /usr/lib/agentsh/shims
for cmd in bash sh curl wget pip pip3 npm node git python python3 rm; do
  ln -sf /usr/bin/agentsh-shell-shim /usr/lib/agentsh/shims/$cmd
done

# Kit `files/` tree — the same content `sbx run --kit` would drop.
install -D -m 0644 \
  /sbx-e2e/kit-files/workspace/.claude/skills/agentsh/SKILL.md \
  /workspace/.claude/skills/agentsh/SKILL.md
install -D -m 0644 \
  /sbx-e2e/kit-files/home/agent/.agentsh/policy.yaml \
  /home/agent/.agentsh/policy.yaml
# Replace the empty stub with the test override so the merge step has something
# meaningful to merge.
install -m 0644 /sbx-e2e/user-override.yaml /home/agent/.agentsh/policy.yaml

# Kit `initFiles`
cat >/etc/profile.d/agentsh.sh <<EOF
export PATH=/usr/lib/agentsh/shims:\$PATH
EOF
chmod 0644 /etc/profile.d/agentsh.sh

mkdir -p /etc/environment.d
cat >/etc/environment.d/10-agentsh.conf <<EOF
PATH=/usr/lib/agentsh/shims:/usr/local/bin:/usr/bin:/bin
EOF
chmod 0644 /etc/environment.d/10-agentsh.conf

# Directories the bootstrap expects to write into.
mkdir -p /run/agentsh /var/log/agentsh
'

# ---------------------------------------------------------------------------
# 6. Run the bootstrap — the kit's startup command.
#    The fake `agentsh` will spawn, the socket-wait will time out (2s) and
#    the bootstrap logs and continues. The shim probe runs against the
#    PATH we set up, and the tier file is written.
# ---------------------------------------------------------------------------

log "Running agentsh-sbx-bootstrap..."
in_container '/usr/bin/agentsh-sbx-bootstrap' >"$STAGE/bootstrap.log" 2>&1 || true

# ---------------------------------------------------------------------------
# 7. Checks
# ---------------------------------------------------------------------------

log
log "Verifying kit mechanics:"

# Check 1: /run/agentsh/tier exists and says "shim".
tier=$(in_container 'cat /run/agentsh/tier 2>/dev/null || echo MISSING')
if [ "$tier" = "shim" ]; then
  pass "tier file = shim"
else
  fail "tier file = '$tier' (want 'shim')"
  log  "---- bootstrap log ----"
  cat "$STAGE/bootstrap.log"
  log  "-----------------------"
fi

# Check 2: PATH wiring resolves curl under the shim dir.
# We use `bash -lc` so /etc/profile.d/agentsh.sh is sourced — that's how the
# kit's initFiles delivers the shim PATH in production.
resolved=$(in_container "bash -lc 'command -v curl'" || echo NONE)
if printf '%s' "$resolved" | grep -q '^/usr/lib/agentsh/shims/curl$'; then
  pass "curl resolves under /usr/lib/agentsh/shims/"
else
  fail "curl resolved to '$resolved' (want /usr/lib/agentsh/shims/curl)"
fi

# Check 3: /etc/agentsh/policies/default.yaml is the merged output.
#   - Contains a baked rule name (proves the template was loaded).
#   - Contains the override's appended rule (proves append-by-name worked).
#   - The replaced rule's overlay paths win (proves replace-by-name worked).
merged=$(in_container 'cat /etc/agentsh/policies/default.yaml')
if printf '%s' "$merged" | grep -q 'deny-credential-paths'; then
  pass "merged policy contains baked rule 'deny-credential-paths'"
else
  fail "merged policy missing baked rule 'deny-credential-paths'"
fi

if printf '%s' "$merged" | grep -q 'e2e-allow-data'; then
  pass "merged policy contains appended override rule 'e2e-allow-data'"
else
  fail "merged policy missing appended override rule 'e2e-allow-data'"
fi

# The baked allow-tmp has /tmp/** and /var/tmp/**. The override added
# /srv/scratch/**. After merge, the override's paths win (replace-by-name).
if printf '%s' "$merged" | grep -q '/srv/scratch'; then
  pass "merged policy contains override paths for 'allow-tmp' (replace-by-name)"
else
  fail "merged policy missing /srv/scratch/** from override 'allow-tmp'"
fi

# Check 4: Self-teaching artifacts landed where the kit's files/ tree expects.
if in_container 'test -f /workspace/.claude/skills/agentsh/SKILL.md'; then
  pass "SKILL.md present at /workspace/.claude/skills/agentsh/"
else
  fail "SKILL.md missing from /workspace/.claude/skills/agentsh/"
fi

if in_container 'test -f /home/agent/.agentsh/policy.yaml'; then
  pass "user override stub present at /home/agent/.agentsh/policy.yaml"
else
  fail "user override stub missing from /home/agent/.agentsh/policy.yaml"
fi

# ---------------------------------------------------------------------------
# 8. Wrapper engagement check.
#    Install a fake /usr/bin/claude stub, a fake `agentsh` that emits a
#    recognizable marker, run the installer to create /usr/local/bin/claude,
#    then invoke claude via a login shell and verify the wrap chain fired.
# ---------------------------------------------------------------------------

log
log "Verifying agent wrap engagement:"

in_container '
set -e

# Fake agentsh that announces itself when called as `agentsh wrap`.
cat >/usr/bin/agentsh <<EOF
#!/bin/sh
echo "FAKE-AGENTSH-WRAP-MARKER: \$*"
EOF
chmod +x /usr/bin/agentsh

# Fake claude binary.
cat >/usr/bin/claude <<EOF
#!/bin/sh
echo "REAL-CLAUDE-MARKER: \$*"
EOF
chmod +x /usr/bin/claude

# Copy the installer and wrap script into the container at the production
# layout. (In real `sbx run`, install.sh would do this via the OS package;
# here we side-load from the host so the E2E does not depend on a tagged
# release.)
install -m 0755 /sbx-e2e/agent-wrap /usr/lib/agentsh/agent-wrap
install -m 0755 /sbx-e2e/install-agent-wrappers /usr/lib/agentsh/install-agent-wrappers.sh

# Run the installer.
/usr/lib/agentsh/install-agent-wrappers.sh
'

# Now invoke `claude` from a login shell — bash -lc sources profile.d, which
# puts /usr/local/bin on PATH ahead of /usr/bin (the default on most distros).
out=$(in_container "bash -lc 'claude --version'" 2>&1 || true)

if printf '%s' "$out" | grep -q 'FAKE-AGENTSH-WRAP-MARKER: wrap -- /usr/bin/claude --version'; then
    pass "wrapper engages \`agentsh wrap\` with args preserved"
else
    fail "wrapper did not engage wrap (or args dropped)"
    log  "----- claude invocation output -----"
    printf '%s\n' "$out"
    log  "------------------------------------"
fi

# ---------------------------------------------------------------------------
# 9. Summary
# ---------------------------------------------------------------------------

log
log "summary: $PASS pass, $FAIL fail"
if [ "$FAIL" -gt 0 ]; then
  log
  log "---- bootstrap log ----"
  cat "$STAGE/bootstrap.log" >&2
  log "-----------------------"
  exit 3
fi
exit 0
