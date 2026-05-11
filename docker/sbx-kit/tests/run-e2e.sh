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
SKIP=0

log()    { printf '%s\n' "$*"; }
pass()   { printf 'PASS: %s\n' "$*"; PASS=$((PASS + 1)); }
fail()   { printf 'FAIL: %s\n' "$*" >&2; FAIL=$((FAIL + 1)); }
skip()   { printf 'SKIP: %s\n' "$*"; SKIP=$((SKIP + 1)); }

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  # Remove any per-agent containers from Section 8 (best-effort).
  docker ps -aq --filter "name=agentsh-sbx-e2e-" 2>/dev/null \
    | xargs -r docker rm -f >/dev/null 2>&1 || true
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
# 8. Real-agent wrapper engagement check against docker/sandbox-templates:*.
#
#    This replaces the stub-based check that faked both agentsh and the agent.
#    The v1 design bug: the installer used `command -v <agent>` from a login
#    shell, which resolves to /usr/local/share/npm-global/bin/<agent> (that
#    directory appears before /usr/local/bin in every npm-shipped template's
#    PATH). This test pins the expected path and asserts the move-aside layout
#    matches the real image — for each publicly available agent template we
#    can pull.
#
#    We use a stub agentsh (not a real CGO+libseccomp build) because the
#    wrap-engagement assertion is purely structural: we only need to confirm
#    the wrapper invokes `agentsh wrap -- <real-path> <args>` and that the
#    real agent binary still runs (stub execs through). No enforcement kernel
#    machinery is exercised here, so libseccomp-dev is not required, keeping
#    this check CI-friendly.
# ---------------------------------------------------------------------------

log
log "Section 8: real-agent wrapper engagement (per-agent template):"

# Shared stub agentsh used by every agent run.
cat >"$STAGE/bin/agentsh-stub" <<'STUB'
#!/bin/sh
# E2E stub: record invocation and exec through to the real binary.
echo "AGENTSH-MARKER: $*" >&2
# Strip "wrap --" prefix: the real binary is the third positional arg.
shift  # past "wrap"
shift  # past "--"
exec "$@"
STUB
chmod +x "$STAGE/bin/agentsh-stub"

# Per-agent check. Args: $1=image tag (suffix on docker/sandbox-templates:),
# $2=agent CLI name (the binary name `command -v` should find).
#
# Asserts that for this image:
#   - The agent resolves to /usr/local/share/npm-global/bin/<name>.
#   - The installer's symlink lands there and points at agent-wrap.
#   - <name>.real exists as the moved-aside binary.
#   - Invoking `<name> --version` through a login shell engages the wrap
#     chain (AGENTSH-MARKER on stderr) and produces non-empty real output
#     (proving the moved-aside binary still executes via the stub).
check_real_agent() {
  local image_tag="$1"
  local agent="$2"
  local image="docker/sandbox-templates:${image_tag}"
  local container="agentsh-sbx-e2e-${image_tag}-$$"
  local label="${agent}@${image_tag}"
  local expected_path="/usr/local/share/npm-global/bin/${agent}"

  log
  log "  ${label}:"

  if ! docker pull "$image" >/dev/null 2>&1; then
    skip "${label}: image pull failed — skipping (no network/hub access)"
    return 0
  fi

  docker run -d --name "$container" --user 0 "$image" sleep 600 >/dev/null

  local in_c="docker exec --user 0 $container /bin/bash -c"

  # Side-load: stub agentsh, real agent-wrap, real installer.
  docker cp "$STAGE/bin/agentsh-stub" "$container:/usr/bin/agentsh"
  $in_c 'mkdir -p /usr/lib/agentsh'
  docker cp "$REPO/packaging/agent-wrap.sh" "$container:/usr/lib/agentsh/agent-wrap"
  docker cp "$REPO/packaging/install-agent-wrappers.sh" "$container:/usr/lib/agentsh/install-agent-wrappers.sh"
  $in_c 'chmod +x /usr/bin/agentsh /usr/lib/agentsh/agent-wrap /usr/lib/agentsh/install-agent-wrappers.sh'

  # Tier file (wrapper requires /run/agentsh/tier = shim).
  $in_c 'mkdir -p /run/agentsh && echo shim > /run/agentsh/tier'

  # Run the installer from root login shell so it sees the production PATH.
  $in_c 'bash -lc /usr/lib/agentsh/install-agent-wrappers.sh' \
    2>"$STAGE/${image_tag}-install.log" || true

  # Discover the agent's path (must match the npm-global location).
  local agent_path
  agent_path=$($in_c "bash -lc 'command -v ${agent} 2>/dev/null || echo MISSING'" || echo MISSING)
  local agent_real="${agent_path}.real"

  # Check N.1: discovered path is the expected npm-global location.
  if [ "$agent_path" = "$expected_path" ]; then
    pass "${label}: discovered at expected npm-global path ($agent_path)"
  else
    fail "${label}: path is '$agent_path' (want $expected_path) — layout may have changed"
  fi

  # Check N.2: discovered path is a symlink to agent-wrap.
  local link_target
  link_target=$($in_c "readlink '$agent_path' 2>/dev/null || echo NOTLINK" || echo NOTLINK)
  if [ "$link_target" = "/usr/lib/agentsh/agent-wrap" ]; then
    pass "${label}: symlink points to /usr/lib/agentsh/agent-wrap"
  else
    fail "${label}: not a symlink to agent-wrap (readlink='$link_target')"
    log  "----- installer log -----"
    cat "$STAGE/${image_tag}-install.log"
    log  "-------------------------"
  fi

  # Check N.3: .real sibling exists and is executable.
  if $in_c "test -x '$agent_real'" 2>/dev/null; then
    pass "${label}: .real sibling exists and is executable ($agent_real)"
  else
    fail "${label}: .real sibling missing or not executable ($agent_real)"
  fi

  # Check N.4: invoking the agent through a login shell engages the wrap.
  local stdout stderr
  stdout=$(docker exec --user agent "$container" bash -lc "${agent} --version 2>/dev/null" 2>/dev/null || true)
  stderr=$(docker exec --user agent "$container" bash -lc "${agent} --version 2>&1 >/dev/null" 2>/dev/null || true)

  local expected_marker="AGENTSH-MARKER: wrap -- ${agent_real} --version"
  if printf '%s' "$stderr" | grep -qF "$expected_marker"; then
    pass "${label}: AGENTSH-MARKER present (wrap chain fired with correct argv)"
  else
    fail "${label}: AGENTSH-MARKER not found (want: '$expected_marker')"
    log  "----- ${label} stderr -----"
    printf '%s\n' "$stderr"
    log  "---------------------------"
  fi

  # Check N.5: stdout is non-empty and does not contain the marker
  # (the real binary executed via the stub's exec).
  if [ -n "$stdout" ] && ! printf '%s' "$stdout" | grep -q 'AGENTSH-MARKER'; then
    pass "${label}: --version produced real output (real binary ran through stub)"
  else
    fail "${label}: --version stdout empty or contains marker"
    log  "----- ${label} stdout -----"
    printf '%s\n' "$stdout"
    log  "---------------------------"
  fi

  docker rm -f "$container" >/dev/null 2>&1 || true
}

# Run against every agent template we can pull. Templates we know are public
# at the time of writing: opencode, gemini, codex. (claude template isn't
# published.) Any agent whose image pulls succeeds gets fully verified;
# others SKIP without failing the suite.
check_real_agent opencode opencode
check_real_agent gemini   gemini
check_real_agent codex    codex

# ---------------------------------------------------------------------------
# 9. Summary
# ---------------------------------------------------------------------------

log
log "summary: $PASS pass, $FAIL fail, $SKIP skip"
if [ "$FAIL" -gt 0 ]; then
  log
  log "---- bootstrap log ----"
  cat "$STAGE/bootstrap.log" >&2
  log "-----------------------"
  exit 3
fi
exit 0
