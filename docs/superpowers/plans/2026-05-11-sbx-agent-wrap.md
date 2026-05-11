# Auto-wrap Agent Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After the Docker Sandboxes mixin kit installs, the agent harness (`claude`, `opencode`, `gemini`, `codex`, `cursor`) launches under `agentsh wrap` via `/usr/local/bin/<agent>` symlink wrappers. Fail-CLOSED: if `agentsh wrap` can't engage cleanly, the wrapper refuses to launch the agent.

**Architecture:** Two new shell scripts ship in every `.deb`/`.rpm`/`.apk` at `/usr/lib/agentsh/`: `agent-wrap` (the wrapper that runs `agentsh wrap -- /usr/bin/<agent>`) and `install-agent-wrappers.sh` (probes `/usr/bin` for known agents and symlinks `/usr/local/bin/<agent> -> /usr/lib/agentsh/agent-wrap`). The kit's `spec.yaml install:` block invokes the installer after `install.sh` finishes. PATH precedence (`/usr/local/bin` before `/usr/bin`) makes the agent kit's `exec claude` resolve to our wrapper.

**Tech Stack:** POSIX shell (no bashisms — Alpine sandboxes use busybox sh), GoReleaser nfpms for packaging, Docker Sandboxes `spec.yaml` schema v1.

**Spec reference:** `docs/superpowers/specs/2026-05-11-sbx-agent-wrap.md`.

---

## Task 1: Wrapper script (`agent-wrap.sh`) + tests

**Files:**
- Create: `packaging/agent-wrap.sh`
- Create: `packaging/agent-wrap_test.sh`

The wrapper is the brain of this feature. It runs per-agent-launch and decides whether to engage `agentsh wrap` or refuse. TDD via a self-contained shell test that stubs the real binary, `agentsh`, and the tier file.

- [ ] **Step 1: Write the failing test**

Create `packaging/agent-wrap_test.sh`:

```bash
#!/usr/bin/env bash
# Smoke test for packaging/agent-wrap.sh. Sets up an isolated tempdir with a
# fake agent binary, fake agentsh, and fake tier file, then drives the wrapper
# through all 5 scenarios.

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

mkdir -p "$tmp/usr/bin" "$tmp/usr/local/bin" "$tmp/agentsh-bin" "$tmp/run/agentsh"

# Fake real agent binary that announces itself.
cat >"$tmp/usr/bin/claude" <<'EOF'
#!/bin/sh
echo "REAL-CLAUDE: $*"
EOF
chmod +x "$tmp/usr/bin/claude"

# Fake agentsh that announces itself when called as `agentsh wrap`.
cat >"$tmp/agentsh-bin/agentsh" <<'EOF'
#!/bin/sh
echo "AGENTSH-WRAP: $*"
EOF
chmod +x "$tmp/agentsh-bin/agentsh"

# Symlink the wrapper as if installed.
ln -s "$wrap" "$tmp/usr/local/bin/claude"

# Helper: run the symlinked wrapper with an overridden FAKE_ROOT (the wrapper
# reads FAKE_ROOT to relocate /usr/bin, /run/agentsh, etc. — see Task 1 Step 3
# for how this hook is wired).
run_wrap() {
    FAKE_ROOT="$tmp" PATH="$tmp/agentsh-bin:$PATH" "$tmp/usr/local/bin/claude" "$@"
}

run_wrap_no_agentsh() {
    # Restrict PATH so `command -v agentsh` fails.
    FAKE_ROOT="$tmp" PATH="/usr/bin:/bin" "$tmp/usr/local/bin/claude" "$@"
}

# Test 1: real binary missing → exit 127
rm "$tmp/usr/bin/claude"
out=$(run_wrap --version 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 127 ]; then
    echo "FAIL: missing-real-binary should exit 127; got rc=$rc out=$out"
    exit 1
fi
# Restore for subsequent tests.
cat >"$tmp/usr/bin/claude" <<'EOF'
#!/bin/sh
echo "REAL-CLAUDE: $*"
EOF
chmod +x "$tmp/usr/bin/claude"
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

# Test 5: everything green → engages wrap with args preserved
echo "shim" >"$tmp/run/agentsh/tier"
out=$(run_wrap --version --foo bar 2>&1)
expected="AGENTSH-WRAP: wrap -- $tmp/usr/bin/claude --version --foo bar"
if [ "$out" != "$expected" ]; then
    echo "FAIL: engage path wrong"
    echo "  want: $expected"
    echo "  got:  $out"
    exit 1
fi
echo "PASS: engages wrap with args"

echo
echo "OK agent-wrap.sh (5/5)"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `chmod +x packaging/agent-wrap_test.sh && ./packaging/agent-wrap_test.sh`
Expected: FAIL with "agent-wrap.sh missing or not executable".

- [ ] **Step 3: Implement the wrapper**

Create `packaging/agent-wrap.sh`:

```sh
#!/bin/sh
# /usr/lib/agentsh/agent-wrap — invoked via symlinks at /usr/local/bin/<agent>.
# Routes the agent through `agentsh wrap`. Fail-CLOSED: any health-check
# failure refuses the launch with a non-zero exit and a stderr message.
#
# This deviates from the parent kit's "never brick the sandbox" posture
# (parent spec §7) because this kit's purpose IS enforcement; running
# unenforced when the operator asked for enforcement is the worse failure.
#
# FAKE_ROOT is a TEST-ONLY hook: when set, /usr/bin and /run/agentsh paths
# are relocated under that root. Production must NOT set FAKE_ROOT.

set -u

# Test hook. Empty in production.
FAKE_ROOT="${FAKE_ROOT:-}"

name=$(basename "$0")
real="${FAKE_ROOT}/usr/bin/$name"
tier_file="${FAKE_ROOT}/run/agentsh/tier"

if [ ! -x "$real" ]; then
    echo "agentsh-agent-wrap: real binary not found at $real" >&2
    exit 127
fi

if ! command -v agentsh >/dev/null 2>&1; then
    echo "agentsh-agent-wrap: agentsh binary missing; refusing to launch $name without enforcement" >&2
    exit 1
fi

tier=$(cat "$tier_file" 2>/dev/null || echo missing)
if [ "$tier" != "shim" ]; then
    echo "agentsh-agent-wrap: enforcement not active (tier='$tier'); refusing to launch $name" >&2
    exit 1
fi

exec agentsh wrap -- "$real" "$@"
```

```bash
chmod +x packaging/agent-wrap.sh
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./packaging/agent-wrap_test.sh`
Expected: PASS — all 5 checks.

- [ ] **Step 5: Run shellcheck**

Run: `shellcheck packaging/agent-wrap.sh packaging/agent-wrap_test.sh`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add packaging/agent-wrap.sh packaging/agent-wrap_test.sh
git commit -m "packaging: agent-wrap.sh — engage \`agentsh wrap\` on launch (fail-closed)"
```

---

## Task 2: Installer script (`install-agent-wrappers.sh`) + tests

**Files:**
- Create: `packaging/install-agent-wrappers.sh`
- Create: `packaging/install-agent-wrappers_test.sh`

The installer runs per-sandbox in the kit's `install` step. It probes for known agents in `/usr/bin` and creates symlinks at `/usr/local/bin/<agent>` to `/usr/lib/agentsh/agent-wrap`. Skips on conflict, idempotent.

- [ ] **Step 1: Write the failing test**

Create `packaging/install-agent-wrappers_test.sh`:

```bash
#!/usr/bin/env bash
# Smoke test for packaging/install-agent-wrappers.sh.
# Drives the installer through 5 scenarios using a FAKE_ROOT.

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
state1=$(ls -la "$tmp/usr/local/bin" | sort)
FAKE_ROOT="$tmp" "$installer" >/dev/null 2>&1
state2=$(ls -la "$tmp/usr/local/bin" | sort)
if [ "$state1" != "$state2" ]; then
    echo "FAIL: not idempotent"
    diff <(echo "$state1") <(echo "$state2") || true
    exit 1
fi
echo "PASS: idempotent"

echo
echo "OK install-agent-wrappers.sh (6/6)"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `chmod +x packaging/install-agent-wrappers_test.sh && ./packaging/install-agent-wrappers_test.sh`
Expected: FAIL with "install-agent-wrappers.sh missing or not executable".

- [ ] **Step 3: Implement the installer**

Create `packaging/install-agent-wrappers.sh`:

```sh
#!/bin/sh
# /usr/lib/agentsh/install-agent-wrappers.sh
# Probe /usr/bin for known agent binaries and create /usr/local/bin/<name>
# symlinks pointing at /usr/lib/agentsh/agent-wrap. Skips when:
#   - the agent binary isn't present (nothing to wrap)
#   - /usr/local/bin/<name> already exists (don't fight the agent kit)
#
# Idempotent. Fail-open if the wrap script itself is missing (warns, exits 0,
# leaves /usr/local/bin untouched).
#
# FAKE_ROOT is a TEST-ONLY hook: when set, all paths are relocated under it.
# Production must NOT set FAKE_ROOT.

set -eu

FAKE_ROOT="${FAKE_ROOT:-}"
WRAP="${FAKE_ROOT}/usr/lib/agentsh/agent-wrap"
DEST="${FAKE_ROOT}/usr/local/bin"
BIN="${FAKE_ROOT}/usr/bin"

# Known agent binaries. Extend this list as Docker Sandboxes adds support.
AGENTS="claude opencode gemini codex cursor"

if [ ! -x "$WRAP" ]; then
    echo "install-agent-wrappers: agent-wrap missing at $WRAP; skipping (kit still works without auto-wrap)" >&2
    exit 0
fi

mkdir -p "$DEST"

for agent in $AGENTS; do
    if [ ! -x "$BIN/$agent" ]; then
        continue
    fi
    target="$DEST/$agent"
    if [ -e "$target" ] || [ -L "$target" ]; then
        echo "install-agent-wrappers: $target exists; not overwriting" >&2
        continue
    fi
    ln -s "$WRAP" "$target"
    echo "install-agent-wrappers: wrapped $agent"
done
```

```bash
chmod +x packaging/install-agent-wrappers.sh
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./packaging/install-agent-wrappers_test.sh`
Expected: PASS — 6/6.

- [ ] **Step 5: Run shellcheck**

Run: `shellcheck packaging/install-agent-wrappers.sh packaging/install-agent-wrappers_test.sh`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add packaging/install-agent-wrappers.sh packaging/install-agent-wrappers_test.sh
git commit -m "packaging: install-agent-wrappers.sh — symlink /usr/local/bin/<agent> on install"
```

---

## Task 3: Package the new scripts via `.goreleaser.yml`

**Files:**
- Modify: `.goreleaser.yml`

Add two `nfpms.contents` entries so `agent-wrap` and `install-agent-wrappers.sh` ship in every .deb/.rpm/.apk.

- [ ] **Step 1: Locate the insertion point**

Read `.goreleaser.yml`. Find the existing `nfpms.contents` entry for `bash_startup.sh`:

```
grep -nE "bash_startup|/usr/lib/agentsh" .goreleaser.yml
```

The new entries go alongside the existing `/usr/lib/agentsh/bash_startup.sh` line.

- [ ] **Step 2: Add the entries**

In `.goreleaser.yml`, find the line containing `- src: packaging/bash_startup.sh` and add immediately after the block ending with that entry's `mode: 0755`:

```yaml
      # Auto-wrap agent harness (paired with the Docker Sandboxes mixin kit).
      - src: packaging/agent-wrap.sh
        dst: /usr/lib/agentsh/agent-wrap
        file_info:
          mode: 0755
      - src: packaging/install-agent-wrappers.sh
        dst: /usr/lib/agentsh/install-agent-wrappers.sh
        file_info:
          mode: 0755
```

- [ ] **Step 3: Validate the config**

Run: `goreleaser check`
Expected: PASS, no warnings.

- [ ] **Step 4: Snapshot-build to confirm packaging**

Run: `goreleaser build --snapshot --clean --single-target --id sbx-bootstrap-linux 2>&1 | tail -10`
Expected: success.

If a full nfpms snapshot build is feasible in the local env (CGO + libseccomp setup), run:
```
goreleaser release --snapshot --clean --skip=publish
```
and confirm a `.deb` contains the two new files:
```
dpkg-deb -c dist/agentsh_*_linux_amd64.deb | grep -E '/usr/lib/agentsh/(agent-wrap|install-agent-wrappers)'
```
Expected: both lines present. If the snapshot build fails for unrelated CGO reasons, `goreleaser check` is the authoritative gate.

- [ ] **Step 5: Commit**

```bash
git add .goreleaser.yml
git commit -m "release: package agent-wrap.sh and install-agent-wrappers.sh"
```

---

## Task 4: Wire the installer into the kit's `spec.yaml`

**Files:**
- Modify: `docker/sbx-kit/spec.yaml`

Add a second `install` command that runs `install-agent-wrappers.sh` after `install.sh` finishes. No `environment.variables` block — the v1 design unconditionally engages wrap.

- [ ] **Step 1: Read the current spec.yaml**

Run: `cat docker/sbx-kit/spec.yaml`. Confirm there is exactly one entry under `commands.install`.

- [ ] **Step 2: Add the second install command**

Edit `docker/sbx-kit/spec.yaml`. Under `commands.install:`, after the existing `curl install.sh | sh` entry, append:

```yaml
    - command: ["/usr/lib/agentsh/install-agent-wrappers.sh"]
      user: "0"
      description: Wrap detected agent binaries via /usr/local/bin/ symlinks
```

The full `commands.install` block should look like:

```yaml
  install:
    - command: "/bin/sh -c 'curl -fsSL https://github.com/erans/agentsh/releases/latest/download/install.sh | sh'"
      user: "0"
      description: Install agentsh from the latest GitHub release
    - command: ["/usr/lib/agentsh/install-agent-wrappers.sh"]
      user: "0"
      description: Wrap detected agent binaries via /usr/local/bin/ symlinks
```

- [ ] **Step 3: Commit**

```bash
git add docker/sbx-kit/spec.yaml
git commit -m "sbx: wire install-agent-wrappers.sh into spec.yaml install step"
```

(The Go structural test that asserts on the new install command lands in Task 6.)

---

## Task 5: Extend E2E test to cover wrapper engagement

**Files:**
- Modify: `docker/sbx-kit/tests/run-e2e.sh`

Add Check 8: after the existing 7 checks pass, install a fake `agentsh` binary that emits a recognizable marker, install a fake `/usr/bin/claude` stub, run the installer to create `/usr/local/bin/claude`, then invoke `claude` from a fresh login shell and assert the wrap marker appears.

- [ ] **Step 1: Modify `docker/sbx-kit/tests/run-e2e.sh`**

Read the file. Find the end of the existing check 7 block (the `user override stub present` check). After that block, BEFORE the `summary:` line, insert:

```bash
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

# Copy the installer into the container (the kit packaging step would
# normally put it at /usr/lib/agentsh, but we ship it from the host so the
# E2E does not depend on a tagged release).
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
```

- [ ] **Step 2: Add the new host-side mounts**

Earlier in `run-e2e.sh`, find the `docker run -d` block. Add two `-v` flags so the host's packaging scripts are reachable inside the container at `/sbx-e2e/agent-wrap` and `/sbx-e2e/install-agent-wrappers`:

```bash
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
```

- [ ] **Step 3: Run the E2E**

Run: `bash docker/sbx-kit/tests/run-e2e.sh`
Expected: `summary: 8 pass, 0 fail` (was 7 pass, now 8).

If check 8 fails on "args dropped," verify the bash login shell actually has `/usr/local/bin` ahead of `/usr/bin` in PATH inside the sandbox-template image. The default Debian-derived templates do. If not, the wrapper may need a more aggressive PATH-precedence mechanism — but that's a separate plan.

- [ ] **Step 4: Commit**

```bash
git add docker/sbx-kit/tests/run-e2e.sh
git commit -m "sbx: extend e2e to verify agent-wrap engagement"
```

---

## Task 6: Update Go structural test for the spec.yaml change

**Files:**
- Modify: `docker/sbx-kit/spec_test.go`

The existing `TestSpecYAML_InstallReferencesInstallScript` asserts exactly ONE install command. With Task 4 there are now two. Rewrite the assertion to require two and check both.

- [ ] **Step 1: Read the current test**

Run: `grep -nA 15 'TestSpecYAML_InstallReferencesInstallScript' docker/sbx-kit/spec_test.go`

- [ ] **Step 2: Update the test**

Replace the body of `TestSpecYAML_InstallReferencesInstallScript` with:

```go
func TestSpecYAML_InstallReferencesInstallScript(t *testing.T) {
	s := loadSpec(t)
	if len(s.Commands.Install) != 2 {
		t.Fatalf("expected exactly two install commands, got %d", len(s.Commands.Install))
	}

	// First entry: curl install.sh | sh
	first := s.Commands.Install[0].Command
	if !strings.Contains(first, "install.sh") {
		t.Errorf("first install command does not curl install.sh: %q", first)
	}
	if s.Commands.Install[0].User != "0" {
		t.Errorf("first install user = %q, want %q (root)", s.Commands.Install[0].User, "0")
	}

	// Second entry: install-agent-wrappers.sh
	second := s.Commands.Install[1].Command
	if !strings.Contains(second, "install-agent-wrappers.sh") {
		t.Errorf("second install command does not invoke install-agent-wrappers.sh: %q", second)
	}
	if s.Commands.Install[1].User != "0" {
		t.Errorf("second install user = %q, want %q (root)", s.Commands.Install[1].User, "0")
	}
}
```

Note: `Command` on the install struct is currently a single `string`. The second install entry uses a YAML list form (`["/usr/lib/agentsh/install-agent-wrappers.sh"]`). YAML unmarshal of a list into `string` will produce a string representation. If the test fails with a parse issue, change the struct to accept either form by using `yaml.Node` or by changing the spec.yaml to use the single-string form:

```yaml
    - command: "/usr/lib/agentsh/install-agent-wrappers.sh"
```

This is uniform with the first entry. Prefer this — change spec.yaml in Task 4 to use the string form too if you haven't already, so the struct shape doesn't need to change.

- [ ] **Step 3: If needed, reconcile the YAML form**

If you used the list form in Task 4, edit `docker/sbx-kit/spec.yaml` to use the string form:

```yaml
    - command: "/usr/lib/agentsh/install-agent-wrappers.sh"
      user: "0"
      description: Wrap detected agent binaries via /usr/local/bin/ symlinks
```

Functionally identical to the list form for Docker Sandboxes; consistent with the first entry; matches the test's `string` expectation.

- [ ] **Step 4: Run the test**

Run: `go test ./docker/sbx-kit/... -run TestSpecYAML_InstallReferencesInstallScript -v -count=1`
Expected: PASS.

- [ ] **Step 5: Run the full sbx-kit + bootstrap suites**

Run: `go test ./docker/sbx-kit/... ./cmd/agentsh-sbx-bootstrap/... -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add docker/sbx-kit/spec_test.go docker/sbx-kit/spec.yaml
git commit -m "sbx: extend spec_test.go to assert the second install command"
```

---

## Task 7: Documentation updates

**Files:**
- Modify: `docker/sbx-kit/README.md`
- Modify: `docs/policy-reference.md`

Document the new behavior in the kit README and add the two new paths to the policy reference table.

- [ ] **Step 1: Update `docker/sbx-kit/README.md`**

Read the current README. Find the section "## v1 enforcement tier" — insert a new "## Behavior: agent harness runs under `agentsh wrap`" section immediately after it (and before "## E2E test (no `sbx` required)"):

```markdown
## Behavior: agent harness runs under `agentsh wrap`

This kit runs the agent harness under `agentsh wrap` whenever it can. After
install, the kit creates symlinks at `/usr/local/bin/<agent>` (for known
agents present in the sandbox) that route launches through `agentsh wrap`,
giving you full exec-pipeline interception of every subprocess the agent
spawns, a coherent session, and a session report on exit.

Wrapped agents (v1): `claude`, `opencode`, `gemini`, `codex`, `cursor`. The
installer skips agents whose binary isn't present in `/usr/bin/` and skips
any entry that already exists in `/usr/local/bin/` (never overwrites
something the agent kit shipped).

### Fail-CLOSED deviation from the parent spec

When the wrapper at `/usr/local/bin/<agent>` runs, it exits non-zero and
refuses to launch the agent if AgentSH cannot engage cleanly: the `agentsh`
binary is missing, `/run/agentsh/tier` does not read `shim`, or the tier
file is missing. Choosing this kit means choosing enforcement-mandatory
semantics; running unenforced is not a supported state.

This deviates from the parent spec's §7 "never bricks the sandbox" stance.
The parent spec governs the kit's *bootstrap*; this section governs the
wrapper's behavior at *agent launch time*.

### Known limitations

- **Absolute-path entrypoints bypass the wrapper.** The mechanism relies on
  `/usr/local/bin` preceding `/usr/bin` in PATH. An agent kit whose
  entrypoint invokes `/usr/bin/claude` directly is unaffected by the
  wrapper. Verify per agent kit before relying on auto-wrap.
- **Install-time failures pass through.** If the kit's `install` command
  itself fails (curl 404, package install error), the wrappers are never
  created and the agent runs unwrapped. sbx run should report this
  failure visibly.
```

- [ ] **Step 2: Update `docs/policy-reference.md`**

Read the existing "Where things live" table. Append two rows (preserving the table's pipe-style format):

```markdown
| `/usr/lib/agentsh/agent-wrap` | OS package, read-only | Shared wrapper script for agent binaries |
| `/usr/local/bin/<agent>` | Kit install step | Symlink to agent-wrap (created per detected agent) |
```

These rows go at the end of the existing table.

- [ ] **Step 3: Verify both docs render**

Run: `wc -l docker/sbx-kit/README.md docs/policy-reference.md`
Expected: both files exist with non-zero line counts; visually scan the diff to confirm the additions land in the right place.

- [ ] **Step 4: Commit**

```bash
git add docker/sbx-kit/README.md docs/policy-reference.md
git commit -m "docs: document agent-wrap behavior + fail-closed deviation"
```

---

## Self-Review

**Spec coverage** against `docs/superpowers/specs/2026-05-11-sbx-agent-wrap.md`:

- §1 Goal — Tasks 1+2+4 (wrapper + installer + spec.yaml wiring) plus Task 5 (e2e proves end-to-end). ✓
- §2 Constraint reminder — informational, embodied in Task 5's reliance on PATH precedence (`bash -lc`). ✓
- §3 Non-goals — no env var anywhere in any task. ✓
- §4 Fail-closed table — Task 1 step 3's wrapper script implements all four rows. ✓
- §5 Components — Tasks 1, 2 (scripts), Task 3 (packaging), Task 4 (spec.yaml), Task 5 (e2e). ✓
- §6 Wrapper — Task 1. ✓
- §7 Installer — Task 2. ✓
- §8 Kit integration — Task 4. ✓
- §9 Testing — Task 1 (5 wrapper tests), Task 2 (6 installer tests — one more than spec said because idempotent was a separate case worth covering), Task 5 (e2e check 8), Task 6 (Go structural test update). ✓
- §10 Documentation — Task 7. ✓
- §11 Risk register — informational; risks are mitigated through the e2e check and the explicit fail-closed posture documented in Task 7. ✓
- §12 Out of scope — preserved by absence; no tasks for LD_PRELOAD/ptrace/etc. ✓

**Placeholder scan:** no `TBD`/`TODO`/"fill in" in any task. Each step has either runnable code, a runnable command, or an exact file edit.

**Type consistency:**
- `FAKE_ROOT` env var: used in Task 1 (wrapper) and Task 2 (installer), same semantics. ✓
- Agent list `claude opencode gemini codex cursor`: Task 2 installer, Task 5 e2e references just `claude`, Task 7 docs list all five. ✓
- `/usr/lib/agentsh/agent-wrap` path: Tasks 1/2/3/7 all reference it consistently. ✓
- `/run/agentsh/tier` path + value `"shim"`: wrapper script (Task 1) and e2e (Task 5) both check for the same string. ✓
- `agentsh wrap --` invocation: wrapper exec'd command (Task 1) matches the marker the e2e asserts (Task 5). ✓

No gaps found. Plan is ready.
