# Auto-wrapping the agent harness via `agentsh wrap` — design

**Date:** 2026-05-11
**Status:** Revised after real-agent-kit probe revealed PATH precedence design flaw
**Owner:** Eran Sandler
**Parent spec:** `2026-05-11-docker-sandboxes-mixin-kit-design.md`

## 0. Revision history

- **v1 (original):** PATH precedence — drop wrapper at `/usr/local/bin/<agent>`, rely on it preceding the real binary in PATH.
- **v2 (this version, after probing `docker/sandbox-templates:{opencode,codex,gemini}`):** real agent kits install their binaries via npm at `/usr/local/share/npm-global/bin/<agent>`, which **precedes** `/usr/local/bin` in PATH. The v1 wrapper would never have fired against any real agent kit. Switched to **move-aside-and-replace** at the discovered binary location.

## 1. Goal

After the AgentSH mixin kit installs, the sandbox's agent binary (`claude`, `opencode`, `gemini`, `codex`, `cursor`) is launched as a child of `agentsh wrap`. The harness — not just its tools — runs under AgentSH's full exec-pipeline interception (session, policy, audit, report).

## 2. Constraint reminder

A `kind: mixin` kit cannot override the agent kit's entrypoint. The mixin can only modify the filesystem post-install. To intercept the agent's exec without entrypoint cooperation, the wrapper must occupy *the exact path the agent kit's entrypoint already resolves to* — not a path that happens to come earlier in PATH.

The probe results (`docker run --rm docker/sandbox-templates:opencode bash -lc 'type -a opencode'`) show:

```
opencode is /usr/local/share/npm-global/bin/opencode
PATH=/home/agent/.local/bin:/usr/local/share/npm-global/bin:/usr/local/sbin:/usr/local/bin:...
```

`/usr/local/bin` is 4th in PATH; npm-global is 2nd. A wrapper at `/usr/local/bin/opencode` would be shadowed. The move-aside design avoids this entirely by relocating the agent binary in place.

## 3. Non-goals

- **No env-var opt-in.** Auto-wrap is the kit's purpose.
- **No SKILL.md manual-wrap guidance.** Harness is already wrapped; the LLM doesn't need to invoke wrap explicitly.
- **No "do not touch the agent kit's installed files" guarantee.** The move-aside approach explicitly renames the binary the agent kit shipped. This is the trade-off for actually engaging the wrap.

## 4. Failure posture: fail-CLOSED (unchanged from v1)

| Failure | Disposition |
|---|---|
| `${0}.real` missing | exit 127 + stderr — installer didn't run or someone deleted the moved-aside binary |
| `agentsh` binary missing | exit 1 + stderr |
| `/run/agentsh/tier` ≠ `shim` | exit 1 + stderr |
| `agentsh wrap` itself fails after exec | agent launch fails |

## 5. Components (unchanged from v1)

```
packaging/
  agent-wrap.sh                       # the wrapper script (real path now derived from ${0}.real)
  agent-wrap_test.sh                  # shell test of the wrapper
  install-agent-wrappers.sh           # discover-via-command-v + move-aside + symlink
  install-agent-wrappers_test.sh      # shell test of the installer

docker/sbx-kit/
  spec.yaml                           # (unchanged) second install command
  tests/run-e2e.sh                    # gains a real-agent-kit check using opencode

.goreleaser.yml                       # (unchanged) packages the two scripts
```

## 6. The wrapper (`/usr/lib/agentsh/agent-wrap`)

```sh
#!/bin/sh
# Invoked via symlinks placed by install-agent-wrappers.sh at the original
# location of each agent binary (e.g. /usr/local/share/npm-global/bin/opencode).
# Real binary lives at the same path with a .real suffix.
#
# Fail-CLOSED: any health-check failure refuses launch.

set -u

# Gated test hook (parallel of v1 design).
if [ "${AGENTSH_TEST:-}" = "1" ]; then
    FAKE_ROOT="${FAKE_ROOT:-}"
else
    FAKE_ROOT=""
fi

real="${0}.real"
tier_file="${FAKE_ROOT}/run/agentsh/tier"

if [ ! -x "$real" ]; then
    echo "agentsh-agent-wrap: real binary not found at $real; refusing to launch $(basename "$0")" >&2
    exit 127
fi

# command -v also reports shell functions; exec below dispatches to binaries
# only, so a function-named agentsh fails non-zero — still fail-closed.
if ! command -v agentsh >/dev/null 2>&1; then
    echo "agentsh-agent-wrap: agentsh binary missing; refusing to launch $(basename "$0") without enforcement" >&2
    exit 1
fi

tier=$(cat "$tier_file" 2>/dev/null || echo missing)
if [ "$tier" != "shim" ]; then
    echo "agentsh-agent-wrap: enforcement not active (tier='$tier'); refusing to launch $(basename "$0")" >&2
    exit 1
fi

exec agentsh wrap -- "$real" "$@"
```

Key change from v1: `real="${0}.real"` instead of `real="${FAKE_ROOT}/usr/bin/$name"`. The wrapper is now location-flexible — it works wherever the installer placed it.

## 7. The installer (`/usr/lib/agentsh/install-agent-wrappers.sh`)

Discovers each known agent via `command -v`, renames it to `<path>.real`, drops a symlink to the wrap script at the original location.

```sh
#!/bin/sh
# Discover known agent binaries via `command -v`, move them aside to a
# `.real` sibling, and put a symlink to /usr/lib/agentsh/agent-wrap in
# the original location. The agent kit's entrypoint, which resolves the
# agent via PATH lookup, then hits our symlink wherever the binary lived.
#
# Idempotent. Fail-open if the wrap script itself is missing.

set -eu

if [ "${AGENTSH_TEST:-}" = "1" ]; then
    FAKE_ROOT="${FAKE_ROOT:-}"
    PATH="${FAKE_TEST_PATH:-$PATH}"   # test can override the search path
else
    FAKE_ROOT=""
fi

WRAP="${FAKE_ROOT}/usr/lib/agentsh/agent-wrap"

# Known agent binaries. Extend as Docker Sandboxes adds support.
AGENTS="claude opencode gemini codex cursor"

if [ ! -x "$WRAP" ]; then
    echo "install-agent-wrappers: agent-wrap missing at $WRAP; skipping (kit still works without auto-wrap)" >&2
    exit 0
fi

for agent in $AGENTS; do
    # Discover via PATH lookup, matching how the agent kit's entrypoint
    # would resolve the binary.
    real=$(command -v "$agent" 2>/dev/null || true)
    if [ -z "$real" ] || [ ! -x "$real" ]; then
        continue  # agent not installed
    fi

    # Idempotency: if $real is already our symlink AND $real.real exists,
    # the agent is already wrapped — silent skip.
    if [ -L "$real" ] && [ "$(readlink "$real")" = "$WRAP" ] && [ -e "${real}.real" ]; then
        continue
    fi

    # Conflict detection: if $real.real already exists but $real is NOT
    # our symlink, something else owns the location — don't touch it.
    if [ -e "${real}.real" ]; then
        echo "install-agent-wrappers: ${real}.real already exists but $real is not our symlink; not overwriting" >&2
        continue
    fi

    # Move-aside-and-replace.
    mv "$real" "${real}.real"
    ln -s "$WRAP" "$real"
    echo "install-agent-wrappers: wrapped $agent at $real (real moved to ${real}.real)" >&2
done
```

**Why `command -v` instead of probing `/usr/bin/<agent>` like v1?** Because real agent kits don't put their binaries in `/usr/bin`. `command -v` is the same PATH-search the agent kit's entrypoint uses, so we find the binary wherever it actually lives. This is the load-bearing fix.

## 8. Kit integration (unchanged from v1)

Same two install commands in `spec.yaml`:

```yaml
commands:
  install:
    - command: "/bin/sh -c 'curl -fsSL https://github.com/erans/agentsh/releases/latest/download/install.sh | sh'"
      user: "0"
      description: Install agentsh from the latest GitHub release
    - command: "/usr/lib/agentsh/install-agent-wrappers.sh"
      user: "0"
      description: Move-aside-and-replace detected agent binaries with /usr/lib/agentsh/agent-wrap
```

## 9. Testing

**Wrapper script** (5 cases in `packaging/agent-wrap_test.sh`):
1. `${0}.real` missing → exit 127.
2. `agentsh` missing from PATH → exit 1.
3. Tier file says `none` → exit 1.
4. Tier file missing entirely → exit 1.
5. All three green → exec'd `agentsh wrap -- ${0}.real <args>` with args preserved.

Test setup: place a fake binary at `<symlink>.real`, place a symlink to the wrapper at `<symlink>`, invoke via the symlink. Tests no longer reference `/usr/bin`.

**Installer** (6 cases in `packaging/install-agent-wrappers_test.sh`):
1. No agents on PATH → no actions taken.
2. One agent on PATH → moved to `.real` + symlink created at original location.
3. Multiple agents → all wrapped at their respective discovered locations.
4. Pre-existing `<path>.real` but `$path` is NOT our symlink → skipped with warning (foreign conflict).
5. Missing wrap script → exit 0 with warning, no moves.
6. Idempotent: re-run on already-wrapped tree → silent, no double-rename.

Test setup uses `AGENTSH_TEST=1 FAKE_TEST_PATH=<tempdir-bin>` to scope the `command -v` search to a controlled location.

**E2E** (`docker/sbx-kit/tests/run-e2e.sh`): the existing check 8 (stub-based engagement check) is **replaced** with a real-agent-kit check:

- Pull `docker/sandbox-templates:opencode` (publicly available; verified).
- Build the real `agentsh` binary on the host (CGO + libseccomp, same as `go build` in this worktree).
- Side-load the binaries, the wrap script, and the installer into the opencode container.
- Run the installer; verify `/usr/local/share/npm-global/bin/opencode` is now a symlink to `/usr/lib/agentsh/agent-wrap` and `opencode.real` exists.
- Bring up the daemon (or stub the wrap session-creation endpoint, per E2E-tractability).
- Invoke `opencode --help` from a login shell as the agent user. Assert `agentsh wrap` engaged AND opencode's real `--help` output appears (proving the move-aside binary still executes correctly).

This is the real-agent E2E the v1 design never produced — the bug that prompted this revision would have been caught at this step.

## 10. Documentation

**`docker/sbx-kit/README.md`** "Behavior" section needs revision:
- Drop "PATH precedence" language.
- Describe the move-aside-and-replace mechanism.
- Update the "Known limitations" — remove the absolute-path-entrypoint caveat (move-aside doesn't depend on PATH order) but ADD: "the installer renames files the agent kit shipped; uninstalling cleanly requires restoring `<path>.real` → `<path>`."

**`docs/policy-reference.md`** table additions are mostly fine but the `/usr/local/bin/<agent>` row needs to become `<original agent path>` since the location varies per agent kit.

## 11. Risk register (revised)

- **Move-aside collides with agent kit upgrades.** If the agent kit's image is rebuilt with a new agent binary at the same path, our move-aside would have already happened and the new binary would land *next to* our symlink, not under it. v1 mitigation: idempotency check detects "already wrapped" and skips. v2 mitigation: image rebuild is image-rebuild — a fresh sandbox triggers a fresh install which catches the new binary.
- **Uninstall path is non-trivial.** Removing the kit no longer just removes a symlink — it needs to restore `<path>.real` → `<path>`. Out of scope for v1; document the manual recovery in the README.
- **Real `agentsh wrap` compatibility with opencode/codex/gemini.** Still untested against real agents until E2E lands. The new E2E directly exercises this.
- **CGO+libseccomp build complexity for the E2E.** The dev host has the deps; CI runners typically have `libseccomp-dev` available via apt. If the E2E build is too brittle, fall back to building agentsh in a Docker build stage.

## 12. Out of scope (unchanged)

- LD_PRELOAD / ptrace tiers.
- Wrapping subprocess binaries (already handled by the shim list).
- Clean uninstall logic.
- Detecting agent-kit image upgrades that swap the wrapped binary.
