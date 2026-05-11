# Auto-wrapping the agent harness via `agentsh wrap` — design

**Date:** 2026-05-11
**Status:** Draft, awaiting review
**Owner:** Eran Sandler
**Parent spec:** `2026-05-11-docker-sandboxes-mixin-kit-design.md`

## 1. Goal

After the AgentSH mixin kit installs, the sandbox's agent binary (`claude`, `opencode`, `gemini`, `codex`, `cursor`) is launched as a child of `agentsh wrap`. The harness — not just its tools — runs under AgentSH's full exec-pipeline interception (session, policy, audit, report).

The kit's value proposition stops being "AgentSH is installed alongside the agent" and becomes "AgentSH owns the agent's lifecycle from `claude --help` outwards."

## 2. Constraint reminder

A `kind: mixin` kit **cannot** override the agent kit's entrypoint — that field belongs to the `kind: agent` kit (claude, opencode, etc.). We can't tell sbx "launch the agent as `agentsh wrap -- claude`." The only tool a mixin has is PATH precedence: drop a wrapper at `/usr/local/bin/claude` (which precedes `/usr/bin/claude` in PATH) and rely on the agent kit's entrypoint using PATH lookup rather than an absolute path.

This is an unavoidable structural limitation. If a future agent kit launches its binary via absolute path, the wrapper is bypassed and this design's coverage drops to zero for that kit.

## 3. Non-goals

- **No env-var opt-in.** Earlier drafts gated this on `AGENTSH_WRAP_AGENT=1`; the v1 design unconditionally engages wrap. The kit's purpose is enforcement; an opt-out flag implies the unenforced path is supported, which it is not.
- **No manual `agentsh wrap` SKILL guidance.** The harness is already wrapped; instructing the LLM to manually invoke wrap on individual commands would be redundant.
- **No fix for absolute-path entrypoints.** Documented as a known limitation. Per-agent-kit verification is the operator's responsibility.

## 4. Failure posture: fail-CLOSED (explicit deviation from parent spec §7)

The parent spec promises "fail-open with loud logging — never bricks a user's sandbox." This design **deviates** for runtime failures: if `agentsh wrap` cannot engage cleanly when the wrapper runs, the wrapper refuses to launch the agent.

| Failure | Disposition |
|---|---|
| `/usr/bin/<agent>` missing | exit 127 + stderr — there's nothing to wrap; sandbox is misconfigured. |
| `agentsh` binary missing | exit 1 + stderr — kit installed wrappers but not AgentSH; broken install. |
| `/run/agentsh/tier` ≠ `shim` | exit 1 + stderr — bootstrap didn't complete or daemon never came up. |
| `agentsh wrap` itself fails after exec | agent launch fails (cannot fork-monitor around exec). |

**Justification for the deviation:** the kit's contract has shifted. Under the parent spec, the kit guaranteed "the agent runs; AgentSH may or may not enforce." Under this design, the kit guarantees "the agent runs *and* is enforced, or it doesn't run." Operators choosing this kit choose enforcement-mandatory semantics. Running unenforced when the operator asked for enforcement is the worse failure mode.

**One layer the design cannot close:** if the kit's `install` command itself fails (curl 404, package install error), the wrappers are never created and `exec claude` resolves to the unwrapped `/usr/bin/claude`. That's pass-through despite the fail-closed intent — but at that point sbx run will have reported the install-phase error visibly, so the operator can react.

## 5. Components

```
packaging/
  agent-wrap.sh                       # the wrapper script (shipped in /usr/lib/agentsh/)
  agent-wrap_test.sh                  # shell test of the wrapper
  install-agent-wrappers.sh           # symlink-creating installer (shipped in /usr/lib/agentsh/)
  install-agent-wrappers_test.sh      # shell test of the installer

docker/sbx-kit/
  spec.yaml                           # +1 install command line
  tests/run-e2e.sh                    # +1 verification check

.goreleaser.yml                       # +2 nfpms contents entries
```

The wrapper and installer ship in every `.deb`/`.rpm`/`.apk` so they're available wherever `install.sh` lands the kit. Symlink creation happens **per-sandbox**, in the kit's `install` step, because the set of agent binaries varies between sandbox templates.

## 6. The wrapper (`/usr/lib/agentsh/agent-wrap`)

```sh
#!/bin/sh
# Symlinked from /usr/local/bin/<agent>. Routes the agent through
# `agentsh wrap`. Fail-closed.

set -u
name=$(basename "$0")
real="/usr/bin/$name"

if [ ! -x "$real" ]; then
    echo "agentsh-agent-wrap: real binary not found at $real" >&2
    exit 127
fi

if ! command -v agentsh >/dev/null 2>&1; then
    echo "agentsh-agent-wrap: agentsh binary missing; refusing to launch $name without enforcement" >&2
    exit 1
fi

tier=$(cat /run/agentsh/tier 2>/dev/null || echo missing)
if [ "$tier" != "shim" ]; then
    echo "agentsh-agent-wrap: enforcement not active (tier='$tier'); refusing to launch $name" >&2
    exit 1
fi

exec /usr/bin/agentsh wrap -- "$real" "$@"
```

## 7. The installer (`/usr/lib/agentsh/install-agent-wrappers.sh`)

Idempotent. Probes `/usr/bin` for the known agent set, creates `/usr/local/bin/<agent>` symlinks to `/usr/lib/agentsh/agent-wrap`. Skips when:
- The agent binary is absent (no agent to wrap).
- An entry already exists at the destination (don't fight the agent kit).

Known agent list (v1): `claude`, `opencode`, `gemini`, `codex`, `cursor`. Adding a new agent is a one-line list edit.

## 8. Kit integration (`docker/sbx-kit/spec.yaml`)

The kit's `commands.install` gains one entry, run after `install.sh`:

```yaml
commands:
  install:
    - command: "/bin/sh -c 'curl -fsSL https://github.com/erans/agentsh/releases/latest/download/install.sh | sh'"
      user: "0"
      description: Install agentsh from the latest GitHub release
    - command: ["/usr/lib/agentsh/install-agent-wrappers.sh"]
      user: "0"
      description: Wrap detected agent binaries via /usr/local/bin/ symlinks
```

No `environment.variables` block (the env-var design was dropped).

## 9. Testing

**Wrapper script** (5 cases in `packaging/agent-wrap_test.sh`):
1. Real binary missing → exit 127.
2. `agentsh` missing from PATH → exit 1.
3. Tier file says `none` → exit 1.
4. Tier file missing entirely → exit 1.
5. All three green → exec'd `agentsh wrap -- /usr/bin/<agent> <args>` with args preserved.

**Installer** (5 cases in `packaging/install-agent-wrappers_test.sh`):
1. No agents in `/usr/bin` → no symlinks.
2. One agent → one symlink.
3. Multiple agents → all wrapped.
4. Pre-existing entry at `/usr/local/bin/<agent>` (file or symlink) → skipped, stderr warning, no overwrite.
5. Re-run on a populated tree → no-op (idempotent).

**E2E** (`docker/sbx-kit/tests/run-e2e.sh`): one new check appended after the existing 7 (becomes 8 total). The check installs a fake `agentsh` binary that prints a recognizable marker, drops a fake `/usr/bin/claude` stub, runs the installer to create `/usr/local/bin/claude`, then invokes `claude --version` from a fresh login shell and asserts the wrap-marker appears in the output. This proves the PATH precedence + wrapper + wrap-exec chain works end-to-end in a real sandbox-template container.

## 10. Documentation

**`docker/sbx-kit/README.md`** — a new "Behavior" section after "v1 enforcement tier":

> This kit runs the agent harness under `agentsh wrap` whenever it can. After install, the kit creates symlinks at `/usr/local/bin/<agent>` (for known agents present in the sandbox) that route launches through `agentsh wrap`, giving you full exec-pipeline interception of every subprocess the agent spawns, a coherent session, and a session report on exit.
>
> **Fail-closed deviation from the parent spec:** when `agentsh wrap` cannot engage cleanly (AgentSH missing, bootstrap incomplete, tier != shim), the wrapper exits non-zero and refuses to launch the agent. Choosing this kit means choosing enforcement-mandatory semantics; running unenforced is not a supported state.
>
> **Limitations:** the wrappers rely on PATH precedence. An agent kit whose entrypoint launches its binary via absolute path bypasses them. Verify per agent kit.

**`docs/policy-reference.md`** — append two rows to the "Where things live" table:

| `/usr/lib/agentsh/agent-wrap` | OS package, read-only | Shared wrapper for agent binaries |
| `/usr/local/bin/<agent>` | Kit install step | Symlink to agent-wrap (one per detected agent) |

No SKILL.md changes — the existing skill stays as-is.

## 11. Risk register

- **PATH-precedence assumption.** If `claude`/`opencode`/`gemini` agent kits launch via absolute path, this design has zero effect for those kits. Mitigation: e2e check exercises PATH-lookup behavior; per-agent-kit manual verification before tagging the kit's release.
- **`agentsh wrap` compatibility with long-lived agents.** `wrap` was designed for typical agent runs but its session-lifecycle behavior with a multi-hour interactive agent is untested. Mitigation: e2e is a smoke; the actual matrix lives in `coding-agent-smoke.sh` and runs against a real `sbx run` once a release is tagged.
- **Fail-closed brittleness.** A flaky bootstrap (e.g., daemon crash mid-startup) leaves tier=none, refusing the agent. Operators must rely on AgentSH's startup being reliable. Mitigation: the bootstrap's daemon-spawn already retries; ongoing reliability is owned by AgentSH's release quality.
- **Agent-kit-installed `/usr/local/bin/<agent>` conflict.** If an agent kit ships its own wrapper at `/usr/local/bin/claude`, the installer skips and the agent runs unwrapped. Mitigation: skip-and-log is the deliberate choice; alternative would be aggressive overwriting, which breaks the agent kit. Operators in this case need to manually merge.

## 12. Out of scope

- LD_PRELOAD / ptrace tiers (parked per parent spec §13).
- Wrapping commands that aren't agent binaries (subprocesses are already handled by the shim list under `/usr/lib/agentsh/shims/`).
- Absolute-path-entrypoint workarounds.
- A pre-flight check that warns if a specific agent kit is known to use absolute paths.
