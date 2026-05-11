# AgentSH mixin kit for Docker Sandboxes

This is a [Docker Sandboxes mixin kit](https://docs.docker.com/ai/sandboxes/customize/kits/)
that installs [AgentSH](https://github.com/erans/agentsh) into any sandbox at
creation and routes the agent's command-level activity through a
coding-agent-tuned policy.

## Use

```
sbx run <agent> --kit git+https://github.com/erans/agentsh.git#dir=docker/sbx-kit
```

Works with `claude`, `opencode`, `gemini`, and any agent kit derived from
`docker/sandbox-templates:shell-docker`.

## Verify

```
sbx exec <session> cat /run/agentsh/tier              # expect: shim
sbx exec <session> cat /etc/agentsh/policies/default.yaml
sbx exec <session> pgrep -af 'agentsh server'
```

For a deeper smoke test, run `tests/coding-agent-smoke.sh` inside the
sandbox.

## OpenCode / Gemini setup

Claude Code auto-discovers `.claude/skills/agentsh/SKILL.md`. For other
agents, copy the SKILL into your agent's discovery path:

```
sbx exec <session> cp /workspace/.claude/skills/agentsh/SKILL.md /workspace/AGENTS.md
```

(Or symlink, or merge with your own `AGENTS.md` — whatever fits your flow.)

## Logs

| File | Purpose |
|---|---|
| `/var/log/agentsh/bootstrap.log` | Startup banner, policy-merge result, tier-probe result |
| `/var/log/agentsh/daemon.log`    | Daemon stdout+stderr |

## v1 enforcement tier

v1 ships shim-tier interception only: subprocess execs of common commands
are routed through AgentSH's shim binary. LD_PRELOAD and ptrace tiers are
planned (see the spec under
`docs/superpowers/specs/2026-05-11-docker-sandboxes-mixin-kit-design.md`).

## E2E test (no `sbx` required)

`tests/run-e2e.sh` (or `make sbx-e2e` from the repo root) exercises the kit's
mechanics against the public `docker/sandbox-templates:shell-docker` image —
no Docker Sandboxes install needed. It:

1. Builds `agentsh-shell-shim` and `agentsh-sbx-bootstrap` on the host (CGO off).
2. Starts a container from the sandbox template.
3. Lays down the same payload `sbx run --kit` would (binaries, policy template,
   `/usr/lib/agentsh/shims/*` symlinks, `/etc/profile.d/agentsh.sh`,
   `/etc/environment.d/10-agentsh.conf`, the kit's `files/` tree, plus a user
   override fragment crafted to exercise both replace-by-name and append).
4. Runs `/usr/bin/agentsh-sbx-bootstrap`.
5. Verifies: `/run/agentsh/tier == shim`; `command -v curl` resolves under
   `/usr/lib/agentsh/shims/`; `/etc/agentsh/policies/default.yaml` is the
   merged policy (baked rule present; appended override rule present;
   replace-by-name overlay paths win); SKILL.md and override stub landed.

What it does **not** verify (still gated on a real `sbx run` against a
tagged release):

- The `install` step actually downloading `install.sh` and the matching
  `.deb`/`.rpm`/`.apk` from the GitHub release.
- In-sandbox enforcement (deny / audit / soft_delete) — that needs the
  `agentsh server` running, which depends on libseccomp; out of scope for
  v1 E2E. Run `tests/coding-agent-smoke.sh` inside a real sandbox for that.
- That the agent kit's actual entrypoint inherits the shim PATH.

## Override the policy

Write a partial YAML policy to `/home/agent/.agentsh/policy.yaml` inside the
sandbox. See `/usr/share/doc/agentsh/policy-reference.md` for the grammar.
Restart the sandbox to apply.

## Note on smoke test permissions

If `tests/coding-agent-smoke.sh` loses its executable bit post-checkout (git
may not preserve file modes on some platforms), restore it with:

```
chmod +x docker/sbx-kit/tests/coding-agent-smoke.sh
```
