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
