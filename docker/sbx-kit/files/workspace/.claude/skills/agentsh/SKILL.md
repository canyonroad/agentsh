---
name: agentsh
description: Use when the user asks about AgentSH policy, sandbox enforcement, audit events, or what file/network/command operations are allowed inside this Docker Sandbox. Read /run/agentsh/tier for the active enforcement mode, /etc/agentsh/policies/default.yaml for the merged active policy, and /home/agent/.agentsh/policy.yaml for the user-overlay fragment.
---

# AgentSH in this sandbox

This sandbox has AgentSH installed via the Docker Sandboxes mixin kit. It
enforces a policy on file, network, command, and signal operations performed
by you and your subprocesses.

## Inspect the live state

| Question | Run |
|---|---|
| What enforcement tier is active? | `cat /run/agentsh/tier` (one of `shim`, `none`) |
| What policy is being enforced right now? | `cat /etc/agentsh/policies/default.yaml` |
| What are my overrides on top of the baked policy? | `cat /home/agent/.agentsh/policy.yaml` |
| Is the daemon running? | `pgrep -af 'agentsh server'` |
| Full grammar reference | `cat /usr/share/doc/agentsh/policy-reference.md` |

## Extend the policy

Write a partial YAML policy to `/home/agent/.agentsh/policy.yaml`. The
bootstrap merges it on top of the baked `coding-agent` template on the next
sandbox start. Rules that share a `name` with a baked rule replace it;
rules with new names append.

Minimal example:

```yaml
version: 1
name: my-overrides
file_rules:
  - name: allow-data-area
    paths: ["/data/**"]
    operations: [write, create, mkdir, rename]
    decision: allow
```

Restart the sandbox via Docker Sandboxes to pick up the change. In-place
reload is not supported in v1.

## Common patterns

- Let the agent write outside `/workspace`: add a `file_rules` entry with `decision: allow` for the new paths.
- Block a command unconditionally: add a `command_rules` entry with `decision: deny`.
- Soft-delete instead of hard-delete on a path: `decision: soft_delete` in a `file_rules` entry for `delete`/`rmdir` operations.
- Audit (don't block) a pattern: `decision: audit`.

For the full grammar — every field, every decision value, available
templating variables — read `/usr/share/doc/agentsh/policy-reference.md`.

## When the tier is `none`

That means the bootstrap couldn't confirm the shim PATH made it past the
agent's entrypoint, OR the daemon failed to start. Check
`/var/log/agentsh/bootstrap.log` and `/var/log/agentsh/daemon.log` for the
reason. The agent will continue to run — AgentSH never blocks the agent's
startup — but enforcement is degraded to advisory.
