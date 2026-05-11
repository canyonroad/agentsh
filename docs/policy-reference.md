# AgentSH policy reference (Docker Sandboxes edition)

This file ships at `/usr/share/doc/agentsh/policy-reference.md` inside any
Docker Sandbox that has the AgentSH mixin kit installed. It's the canonical
reference the agent's SKILL.md points at when you (or the agent) want to add
or change a rule.

For the full schema documented inline with examples, see
`/etc/agentsh/policies/default.yaml` — the merged policy the daemon is
currently enforcing.

## Inspecting the live state

| Question | Run |
|---|---|
| What enforcement tier is active? | `cat /run/agentsh/tier` (one of `shim`, `none`) |
| What policy is being enforced right now? | `cat /etc/agentsh/policies/default.yaml` |
| What are my overrides on top of the baked policy? | `cat /home/agent/.agentsh/policy.yaml` |
| Is the daemon running? | `pgrep -af 'agentsh server'` |

## Adding rules — `~/.agentsh/policy.yaml`

Write a partial policy. The bootstrap merges it on top of the baked
`coding-agent` template on next sandbox start. Rules that share a `name` with
a baked rule replace it; rules with new names append after the baked set.

```yaml
version: 1
name: my-overrides

file_rules:
  - name: allow-extra-write-area
    paths: ["/data/**"]
    operations: [write, create, mkdir, rename]
    decision: allow

  - name: allow-workspace-write     # overrides the baked rule by name
    paths: ["/workspace", "/workspace/**", "/scratch/**"]
    operations: [write, create, mkdir, chmod, rename]
    decision: allow

command_rules:
  - name: deny-aws-cli
    commands: [aws]
    decision: deny
    message: "aws-cli is not permitted in this sandbox"
```

## Rule kinds at a glance

- `file_rules` — file open/read/write/delete/stat/list, by glob path. Decisions: `allow`, `deny`, `approve`, `audit`, `soft_delete`, `redirect`.
- `command_rules` — process exec, by command name + optional argument regex. Decisions: `allow`, `deny`, `approve`, `audit`, `redirect`.
- `signal_rules` — signal sending. Decisions: `allow`, `deny`, `audit`, `approve`, `redirect`, `absorb`.
- `network_rules` — outbound connect by domain / port / CIDR. The Docker Sandbox proxy is the primary outbound-network gate inside a sandbox; AgentSH's network rules are layered on top and apply *before* the proxy.
- `unix_socket_rules` — AF_UNIX socket connect/bind/listen.

Each rule has `name`, `description`, the kind-specific selectors, `decision`, and an optional `message` (Go template; available variables: `.Path`, `.Command`, `.Args`, `.Decision`, `.Signal`, `.PID`).

## Where things live

| Path | Owner | Purpose |
|---|---|---|
| `/usr/share/agentsh/coding-agent.template.yaml` | OS package, read-only | Baked-in policy the bootstrap reads |
| `/home/agent/.agentsh/policy.yaml` | You | Override fragment (optional) |
| `/etc/agentsh/policies/default.yaml` | bootstrap (regenerated each start) | What the daemon enforces |
| `/etc/agentsh/config.yaml` | OS package | Daemon server config |
| `/run/agentsh/tier` | bootstrap | Active enforcement tier |
| `/run/agentsh/agentsh.sock` | daemon | Daemon control socket |
| `/var/log/agentsh/daemon.log` | daemon | Daemon stdout+stderr |
| `/var/log/agentsh/bootstrap.log` | bootstrap | Startup banner + tier probe result |

## Decision semantics quick reference

- `allow` — operation proceeds.
- `audit` — operation proceeds, emit an audit event.
- `deny` — operation refused; the agent gets EACCES (or equivalent).
- `approve` — operation blocks until a human approves out-of-band.
- `soft_delete` — for file delete/rmdir operations only: the path is moved to `/var/lib/agentsh/trash/` instead of being removed. Recoverable.
- `redirect` — for `command_rules` and `connect_redirects`: the operation is rewritten to a different command or destination.
- `absorb` — for `signal_rules` only: the signal is silently consumed and never delivered to the target.

## Reloading

In v1, the bootstrap re-runs only at sandbox start. To pick up a new
`~/.agentsh/policy.yaml`, restart the sandbox via Docker Sandboxes. v1.1 may
add an in-place reload.
