# Command Policies Cookbook

This page is a practical, recipe-first guide to agentsh's **command policy** layer:
what to do when a binary is blocked, how to allow it, how to gate it behind an
approval, and when to reach for `agentsh wrap` instead of `agentsh exec`.

For the full policy language reference (variables, signal rules, network
redirect, troubleshooting), see
[`docs/operations/policies.md`](../operations/policies.md). This page is
focused on `command_rules` and the workflow around them.

## How command matching works

The command policy engine is **default-deny**. A command that does not match
any compiled rule hits the built-in `default-deny-commands` rule at the end of
the evaluation chain
([`internal/policy/engine.go`](../../internal/policy/engine.go)). You will see
this in the audit stream as a `command_precheck` event with
`policy.rule = "default-deny-commands"`. That rule name is the tell for "no
rule matched" — not "a deny rule fired."

Rules in `command_rules` are evaluated **in declaration order**, and the
**first match wins**. Within a single rule, a command is considered matching if
any of the following patterns from that rule match, tried in this order:

1. **Full-path exact match** — e.g. `commands: ["/opt/myapp/bin/emdash"]`.
   Most specific; pin to a known-good binary.
2. **Full-path glob** — e.g. `commands: ["/opt/myapp/**"]`.
3. **Basename exact match** — e.g. `commands: ["emdash"]`. Matches any
   `emdash` on `$PATH`, regardless of directory.
4. **Basename glob** — e.g. `commands: ["py*"]`. Matches `python`, `python3`,
   `pytest`, etc.

If the rule also specifies `args_patterns`, the joined arg string must match
at least one of the regex patterns for the rule to apply — otherwise the
engine skips to the next rule.

`command_rules` at `depth: 0` (the default) apply to direct commands from
`agentsh exec`. Rules with `context.min_depth: 1` apply only to nested
execve calls observed by the seccomp/ptrace tracer (commands that the agent
itself spawns). Most of the shipped presets use depth-0 rules; reach for
`context.min_depth` when you want to say "the agent can run X, but only
if X is spawning it, not a human."

## Recipe: allow a new binary

You tried to run a command under `agentsh exec` and got `blocked by policy
(rule=default-deny-commands)`. Add an allow rule.

**By basename** — when you trust any binary with that name on `$PATH`:

```yaml
command_rules:
  - name: allow-emdash
    description: Allow the emdash agent CLI
    commands:
      - emdash
    decision: allow
```

**By full path** — stricter, and what we recommend for anything security-
sensitive. Only the specific binary at the specific path is allowed; a
different `emdash` dropped into `/tmp` will still hit default-deny:

```yaml
command_rules:
  - name: allow-emdash-pinned
    description: Allow the emdash agent CLI (pinned)
    commands:
      - "/opt/emdash/bin/emdash"
    decision: allow
```

**By directory glob** — when a vendor installs many binaries under one
prefix:

```yaml
command_rules:
  - name: allow-myapp-bundle
    description: Allow every binary shipped under /opt/myapp
    commands:
      - "/opt/myapp/**"
    decision: allow
```

Place the rule **before** any broader rule that might also match (first match
wins). In `configs/policies/default.yaml` the safe place is near the top of
`command_rules`, above the generic allow-lists.

## Recipe: allow it only under approval

If you want the binary to run but want a human-in-the-loop gate, use
`decision: approve` instead of `allow`. The command is suspended until a human
approves it through the configured approval channel (terminal prompt, TOTP,
WebAuthn, REST — see
[`SECURITY.md`](../../SECURITY.md)).

```yaml
command_rules:
  - name: approve-emdash
    description: Require approval before running emdash
    commands:
      - emdash
    decision: approve
    message: "Agent wants to run emdash: {{.Args}}"
    timeout: 5m
```

This is the right middle ground for tools you occasionally use but don't want
the agent reaching for unattended. Approvals are cheap; unrestricted allows
are not.

## Recipe: running long-lived / GUI / Electron agents — use `wrap`, not `exec`

`agentsh exec` and `agentsh wrap` are not interchangeable. Reaching for `exec`
to launch an agent that lives for hours is the single most common cause of
"command denied by policy" confusion.

| | `agentsh exec` | `agentsh wrap` |
|---|---|---|
| Shape | Synchronous: run-and-wait | Launch and supervise |
| Pre-execution policy check | Yes (`command_precheck`) | **No** — the top-level binary is not pre-checked |
| Intended workload | Short commands (`ls`, `git status`, `python build.py`) | Long-lived agents, IDEs, Electron apps, MCP servers |
| Enforcement surface | The single spawned process | The full process tree spawned under the agent |
| Child processes | Tracked via the execve-depth layer | Tracked via the execve-depth layer |

`agentsh wrap` creates (or reuses) a session, installs the full enforcement
stack — ptrace / seccomp-notify / Landlock / signal filter / FUSE workspace /
LLM proxy env injection / eBPF network rules — spawns the agent binary under
that stack, and forwards stdio and signals so the terminal that ran the
command acts as the agent's foreground. Because the top-level binary is
launched *under* enforcement rather than *through* an exec pre-check, you do
**not** need a `command_rules` entry for it. Rules on what the agent then
spawns internally still apply via the execve-depth layer — that is where the
real policy work happens for a long-lived agent.

**Worked example — launch emdash under the strict policy:**

```bash
agentsh wrap --policy agent-strict -- emdash
```

This will:

1. Create a fresh session pinned to
   [`configs/policies/agent-strict.yaml`](../../configs/policies/agent-strict.yaml).
2. Set up the FUSE workspace mount and LLM proxy for the session.
3. Install the platform-appropriate interception layer (seccomp or ptrace on
   Linux, ES on macOS, driver on Windows).
4. Spawn `emdash` under that layer.
5. Forward the terminal's stdin/stdout/stderr and signals to the emdash
   process, so Ctrl-C and the like behave as expected.

No `command_rules` entry for `emdash` is needed — the binary is launched
directly. The policy applies to everything emdash then spawns: subprocesses,
shell commands, network, file writes.

Nested shell behavior depends on the active wrap mode. In strong interception
paths such as ptrace or execve-intercepting wrap, descendant `sh`/`bash`
processes bypass the shell shim because wrap is already enforcing exec policy
for the whole tree. In fallback or no-`execve` modes, nested shells still
depend on the shim for command steering, so `AGENTSH_IN_SESSION` is not
injected.

### Electron sharp edges

Electron apps (and anything using a Chromium renderer subprocess) exercise
two corners of the enforcement stack harder than most CLI agents:

1. **`chrome-sandbox` is setuid**, and setuid binaries strip `PR_SET_DUMPABLE`
   on exec. ptrace requires the target to be dumpable to attach, so launching
   an Electron app under the ptrace tracer can fail unless you pass
   `--no-sandbox` to the app or run under seccomp-notify instead. Treat
   `--no-sandbox` as an escape hatch, not a default; it disables Chromium's
   own sandbox, which is a separate layer from agentsh's enforcement.
2. **High-volume execve traffic.** Electron spawns renderer, GPU, utility,
   and zygote subprocesses aggressively. Every one of those goes through the
   execve-depth layer. This is supported, but it exercises the tracer path
   heavily — if you see unexpected latency or dropped events, reach for the
   ptrace/seccomp benchmarks and compare against your baseline before
   assuming the agent is buggy.

## How to debug a denial

Start with the audit stream. Every command that goes through `agentsh exec`
(or the wrapped execve-depth layer) emits a `command_policy` event with
`operation = "command_precheck"`.

```bash
# Tail live events for a session (SSE, everything) and filter client-side:
agentsh events tail "$SID" | jq 'select(.type == "command_policy")'

# Query historical events with server-side type filtering:
agentsh events query --session "$SID" --type command_policy
```

A denial looks like this:

```json
{
  "type": "command_policy",
  "operation": "command_precheck",
  "session_id": "sess-abc123",
  "command_id": "cmd-042",
  "policy": {
    "decision": "deny",
    "effective_decision": "deny",
    "rule": "default-deny-commands",
    "message": ""
  },
  "fields": {
    "command": "emdash",
    "args": ["--project", "."]
  }
}
```

Read the fields in this order:

1. **`policy.rule`** — which rule matched. If it is `default-deny-commands`,
   **no rule matched** and you need to add one (see the recipes above). If it
   is a named rule you recognize, that rule has `decision: deny` — the fix is
   to adjust or reorder the rule, not to add a new one.
2. **`policy.message`** — custom message from the rule author, when present.
3. **`fields.command` / `fields.args`** — the exact command string and
   argument vector that the engine saw. Watch for unexpected path expansion
   (basename rule expected, full path supplied by the agent, or vice versa).
4. **`policy.effective_decision`** — the final decision after
   approval/redirect processing. When this differs from `policy.decision`, an
   approval was consulted.

If you see a `command_precheck` deny for a GUI application or IDE, that is
almost always the signal you reached for `exec` when you wanted `wrap`. The
fix is a subcommand swap, not a policy edit.

## What NOT to do

### Don't add a catchall allow

```yaml
# DO NOT DO THIS
command_rules:
  - name: allow-everything
    commands: ["*"]
    decision: allow
```

This defeats the command-policy layer entirely and leaves only the file,
network, and signal layers standing. It's tempting during evaluation
("let me just get past this one denial") but it is the end of the benefit
you were paying for with agentsh in the first place. Use specific allow rules
or approval gates.

### Don't rely on basenames for security-sensitive allows

```yaml
# Weaker than it looks
- name: allow-python
  commands: [python]
  decision: allow
```

This allows **any** binary named `python` on `$PATH`, including one that the
agent drops into `/tmp/python` and runs. If the binary identity matters, pin
with a full path or a directory glob under a directory the agent cannot
write to.

### Don't mistake "no rule matched" for "a deny rule fired"

`default-deny-commands` showing up in your audit stream is the engine's way
of saying "nothing matched." Do not try to find and "fix" a deny rule — there
isn't one. The fix is to add an allow (or approve) rule above the catchall.

## Cross-references

- **Full policy language reference:** [`docs/operations/policies.md`](../operations/policies.md)
  — variables, file rules, network redirect, signal rules, troubleshooting.
- **Shipped default policy:** [`configs/policies/default.yaml`](../../configs/policies/default.yaml)
  — balanced dev policy; safe starting point.
- **Strict policy preset:** [`configs/policies/agent-strict.yaml`](../../configs/policies/agent-strict.yaml)
  — read-only tools allowed, everything else approved.
- **Approval channels and auth:** [`SECURITY.md`](../../SECURITY.md)
  — how `decision: approve` is surfaced to humans (TTY, TOTP, WebAuthn, REST).
- **CLI help:** `agentsh wrap --help`, `agentsh exec --help`.
