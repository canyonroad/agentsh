# agentsh

**Runtime policy + audit + steering for AI agent execution.**

agentsh is a secure, policy-enforced execution gateway that sits *under* your agent/tooling. It intercepts **file**, **network**, and **process** activity (including subprocess trees), enforces the policy you define, and emits **structured audit events**.

> **Platform note**
> agentsh targets **Linux** today (native hosts or inside Linux containers). **macOS and Windows builds are planned**; until then, run agentsh inside a Linux container/VM on those platforms.

---

## What is agentsh?

- **Drop-in shell/exec endpoint** that turns every command (and its subprocesses) into auditable events.
- **Per-operation policy engine**: `allow`, `deny`, `approve` (human OK), `soft_delete`, or `redirect`.
- **Full I/O visibility**:
  - file open/read/write/delete
  - network connect + DNS
  - process start/exit
  - PTY activity
- **Two output modes**:
  - human-friendly shell output
  - compact JSON responses for agents/tools

---

## Why agentsh?

Agent workflows eventually run arbitrary code (`pip install`, `make test`, `python script.py`). Traditional "ask for approval before running a command" controls stop at the tool boundary and can't see what happens *inside* that command.

agentsh enforces policy **at runtime**, so hidden work done by subprocesses is still governed, logged, and (when required) approved.

---

## Meaningful blocks: deny → redirect (the "steering" superpower)

Most systems can *deny* an action. agentsh can also **redirect** it.

That means when an agent tries the wrong approach (or brute-force workarounds), policy can steer it to the right path by swapping the command and returning guidance—keeping the agent on the paved road and reducing wasted retries.

---

## Containers + agentsh: better together

Containers isolate the host surface; agentsh adds **in-container runtime visibility and policy**.

- Per-operation audit (files, network, commands) shows what happened during installs/builds/tests.
- Approvals and rules persist across long-lived shells and subprocess trees—not just the first command.
- Path-level controls on mounted workspaces/caches/creds; containers don't natively give that granularity.
- Same behavior on host and in containers, so CI and local dev see the same policy outcomes.

---

## Quick start

### Install

**From a GitHub Release**
Download the `.deb`, `.rpm`, or `.apk` for your platform and install.

Example:
```bash
sudo dpkg -i agentsh_*_linux_amd64.deb
```

Releases: [https://github.com/erans/agentsh/releases](https://github.com/erans/agentsh/releases)

**From source**

```bash
make build
sudo install -m 0755 bin/agentsh bin/agentsh-shell-shim /usr/local/bin
```

---

### Run locally

```bash
# Start the server (optional if using autostart)
./bin/agentsh server --config configs/server-config.yaml

# Create a session and run a command (shell output)
SID=$(./bin/agentsh session create --workspace . | jq -r .id)
./bin/agentsh exec "$SID" -- ls -la

# Structured output for agents
./bin/agentsh exec --output json --events summary "$SID" -- curl https://example.com
```

---

### Tell your agent to use it (AGENTS.md / CLAUDE.md snippet)

```md
## Shell access

- Run commands via agentsh, not directly in bash/zsh.
- Use: `agentsh exec -- <command>`
- If you need structured output: `agentsh exec --output json --events summary -- <command>`
```

---

### Autostart (no manual daemon step)

You do **not** need to start `agentsh server` yourself.

* The first `agentsh exec` (or any shimmed `/bin/sh`/`/bin/bash`) will automatically launch a local server using `configs/server-config.yaml` (or `AGENTSH_CONFIG` if set).
* That server keeps the FUSE layer and policy engine alive for the session lifetime; subsequent commands reuse it.
* Set `AGENTSH_NO_AUTO=1` if you want to manage the server lifecycle manually.

---

## Use in Docker (with the shell shim)

See `Dockerfile.example` for a minimal Debian-based image.

Inside the image, install a release package (or copy your build), then activate the shim:

```bash
agentsh shim install-shell \
  --root / \
  --shim /usr/bin/agentsh-shell-shim \
  --bash \
  --i-understand-this-modifies-the-host
```

Point the shim at your server (sidecar or host):

```dockerfile
ENV AGENTSH_SERVER=http://127.0.0.1:8080
```

Now any `/bin/sh -c ...` or `/bin/bash -lc ...` in the container routes through agentsh.

**Recommended pattern:** run agentsh as a sidecar (or PID 1) in the same pod/service and share a workspace volume; the shim ensures every shell hop stays under policy.

---

## Policy model

### Decisions

* `allow`
* `deny`
* `approve` (human OK)
* `redirect` (swap a command)
* `audit` (allow + log)
* `soft_delete` (quarantine deletes with restore)

### Scopes

* file operations
* commands
* environment vars
* network (DNS/connect)
* PTY/session settings

### Evaluation

* **first matching rule wins**

Rules live in a named policy; sessions choose a policy.

Defaults:

* sample config: `configs/server-config.yaml`
* default policy: `configs/policies/default.yaml`

---

### Example rules (trimmed)

```yaml
version: 1
name: default

file_rules:
  - name: allow-workspace
    paths: ["/workspace", "/workspace/**"]
    operations: [read, open, stat, list, write, create, mkdir, chmod, rename]
    decision: allow

  - name: approve-workspace-delete
    paths: ["/workspace", "/workspace/**"]
    operations: [delete, rmdir]
    decision: approve
    message: "Delete {{.Path}}?"
    timeout: 5m

  - name: deny-ssh-keys
    paths: ["/home/**/.ssh/**", "/root/.ssh/**"]
    operations: ["*"]
    decision: deny

network_rules:
  - name: allow-api
    domains: ["api.example.com"]
    ports: [443]
    decision: allow

command_rules:
  - name: block-dangerous
    commands: ["rm", "shutdown", "reboot"]
    decision: deny
```

---

### Using a policy

```bash
# Start the server with your policy
./bin/agentsh server --config configs/server-config.yaml

# Create a session pinned to a policy
SID=$(./bin/agentsh session create --workspace /workspace --policy default | jq -r .id)

# Exec commands; responses include decision + guidance when blocked/approved
./bin/agentsh exec "$SID" -- rm -rf /workspace/tmp
```

---

## 60-second demo

The fastest way to "get it" is to run something that spawns subprocesses and touches the filesystem/network.

```bash
# 1) Create a session in your repo/workspace
SID=$(agentsh session create --workspace . | jq -r .id)

# 2) Run something simple (human output)
agentsh exec "$SID" -- uname -a

# 3) Run something that hits the network (JSON output + event summary)
agentsh exec --output json --events summary "$SID" -- curl https://example.com

# 4) Try a sensitive action to see policy outcomes
agentsh exec "$SID" -- rm -rf ./tmp
```

Tip: keep a terminal with `--output json` open when testing policies—it makes it obvious what's being touched.

---

## Starter policy packs

You already have a default policy (`configs/policies/default.yaml`). These opinionated packs are available as separate files so teams can pick one:

* **[`policies/dev-safe.yaml`](configs/policies/dev-safe.yaml)**: safe for local development
  * allow workspace read/write
  * approve deletes in workspace
  * deny `~/.ssh/**`, `/root/.ssh/**`
  * restrict network to allowlisted domains/ports

* **[`policies/ci-strict.yaml`](configs/policies/ci-strict.yaml)**: safe for CI runners
  * deny anything outside workspace
  * deny outbound network except artifact registries
  * deny interactive shells unless explicitly allowed
  * audit everything (summary events)

* **[`policies/agent-sandbox.yaml`](configs/policies/agent-sandbox.yaml)**: "agent runs unknown code" mode
  * default deny + explicit allowlist
  * approve any credential/path access
  * redirect network tool usage to internal proxies/mirrors
  * soft-delete destructive operations for easy recovery

---

## "Meaningful blocks" examples (redirect patterns)

Here are a few redirects that tend to pay off immediately:

* If the agent tries `curl`/`wget`, **redirect** to an internal artifact mirror command.
* If the agent tries to write outside the workspace, **redirect** it to write under `/workspace/...`.
* If the agent tries to delete recursively, require `approve` (or `soft_delete`) and return a message with the safe alternative.

(Keep redirects small and explicit; treat them as the paved road.)

---

## References

* Config template: [`configs/server-config.yaml`](configs/server-config.yaml)
* Default policy: [`configs/policies/default.yaml`](configs/policies/default.yaml)
* Example Dockerfile (with shim): [`Dockerfile.example`](Dockerfile.example)
* Environment variables (all `AGENTSH_*` overrides, auto-start toggles, transport selection): [`docs/spec.md` §15.3 "Environment Variables"](docs/spec.md#153-environment-variables)
* Architecture & data flow (FUSE + policy engine + API): inline comments in [`configs/server-config.yaml`](configs/server-config.yaml) and [`internal/netmonitor`](internal/netmonitor)
* CLI help: `agentsh --help`, `agentsh exec --help`, `agentsh shim --help`

---

Created with the help of agents for agents.
