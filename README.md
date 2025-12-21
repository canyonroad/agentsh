# agentsh

Secure, policy‑enforced execution gateway for AI agents. agentsh sits under your agent/tooling, intercepts every file, network, and process operation, and enforces the policy you define while emitting structured audit events.

---

## What is agentsh?
- A drop‑in shell/exec endpoint that turns every command (and its subprocesses) into auditable events.
- Per‑operation policy engine: allow, deny, require human approval, soft‑delete, or redirect commands.
- Full I/O visibility: file opens/reads/writes/deletes, network connects/DNS, process start/exit, and PTY activity.
- Two output modes: human‑friendly shell output or compact JSON responses for agents/tools.

## Why agentsh?
Agent workflows eventually run arbitrary code (`pip install`, `make test`, `python script.py`). Traditional “ask for approval before running a command” controls stop at the tool boundary and can’t see what happens inside that command. agentsh enforces policy at runtime, so hidden work done by subprocesses is still governed, logged, and (when required) approved.

## Why containers alone are not enough
- A container boundary isolates the host but does **not** explain *what* happened inside. You still need visibility and policy inside the container.
- Package managers/downloads inside the container can exfiltrate data or pull unvetted code; the container won’t tell you which files or hosts were touched.
- Long‑lived shells and subprocess trees bypass wrapper‑level approvals; agentsh keeps enforcing for the entire session.
- Mounted volumes (workspace, caches, creds) still need path‑level rules—containers don’t give you those by default.

---

## Quick start

### Install
- From a GitHub Release: download the `.deb`, `.rpm`, or `.apk` matching your platform and install (example: `sudo dpkg -i agentsh_<VERSION>_linux_amd64.deb`).
- From source: `make build` (binaries land in `./bin/`), then `sudo install -m 0755 bin/agentsh bin/agentsh-shell-shim /usr/local/bin`.

### Run locally
```bash
# Start the server
./bin/agentsh server --config [configs/server-config.yaml](configs/server-config.yaml)

# Create a session and run a command (shell output)
SID=$(./bin/agentsh session create --workspace . | jq -r .id)
./bin/agentsh exec "$SID" -- ls -la

# Structured output for agents
./bin/agentsh exec --output json --events summary "$SID" -- curl https://example.com
```

### Tell your agent to use it (AGENTS.md / CLAUDE.md snippet)
```md
## Shell access
- Run commands via agentsh, not directly in bash/zsh.
- Use: `agentsh exec -- <command …>`
- If you need structured output: `agentsh exec --output json --events summary -- <command …>`
```

### Autostart (no manual daemon step)
- You do **not** need to start `agentsh server` yourself. The first `agentsh exec` (or any shimmed `/bin/sh`/`/bin/bash`) will automatically launch a local server using [`configs/server-config.yaml`](configs/server-config.yaml) (or `AGENTSH_CONFIG` if set).
- That server process keeps the FUSE layer and policy engine alive for the session lifetime; subsequent commands reuse it.
- Set `AGENTSH_NO_AUTO=1` if you want to manage the server lifecycle manually.

### Use in Docker (with the shell shim)
- See [Dockerfile.example](Dockerfile.example) for a minimal Debian-based image.
- Inside the image, install a release package (or copy your build), then activate the shim:
  ```bash
  agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash --i-understand-this-modifies-the-host
  ```
- Point the shim at your server (sidecar or host):
  ```
  ENV AGENTSH_SERVER=http://127.0.0.1:8080
  ```
- Any `/bin/sh -c ...` or `/bin/bash -lc ...` in the container will now route through agentsh.

---

## Policy model
- **Decisions:** `allow`, `deny`, `approve` (human OK), `redirect` (swap a command), `audit` (allow + log), `soft_delete` (quarantine deletes with restore).
- **Scopes:** file operations, commands, environment vars, network (DNS/connect), PTY/session settings.
- **Evaluation:** first matching rule wins. Rules live in a named policy; sessions choose a policy.
- **Defaults:** sample config at [`configs/server-config.yaml`](configs/server-config.yaml); default policy at [`configs/policies/default.yaml`](configs/policies/default.yaml).

### Example rules (trimmed from [`configs/policies/default.yaml`](configs/policies/default.yaml))
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

### Using a policy
```bash
# Start the server with your policy
./bin/agentsh server --config [configs/server-config.yaml](configs/server-config.yaml)

# Create a session pinned to a policy
SID=$(./bin/agentsh session create --workspace /workspace --policy default | jq -r .id)

# Exec commands; responses include decision + guidance when blocked/approved
./bin/agentsh exec "$SID" -- rm -rf /workspace/tmp
```

---

## References
- Config template: [`configs/server-config.yaml`](configs/server-config.yaml)
- Default policy: [`configs/policies/default.yaml`](configs/policies/default.yaml)
- Example Dockerfile (with shim): [Dockerfile.example](Dockerfile.example)
- Environment variables (all `AGENTSH_*` overrides, auto-start toggles, transport selection): [`docs/spec.md` §15.3 “Environment Variables”](docs/spec.md#153-environment-variables).
- Architecture & data flow (FUSE + policy engine + API): see inline comments in [`configs/server-config.yaml`](configs/server-config.yaml) and [`internal/netmonitor`](internal/netmonitor).
- API/CLI examples are embedded in the CLI help: `agentsh --help`, `agentsh exec --help`, `agentsh shim --help`

---

Created with the help of agents for agents.
