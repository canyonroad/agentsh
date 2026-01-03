# agentsh

**Secure, policy-enforced execution gateway for AI agents.**

agentsh sits *under* your agent/tooling—intercepting **file**, **network**, and **process** activity (including subprocess trees), enforcing the policy you define, and emitting **structured audit events**.

> **Platform note:** Linux provides full enforcement (100% security score). macOS supports two tiers: **ESF+NE** (90% score, requires Apple entitlements) for enterprise deployments, and **FUSE-T** (70% score) as a fallback. Windows supports native enforcement via minifilter driver with **AppContainer** sandbox isolation (85% score). See the [Platform Comparison Matrix](docs/platform-comparison.md) for details.

---

## What is agentsh?

- **Drop-in shell/exec endpoint** that turns every command (and its subprocesses) into auditable events.
- **Per-operation policy engine**: `allow`, `deny`, `approve` (human OK), `soft_delete`, or `redirect`.
- **Full I/O visibility**:
  - file open/read/write/delete
  - network connect + DNS
  - process start/exit
  - PTY activity
  - LLM API requests with DLP and usage tracking
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

**Example: redirect curl to an audited wrapper**

```yaml
command_rules:
  - name: redirect-curl
    commands: [curl, wget]
    decision: redirect
    message: "Downloads routed through audited fetch"
    redirect_to:
      command: agentsh-fetch
      args: ["--audit"]
```

**Example: redirect writes outside workspace back inside**

```yaml
file_rules:
  - name: redirect-outside-writes
    paths: ["/home/**", "/tmp/**"]
    operations: [write, create]
    decision: redirect
    redirect_to: "/workspace/.scratch"
    message: "Writes outside workspace redirected to /workspace/.scratch"
```

The agent sees a successful operation (not an error), but you control where things actually land.

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

Download the `.deb`, `.rpm`, or `.apk` for your platform from the [releases page](https://github.com/erans/agentsh/releases).

```bash
# Example for Debian/Ubuntu
sudo dpkg -i agentsh_<VERSION>_linux_amd64.deb
```

**From source (Linux)**

```bash
make build
sudo install -m 0755 bin/agentsh bin/agentsh-shell-shim /usr/local/bin
```

**From source (macOS)**

```bash
# FUSE-T mode (standard, requires brew install fuse-t)
CGO_ENABLED=1 go build -o bin/agentsh ./cmd/agentsh

# ESF+NE enterprise mode (requires Xcode 15+, Apple entitlements)
make build-macos-enterprise
```

See [macOS Build Guide](docs/macos-build.md) for detailed macOS build instructions.

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
- Use: `agentsh exec $SID -- <your-command-here>`
- For structured output: `agentsh exec --output json --events summary $SID -- <your-command-here>`
- Get session ID first: `SID=$(agentsh session create --workspace . | jq -r .id)`
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
* env override: set `AGENTSH_POLICY_NAME` to an **allowed** policy name (no suffix). If unset/invalid/disallowed, the default is used.
* env policy: configure `policies.env_policy` (allow/deny, max_bytes, max_keys, block_iteration) and per-command `env_*` overrides in policy files. Empty allowlist defaults to minimal PATH/LANG/TERM/HOME with built-in secret deny list; set `block_iteration` to hide env iteration (requires env shim).
* allowlist: configure `policies.allowed` in `config.yml`; empty means only the default is permitted.
* optional integrity: set `policies.manifest_path` to a SHA256 manifest to verify policy files at load time.

### Environment policy quick reference

- **Defaults:** With no `env_allow`, agentsh builds a minimal env (PATH/LANG/TERM/HOME) and strips built-in secret keys.
- **Overrides:** Per-command `env_allow`/`env_deny` plus `env_max_keys`/`env_max_bytes` cap and filter the child env at exec time.
- **Block iteration:** `env_block_iteration: true` (global or per rule) hides env enumeration; set `policies.env_shim_path` to `libenvshim.so` so agentsh injects `LD_PRELOAD` + `AGENTSH_ENV_BLOCK_ITERATION=1`.
- **Limits:** Errors if limits are exceeded; env builder is applied before exec for every command.
- **Examples:** See `config.yml` and policy samples under `configs/`.

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

# 2) Run something simple (human-friendly output)
agentsh exec "$SID" -- uname -a
# → prints system info, just like normal

# 3) Run something that hits the network (JSON output + event summary)
agentsh exec --output json --events summary "$SID" -- curl -s https://example.com
# → JSON response includes: exit_code, stdout, and events[] showing dns_query + net_connect

# 4) Trigger a policy decision - try to delete something
agentsh exec "$SID" -- rm -rf ./tmp
# → With default policy: prompts for approval or denies based on your rules

# 5) See what happened (structured audit trail)
agentsh exec --output json --events full "$SID" -- ls
# → events[] shows every file operation, even from subprocesses
```

**What you'll see in the JSON output:**
- `exit_code`: the command's exit status
- `stdout` / `stderr`: captured output
- `events[]`: every file/network/process operation with policy decisions
- `policy.decision`: `allow`, `deny`, `approve`, or `redirect`

Tip: keep a terminal with `--output json` open when testing policies—it makes it obvious what's being touched.

---

### Session Reports

Generate markdown reports summarizing session activity:

```bash
# Quick summary
agentsh report latest --level=summary

# Detailed investigation
agentsh report <session-id> --level=detailed --output=report.md
```

Reports include:
- Decision summary (allowed, blocked, redirected)
- Automatic findings detection (violations, anomalies)
- Activity breakdown by category
- Full event timeline (detailed mode)

See [CI/CD Integration Guide](docs/cicd-integration.md) for pipeline examples.

---

### LLM Proxy and DLP

agentsh includes an embedded proxy that intercepts all LLM API requests from agents:

```bash
# Check proxy status for a session
agentsh proxy status <session-id>

# View LLM-specific events
agentsh session logs <session-id> --type=llm
```

**Features:**
- **Automatic routing**: Sets `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` so agent SDKs route through the proxy
- **Custom providers**: Route to LiteLLM, Azure OpenAI, vLLM, or corporate gateways
- **DLP redaction**: PII (emails, phone numbers, API keys, etc.) is redacted before reaching LLM providers
- **Custom patterns**: Define organization-specific patterns for sensitive data
- **Usage tracking**: Token counts extracted and logged for cost attribution
- **Audit trail**: All requests/responses logged to session storage

**Provider configuration:**

```yaml
proxy:
  mode: embedded
  providers:
    anthropic: https://api.anthropic.com    # Default Anthropic API
    openai: https://api.openai.com          # Default OpenAI API

    # Or use alternative providers:
    # openai: http://localhost:8000         # LiteLLM / vLLM
    # openai: https://your-resource.openai.azure.com  # Azure OpenAI
    # anthropic: https://llm.corp.example.com         # Corporate gateway
```

**DLP configuration:**

```yaml
dlp:
  mode: redact
  patterns:
    email: true
    api_keys: true
  custom_patterns:
    - name: customer_id
      display: identifier
      regex: "CUST-[0-9]{8}"
```

See [LLM Proxy Documentation](docs/llm-proxy.md) for full configuration options.

---

### Policy Generation

Generate restrictive policies from observed session behavior ("profile-then-lock" workflow):

```bash
# Generate policy from latest session
agentsh policy generate latest --output=ci-policy.yaml

# Generate with custom name and threshold
agentsh policy generate abc123 --name=production-build --threshold=10

# Quick preview to stdout
agentsh policy generate latest
```

The generated policy:
- Allows only operations observed during the session
- Groups paths into globs when many files in same directory
- Collapses subdomains into wildcards (e.g., `*.github.com`)
- Flags risky commands (curl, wget, rm) with arg patterns
- Includes blocked operations as commented-out rules for review

**Use cases:**
- **CI/CD lockdown**: Profile a build/test run, lock future runs to that behavior
- **Agent sandboxing**: Let an AI agent run a task, generate policy for future runs
- **Container profiling**: Profile a workload, generate minimal policy for production

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

## AI Assistant Integration Examples

Ready-to-use snippets for configuring AI coding assistants to use agentsh:

* **[Claude Code](examples/claude/)** - CLAUDE.md snippet for Claude Code integration
* **[Cursor](examples/cursor/)** - Cursor rules for agentsh integration
* **[AGENTS.md](examples/agents/)** - Generic AGENTS.md snippet (works with multiple AI tools)

> **Note:** These examples are for local development scenarios where running the AI agent inside a container isn't practical. For production or CI/CD environments, prefer running agents in containers with the shell shim installed—see [Use in Docker](#use-in-docker-with-the-shell-shim).

---

## References

* **Security & threat model:** [`SECURITY.md`](SECURITY.md) - what agentsh protects against, known limitations, operator checklist
* Config template: [`configs/server-config.yaml`](configs/server-config.yaml)
* Default policy: [`configs/policies/default.yaml`](configs/policies/default.yaml)
* Example Dockerfile (with shim): [`Dockerfile.example`](Dockerfile.example)
* **Platform comparison:** [`docs/platform-comparison.md`](docs/platform-comparison.md) - feature support, security scores, performance by platform
* **LLM Proxy & DLP:** [`docs/llm-proxy.md`](docs/llm-proxy.md) - embedded proxy configuration, DLP patterns, usage tracking
* **macOS build guide:** [`docs/macos-build.md`](docs/macos-build.md) - FUSE-T and ESF+NE build instructions
* **macOS ESF+NE architecture:** [`docs/macos-esf-ne-architecture.md`](docs/macos-esf-ne-architecture.md) - System Extension, XPC, and deployment details
* Environment variables (all `AGENTSH_*` overrides, auto-start toggles, transport selection): [`docs/spec.md` &sect;15.3 "Environment Variables"](docs/spec.md#153-environment-variables)
* Architecture & data flow (FUSE + policy engine + API): inline comments in [`configs/server-config.yaml`](configs/server-config.yaml) and [`internal/netmonitor`](internal/netmonitor)
* CLI help: `agentsh --help`, `agentsh exec --help`, `agentsh shim --help`

---

Created with the help of agents for agents.
