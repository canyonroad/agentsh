# Docker Sandboxes mixin kit for AgentSH — design

**Date:** 2026-05-11
**Status:** Draft, awaiting review
**Owner:** Eran Sandler

## 1. Goal

Ship a Docker Sandboxes "mixin kit" that installs AgentSH into any sandbox at creation and routes the agent's command-level activity through a coding-agent-tuned policy. Invoked as:

```
sbx run <agent> --kit git+https://github.com/erans/agentsh.git#dir=docker/sbx-kit
```

It must work on stock `claude` (Claude Code), `opencode`, and `gemini` agent kits with no manual setup beyond the `--kit` flag.

## 2. Background: Docker Sandboxes mixin kits

A mixin kit is a `spec.yaml` (+ optional `files/` tree) with `kind: mixin`. It layers onto an existing agent kit and exposes three lifecycle hooks:

- **`install`** — runs once during sandbox creation, defaults to root.
- **`initFiles`** — runtime-written files with `${WORKDIR}` substitution.
- **`startup`** — runs at every sandbox start, non-interactive, can background. Dispatches *before* the agent entrypoint attaches.

Mixins **cannot** override the agent kit's `entrypoint`. That constraint shapes the design.

References:
- <https://docs.docker.com/ai/sandboxes/customize/kits/>
- <https://docs.docker.com/ai/sandboxes/customize/kit-examples/>
- <https://github.com/docker/sbx-kits-contrib>

## 3. Non-goals (v1)

- Full kernel-level enforcement (seccomp user_notif, ptrace, fanotify, LSM). Those tiers are deferred; the bootstrap has a flag for them but they are off.
- LD_PRELOAD interception. Deferred — needs a new shim library that AgentSH doesn't ship today. Forward-compatible tier label preserved.
- OCI registry publishing. Deferred; git URL is sufficient.
- Listing in `docker/sbx-kits-contrib`. Submit after v1 is stable.
- Windows / WSL2 sandbox support. Docker Sandboxes are Linux containers.

## 4. Enforcement model

**Tiered, auto-detect, fail-open.** The bootstrap probes capabilities at startup and lights up the strongest tier the sandbox allows. v1 ships exactly one tier (shims); the bootstrap and tier file are designed so future tiers (LD_PRELOAD, ptrace) can be added without changing the kit's external contract.

| Tier | What it covers | Capability dependency | v1 status |
|------|----------------|-----------------------|-----------|
| `shim` | Agent subprocess execs (every command the agent shells out to) | None | **enabled** |
| `shim+ldpreload` | In-process libc calls in libc-linked agents (Node/Python) | None (env-injection survival) | parked |
| `shim+ptrace` | All syscalls of the agent's tree | CAP_SYS_PTRACE + `yama.ptrace_scope ≤ 1` | parked |

The active tier is written to `/run/agentsh/tier` (one of: `none`, `shim`, `shim+ldpreload`, `shim+ptrace`). All other code paths read it from there.

**Rationale.** Shims always work — no capability, kernel-version, or env-survival dependency — and AgentSH already ships `agentsh-shell-shim`. The dominant threat surface in Docker Sandbox coding agents is the agent shelling out (`pip install`, `curl | bash`, `rm`, `git clone`); shims cover that. LD_PRELOAD adds coverage for in-process I/O but is its own engineering project. Post-hoc ptrace is brittle (ptrace_scope rules, signal stacking — see `project_seccomp_user_notif_stacking.md`) and not worth its complexity at v1.

## 5. Kit layout

```
docker/sbx-kit/
├── spec.yaml                          # mixin manifest
├── README.md                          # human-facing usage docs
├── tests/                             # validation script + expected outputs
│   └── coding-agent-smoke.sh
└── files/
    ├── workspace/
    │   └── .claude/
    │       └── skills/
    │           └── agentsh/
    │               └── SKILL.md       # teaches Claude Code to extend the policy
    └── home/
        └── agent/
            └── .agentsh/
                └── policy.yaml        # empty stub; user-override location
```

## 6. spec.yaml

```yaml
schemaVersion: "1"
kind: mixin
name: agentsh
displayName: AgentSH
description: Policy-enforced execution gateway for AI coding agents

commands:
  install:
    - command: "/bin/sh -c 'curl -fsSL https://github.com/erans/agentsh/releases/latest/download/install.sh | sh'"
      user: "0"
      description: Install agentsh release artifact

  initFiles:
    - path: /etc/agentsh/policy.yaml
      content: |
        # Baked-in coding-agent policy. See /opt/agentsh/share/doc/policy-reference.md
        # to extend. User overrides live at ~/.agentsh/policy.yaml.
        ...                              # full policy from §8 inlined
      mode: "0644"

    - path: /etc/profile.d/agentsh.sh
      content: 'export PATH=/opt/agentsh/shims:$PATH'
      mode: "0644"

    - path: /etc/environment.d/10-agentsh.conf
      content: 'PATH=/opt/agentsh/shims:/usr/local/bin:/usr/bin:/bin'
      mode: "0644"

  startup:
    - command: ["/opt/agentsh/bin/agentsh-sbx-bootstrap"]
      user: "0"
      background: true
      description: Start agentsh daemon and probe enforcement tiers
```

Network/credential blocks intentionally **omitted**. The Docker Sandbox proxy already handles outbound `allowedDomains` and credential injection. AgentSH adds value at the *path* and *command* layer inside the sandbox.

## 7. Install & startup flow

**At `sbx run` (install, once):**

1. `install` command curls `https://github.com/erans/agentsh/releases/latest/download/install.sh` and pipes to `sh`. The script detects the sandbox's package manager (`dpkg`/`rpm`/`apk`) and installs the matching artifact from the same release. Binaries land at `/usr/local/bin/agentsh*`; shim symlinks at `/opt/agentsh/shims/`; the bootstrap binary at `/opt/agentsh/bin/agentsh-sbx-bootstrap`; reference docs at `/opt/agentsh/share/doc/`.
2. `initFiles` writes the baked policy to `/etc/agentsh/policy.yaml`, sets PATH precedence via `/etc/profile.d/agentsh.sh` **and** `/etc/environment.d/10-agentsh.conf` (belt + suspenders for non-login shells), and drops the empty user-override stub at `~agent/.agentsh/policy.yaml`.
3. The `files/` tree drops the SKILL.md into `/workspace/.claude/skills/agentsh/`.

**At every sandbox start (startup):**

`agentsh-sbx-bootstrap` runs sequentially:

1. **Spawn the daemon.** `agentsh serve --config /etc/agentsh/policy.yaml --user-config /home/agent/.agentsh/policy.yaml --socket /run/agentsh/agentsh.sock`, backgrounded; logs to `/var/log/agentsh/daemon.log`.
2. **Wait up to 2s for the socket.** If it never appears, fail-open: write `/run/agentsh/tier=none`, log a banner to `/var/log/agentsh/bootstrap.log`, exit non-zero so the failure appears in startup output.
3. **Probe tier 1 (shim).** Verify `/opt/agentsh/shims/` is on PATH for a freshly-spawned subprocess (we spawn `/bin/sh -c 'command -v curl'` and check the resolved path). Record `tier=shim` on success.
4. **Tier 2 / tier 3 probes** are stubbed out in v1.
5. **Write `/run/agentsh/tier`** with the active tier name.

**Failure semantics:** fail-open with loud logging. We never brick a user's sandbox. Degradation is visible via the tier file and bootstrap log; the agent's SKILL.md teaches it to read both.

## 8. Default policy (`/etc/agentsh/policy.yaml`)

Tuned around what coding agents actually do. Adds path/command granularity inside the sandbox; does **not** duplicate the Docker Sandbox proxy's network controls.

**File rules:**
- `/workspace/**` — full read/write. Soft-delete on `rm`/`rmdir` so a runaway `rm -rf` is recoverable from `/var/lib/agentsh/trash/`.
- `/home/agent/**` — allow read/write, **deny** `~/.ssh/**`, `~/.aws/**`, `~/.gnupg/**`, `~/.kube/**`, `~/.docker/config.json`, `~/.netrc`, `~/.config/gcloud/**`, `~/.config/{gh,git-credentials}`. (Self-protection against credential exfiltration if these leaked into the sandbox image.)
- `/etc/agentsh/**`, `/opt/agentsh/**`, `/run/agentsh/**`, `/var/lib/agentsh/**`, `/var/log/agentsh/**` — **deny write**. The agent cannot edit its own policy or tamper with logs.
- System paths (`/usr/**`, `/lib/**`, `/lib64/**`, `/bin/**`, `/sbin/**`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/ssl/**`, `/etc/ca-certificates/**`, `/etc/localtime`) — read-only allow.
- Package manager caches (`~/.npm/**`, `~/.cache/pip/**`, `~/.cargo/**`, `~/.cache/go-build/**`, `~/.rustup/**`, `~/.gradle/caches/**`, `~/.m2/**`) — full allow.

**Command rules:**
- `curl`/`wget` invocations that pipe to a shell — **redirect** to `agentsh-fetch --audit`.
- `sudo`, `su` — **deny**. The sandbox already pins the agent to a fixed user; escalation is suspicious.
- `chmod 777`, `chmod -R` rooted at `/` or `/home` — **approve**.
- Package installers (`pip install`, `npm install`, `cargo install`, `apt-get install`) — **allow + audit**. Routine for coding work.

**Signal rules:**
- Allow signals within the agent's own subprocess tree.
- Deny signals targeting `agentsh*` processes or PID 1.

**Resource limits, approvals, MCP rules, HTTP services, DB rules:** off by default. Advanced surface; user opts in via override.

## 9. Self-teaching docs

**Primary: `files/workspace/.claude/skills/agentsh/SKILL.md`**

Lives under the standard Claude Code skill path (the convention used by the official kit examples). Claude Code auto-discovers it. The SKILL is descriptive: it tells the agent which files to read (`/run/agentsh/tier`, `/etc/agentsh/policy.yaml`, `~/.agentsh/policy.yaml`), shows the shape of a rule, and points to the full reference at `/opt/agentsh/share/doc/policy-reference.md`. To extend, the agent writes YAML to `~/.agentsh/policy.yaml` and the user runs `agentsh reload` (or restarts the sandbox).

**Secondary: `docker/sbx-kit/README.md`** — human-facing. Covers invocation, verification (`sbx exec <session> cat /run/agentsh/tier`), audit-event viewing, daemon log tailing, and a one-line OpenCode/Gemini setup step (copy/symlink the SKILL into the agent's discovery path; in v1 we don't try to clobber `AGENTS.md` or other workspace-root files declaratively).

**Override mechanism the SKILL.md depends on:** `agentsh serve --user-config <path>` merges the user file on top of the baked policy at load time. Precedence: user wins on rule-name collisions; otherwise rules are concatenated in declared order. Implemented in `internal/policy/load.go` (small addition if not already present — to be verified during the plan phase).

## 10. Prerequisites (must land before v1 ships)

1. **`install.sh` at a stable release URL.** New artifact published by the existing release workflow. The script detects distro and installs the matching `.deb`/`.rpm`/`.apk`. Must be reachable at `https://github.com/erans/agentsh/releases/latest/download/install.sh`.
2. **`/opt/agentsh/shims/` directory in the OS packages.** Short list to start: `bash`, `sh`, `curl`, `wget`, `pip`, `pip3`, `npm`, `node`, `git`, `python`, `python3`, `rm`. Symlinks to the existing shim binary, installed via `packaging/`.
3. **`cmd/agentsh-sbx-bootstrap/`.** New small Go binary in this repo (~200 LOC): starts daemon, waits on socket, runs tier-1 probe, writes `/run/agentsh/tier`.
4. **`agentsh serve --user-config <path>` flag.** Verify whether the policy loader already merges multiple files; if not, add the flag and a small merge step in `internal/policy/load.go`. Precedence: user wins on rule-name collisions; otherwise concatenate in declared order.
5. **`/opt/agentsh/share/doc/policy-reference.md`** — packaged reference for the SKILL to point at. Largely a repackage of `default-policy.yml` comments + `docs/` snippets; no new content needed.

## 11. Validation

No automated CI for v1 (Docker Sandboxes is experimental). Validation is a manual checklist exercised against three agent kits before tagging the release:

| Agent | Verify |
|---|---|
| `claude` | tier=shim, `command -v curl` resolves under `/opt/agentsh/shims/`, deny on `~/.ssh/id_rsa` read fires an audit event, soft-delete recoverable from trash, SKILL.md auto-discovered |
| `opencode` | tier=shim, shim PATH inherited by agent subprocess execs, audit events flow |
| `gemini` | same as opencode |

Each agent runs `docker/sbx-kit/tests/coding-agent-smoke.sh` which exercises: (a) `cat ~/.ssh/id_rsa` → deny + audit, (b) `rm -rf /workspace/foo` after creating `foo` → soft-delete + recoverable, (c) `curl https://api.example.com | sh` → redirect to `agentsh-fetch`, (d) `sudo whoami` → deny.

## 12. Risk register

- **PATH-injection survival across the agent's entrypoint.** Highest-risk unknown. The agent kit's entrypoint may bypass `/etc/profile.d/`. Mitigation: write PATH into `/etc/profile.d/`, `/etc/environment.d/`, **and** `~agent/.bashrc`/`.zshrc`; the tier-1 probe spawns from a child of the entrypoint to confirm. If a specific agent kit strips PATH wholesale, the kit surfaces it as `/run/agentsh/tier=none` and we document it as unsupported in v1.
- **Sandbox VM filesystem writability.** Whether `/opt`, `/etc/profile.d`, `/run`, `/var/log` are writable and persist is sandbox-template-dependent. Validation matrix exercises this.
- **Network access during install.** `curl` from `install` runs as root before any AgentSH proxy is up; reaching `github.com` should work but is not yet verified.
- **Sandbox kit format churn.** Docker explicitly calls the kit format experimental and subject to change. We pin to `schemaVersion: "1"` and track upstream changes via the existing release pipeline.

## 13. Out of scope, parked for later

- **LD_PRELOAD tier** — needs a new `libagentsh_preload.so` shim library. Forward-compatible tier label (`shim+ldpreload`) is reserved.
- **Ptrace tier** — needs CAP_SYS_PTRACE + `yama.ptrace_scope ≤ 1` + careful interaction with seccomp user_notif. Behind a feature flag.
- **OCI publishing** — `ghcr.io/erans/agentsh-sbx-kit:<version>`. Add when the kit stabilizes.
- **Upstream submission to `docker/sbx-kits-contrib`** — after v1 is proven stable.
- **Windows/WSL2 sandbox support** — depends on Docker Sandboxes adding Windows runtimes.
