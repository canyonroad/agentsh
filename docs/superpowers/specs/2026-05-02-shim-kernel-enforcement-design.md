# Shim-installed kernel enforcement (#267 + #268)

**Status:** Design — awaiting review
**Issues:** [#267](https://github.com/agentsh/agentsh/issues/267) (shim-loaded Landlock), [#268](https://github.com/agentsh/agentsh/issues/268) (shim-installed seccomp-notify)
**Author:** Eran Sandler
**Date:** 2026-05-02

## Problem

agentsh's file/network/signal policy is enforced by kernel hooks (Landlock, seccomp-notify, FUSE) that are loaded **on the agentsh server's process** and inherited by its children. When commands are spawned by an external supervisor — every sandbox-SDK integration pattern (Tensorlake, E2B, Modal, Daytona, Blaxel) — the target binary is a sibling of agentsh, not a descendant, and the kernel filters never govern it.

Today's repro inside an `agentsh-tensorlake` microVM (file: `agentsh-tensorlake/DETECT.md`):

```
[TEST] sudo whoami                         exit=126 ✅ blocked by command rule
[TEST] kill -9 1                           exit=126 ✅ blocked by command rule
[TEST] curl evil.com                       exit=6   ✅ blocked at DNS
[TEST] cat /etc/shadow                     exit=0   ❌ root:$y$j9T$..ACagKD…
[TEST] touch /etc/x                        exit=0   ❌ file created
[TEST] cp /etc/hosts /etc/hosts_copy       exit=0   ❌ file created
[TEST] ln -s /etc/shadow /tmp/x; cat /tmp/x  exit=0 ❌ shadow contents printed
```

Command-policy works (the shim catches it). File-policy doesn't (the shim is in the wrong process tree for kernel filters).

ptrace-pid mode (#269) is the only currently-shipping mitigation. Its costs (single-tracer kernel limit, supervisor-PID staleness, multi-thread/clone edge cases) are real and called out in #268.

## Goals

- Close file/network/signal policy enforcement when commands are spawned outside agentsh server's process tree.
- Reuse the existing `agentsh-unixwrap` + `/wrap-init` machinery instead of building a parallel install path.
- Single fallback chain: seccomp-notify → Landlock-only → no-op (today).
- Default-on behavior with one operator override for incident rollback.
- Fail-closed by default.

## Non-goals

- SDK calls that bypass any shell shim entirely (`sb.exec("cat", ["/etc/shadow"])`). Documented gap; needs SDK-side `agentsh exec` integration. Tradeoff (B) in #267.
- Daytona / Fargate (no-new-privs blocked). ptrace-pid mode (#269) remains the fallback on those environments and is not regressed.
- Restructuring `agentsh-unixwrap` itself. The wrapper's contract is satisfied identically by the shim and the server's exec path; treat it as a black box.

## Architecture

### Per-shim-invocation decision tree

```
shim invoked
  ├─ AGENTSH_IN_SESSION=1?         ─→ exec real shell      (existing recursion guard)
  ├─ already-filtered (kernel proof, see below)?
  │                                ─→ exec real shell      (filter inherited from outer shim)
  ├─ shim_install.mode == off?     ─→ existing agentsh-exec proxy path
  ├─ wrap-init response has empty WrapperBinary or NotifySocket?
  │                                ─→ existing agentsh-exec proxy path
  └─ install path:
        POST /api/v1/sessions/{id}/wrap-init
            { agent_command: realShell, agent_args: shellArgs, mode: "shim" }
        receive: wrapper_binary, socket_path, env (BPF / Landlock cfg)
        set  AGENTSH_SHIM_INSTALL_DONE=1, AGENTSH_NOTIFY_SOCK_FD=<n>
        execve agentsh-unixwrap -- realShell shellArgs...
            (unixwrap installs seccomp → SCM_RIGHTS to server → installs Landlock → execs target)
        any failure ⇒ exit 126 (fail-closed)
```

#### Already-filtered detection (unforgeable, defense in depth)

A naive `AGENTSH_SHIM_INSTALL_DONE=1` env-var marker is **caller-controlled** and would let a malicious caller pre-set the env to skip the install path. The "already-filtered" decision MUST be backed by an unforgeable kernel-state check:

- **Seccomp present:** read `/proc/self/status`. If the `Seccomp:` field reports value `2` (filter mode), our outer shim — or some other party — has installed a filter. When the caller is a nested invocation under our outer shim, this is the proof. False positives (non-agentsh seccomp filters in the environment) are tolerable — installing again would either succeed (stacking is allowed) or fail in unixwrap, where we fail-closed.
- **Landlock-only mode:** there's no kernel-side query for active Landlock rulesets. The env-var marker is kept as a *secondary* signal for this case, but it is treated as a **hint**, not authority: if the marker is set but `/proc/self/status` does not show Seccomp filter mode, the shim still consults `wrap-init`. If the server says install is required, we install on top — Landlock rulesets compose safely.

Net effect: `AGENTSH_SHIM_INSTALL_DONE=1` only short-circuits when the kernel can prove a filter is in place. Forging the env var without a real filter does not bypass enforcement.

#### Install/skip signal (no `install_required` field)

The protocol uses **presence of `WrapperBinary` and `NotifySocket` in the wrap-init response** as the install/skip signal. Both populated → install. Either empty → skip and fall through to the existing agentsh-exec proxy path. A boolean `install_required` field was rejected because JSON cannot distinguish `false` from "field absent on an old server", and treating an absent field as "skip" silently bypasses enforcement in mixed-version deployments. Presence-of-WrapperBinary is fail-closed: an old server returning its standard populated response triggers an install, exactly as the caller would have wanted.

Three guard rails preserve current behavior:

- `AGENTSH_IN_SESSION=1` (server-spawned children) — unchanged.
- Already-filtered detection (nested shim) — unchanged; no double-install, no filter stacking against the kernel's 64-filter limit.
- `shim_install.mode=off` or wrap-init returns an empty `WrapperBinary`/`NotifySocket` — unchanged; falls into the existing `agentsh exec` proxy.

The new branch only fires when there's something to actually enforce **and** we are outside the server's process tree.

### Server-side changes

Reuse `/api/v1/sessions/{id}/wrap-init`. Three deltas to that handler:

1. **New request field `Mode string`** (`"agent"` default, `"shim"` for the new path). Lets the server pick lifecycle policy without breaking existing callers.

2. **Per-invocation listener cleanup.** Today's `acceptNotifyFD` goroutine lives for the session — fine for `agentsh wrap` long-lived agents, leaks per-invocation in shim mode. Listener terminates on EOF of the notify_fd (kernel closes it when the wrapped process exits) when `Mode == "shim"`. Agent-mode lifecycle unchanged.

3. **Auto-detect short-circuit.** When the request comes in with `Mode == "shim"`, server inspects its own enabled features (`unix_sockets.enabled`, `landlock.enabled`, kernel probe cached at server start) and returns an empty response (no `WrapperBinary`, no `NotifySocket`) if nothing is configured. Shim sees the empty fields and takes the no-op branch without doing any kernel setup.

### Client-side (shim) changes

- New package `internal/shim/kernelinstall` (Linux-only build tag): owns the auto-detect probe, the wrap-init RPC, building the unixwrap exec args, setting marker env vars, fail-closed exit handling.
- `cmd/agentsh-shell-shim/main.go`: insert the new branch *before* the existing `agentsh exec` proxy path (around line 225). When the install path applies the shim execve's `agentsh-unixwrap` directly — *not* `agentsh exec`. Intentional: we want the inherited filter to govern the user's shell, not a Go process that's about to exit.
- `agentsh-unixwrap` itself: zero changes. The contract it expects (env config, AGENTSH_NOTIFY_SOCK_FD, target argv) is satisfied identically by the shim and by the server's exec path.

### Config

```yaml
sandbox:
  shim_install:
    mode: auto    # auto | on | off  (default: auto)
```

Env override: `AGENTSH_SHIM_INSTALL=auto|on|off`.
Marker env (set by shim before execve, recognized by nested shims): `AGENTSH_SHIM_INSTALL_DONE=1`.

`auto` = "install when there's something to install and the kernel supports it"; `on` = "install or fail-closed"; `off` = "never install, fall back to today's behavior".

### Failure modes

| Situation | Behavior |
|---|---|
| Server unreachable | Existing ready_gate behavior (local: fall through to real shell; remote: fail-closed). No new code path. |
| `wrap-init` returns 5xx | Fail-closed, exit 126 with hint mentioning `shim_install.mode=off`. |
| `wrap-init` returns empty `WrapperBinary`/`NotifySocket` | Fall through to existing agentsh-exec proxy path. |
| `agentsh-unixwrap` not on PATH | Fail-closed in `mode=on`; in `mode=auto` server already detects this and returns an empty `WrapperBinary`. |
| Kernel rejects seccomp/landlock install (ENOSYS, EPERM) | unixwrap exits non-zero; shim exits 126; audit event emitted. |

### Performance

Per-invocation cost on a path that takes the install branch:

- HTTP `wrap-init` over Unix socket — ~1–5 ms.
- Exec hop into `agentsh-unixwrap` — ~1 ms.
- seccomp install + SCM_RIGHTS handoff + Landlock install — ~100 µs each.

Total: ~5–10 ms per shim invocation. Acceptable for sandbox-SDK use. Nested shim invocations (skipped via `AGENTSH_SHIM_INSTALL_DONE`) cost only the env-var check.

If a tight `for i in $(seq 1000); do echo $i; done` loop hurts in practice, we have headroom: cache the wrap-init response in the shim process keyed by `(session_id, command_class)`. Out of scope for the initial cut.

### Testing

- **Unit tests:** `internal/shim/kernelinstall` decision tree with mocked wrap-init responses; covers each branch of the decision diagram and each failure mode in the table.
- **Integration tests:** extend the `seccomp_wrapper_test.go` family. New scenarios spawn a process tree that's a *sibling* of the agentsh server (mirroring the sandbox-SDK case) and assert `cat /etc/shadow` exits non-zero; assert `connect()` to a denied address fails; assert nested `bash -c 'bash -c whoami'` doesn't double-install.
- **End-to-end repro:** new `Dockerfile.shim-install-test` mirroring `agentsh-tensorlake`'s setup; CI runs Eran's repro grid and asserts every red row turns green.
- **Regression:** the existing `agentsh wrap` path tests must continue to pass unchanged — Mode defaults to `"agent"`, the server's existing lifecycle behavior applies.

## Open issues called out in the spec

- **Wrap-init listener lifecycle change** is the riskiest server-side delta (per-exec goroutines instead of session-scoped). Needs explicit teardown test asserting no goroutine leak after 1000 shim invocations against the same session.
- **Per-invocation cost** (~5–10 ms/exec) — measured at design time, validate at implementation time. Cache strategy on hand if needed.
- **Direct SDK exec** (sb.exec without bash) — documented gap, not solved here. Track separately.
- **Daytona / Fargate (no-new-privs)** — not addressed. `mode=auto` detects this via the server-side kernel probe and returns an empty `WrapperBinary` (so the shim short-circuits); ptrace-pid mode stays as the enforcement path on those environments.

## Sequencing

Per #268's "Sequencing relative to #267": both ship together as a single feature. The `auto` mode's fallback chain is what wires them into a hierarchy — server-side wrap-init builds whichever combination the kernel supports, the shim doesn't need to know which mechanism is active.

Order of operations after this design lands:

1. Server-side wrap-init `Mode` parameter + per-invocation listener cleanup + empty-`WrapperBinary` short-circuit when nothing is enabled.
2. `internal/shim/kernelinstall` package + decision-tree wiring in `cmd/agentsh-shell-shim/main.go`.
3. Integration tests (sibling-process tree).
4. End-to-end repro Dockerfile.
5. Doc update for `sandbox.shim_install.mode`.
