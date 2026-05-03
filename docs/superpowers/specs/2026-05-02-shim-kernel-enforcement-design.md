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
  ├─ shim_install.mode == off?     ─→ existing agentsh-exec proxy path
  │                                    (with the existing AGENTSH_IN_SESSION
  │                                     recursion guard)
  ├─ wrap-init response has empty WrapperBinary or NotifySocket?
  │                                ─→ existing agentsh-exec proxy path
  │                                    (same in-session guard applies)
  └─ install path:
        POST /api/v1/sessions/{id}/wrap-init
            { agent_command: realShell, agent_args: shellArgs, mode: "shim" }
        receive: wrapper_binary, socket_path, env (BPF / Landlock cfg)
        set  AGENTSH_NOTIFY_SOCK_FD=<n>
        launch agentsh-unixwrap -- realShell shellArgs... as a CHILD process (runAndExit, NOT syscall.Exec)
            (unixwrap installs seccomp → SCM_RIGHTS to server → installs Landlock → execs target)
        any failure ⇒ exit 126 (fail-closed)

NOTE: AGENTSH_IN_SESSION=1 (caller-controllable env var) is NOT a
gate for the install branch — it would let a malicious sandbox-SDK
supervisor pre-set it and bypass enforcement. The existing recursion
guard in the agentsh-exec proxy path is unchanged (it prevents
infinite recursion when the agentsh server fork+execs the shim, where
the in-session signal is trustworthy because it came from the server's
own fork). For the new install branch, server-spawned shims simply
install again — wasteful (filter stacking) but safe.
```

#### Why AGENTSH_IN_SESSION does not gate the install branch

`AGENTSH_IN_SESSION=1` is set by the agentsh server before fork+exec'ing its own children, so the shim can recognize "I'm a child of the server, exec the real shell instead of proxying back through agentsh exec (deadlock guard)". That trust model is sound for the agentsh-exec proxy — recursion would actually deadlock — but the env var is caller-controllable, so a malicious supervisor running outside the agentsh server's process tree can pre-set it.

For the kernel-install branch, the legitimate "I'm in-session" case (server-spawned child) just installs again. Filter stacking is allowed; the wrapper opens a fresh notify socket; the only cost is one extra wrap-init round trip per server-spawned exec — wasteful, not unsafe. The forgery case (sandbox supervisor pre-setting the env) is closed: the shim still installs, exactly as it would for any other sibling-tree invocation.

#### Why no "already-filtered" short-circuit

An earlier draft tried to skip install for nested shim invocations (`bash -c "bash -c ..."`) by checking either an `AGENTSH_SHIM_INSTALL_DONE` env var or `/proc/self/status` Seccomp filter mode. **Neither is safe**:

- The env var is **caller-controlled**: a malicious sandbox-SDK supervisor can pre-set it on every spawned shim and bypass install entirely.
- Seccomp filter mode `2` only proves *some* seccomp filter is in place. In container environments (Docker default profile, Kubernetes runtimeClass, Podman), every process already runs under a non-agentsh seccomp filter, so `Seccomp:2` is always true — checking it would silently bypass agentsh policy in every containerized deployment.
- There is no portable, unforgeable way (without `CAP_SYS_ADMIN` for `PTRACE_SECCOMP_GET_FILTER` and a known filter hash) to prove "the active seccomp filter is *the agentsh filter*".

So the design **always installs** when `shim_install.mode != off` and wrap-init returns a populated response, regardless of `AGENTSH_IN_SESSION` (see "Why AGENTSH_IN_SESSION does not gate the install branch" above). Filter stacking up to the kernel's 64-filter limit is well within real-world nesting depths (typical workloads nest at most 2–3 levels). Per-invocation cost (~5–10 ms) is acceptable for sandbox-SDK use. Server-side per-invocation listener cleanup (described below) keeps the listener-goroutine count proportional to currently-active nesting depth, not unbounded.

#### Install/skip signal (no `install_required` field)

The protocol uses **presence of `WrapperBinary` and `NotifySocket` in the wrap-init response** as the install/skip signal. Both populated → install. Either empty → skip and fall through to the existing agentsh-exec proxy path. A boolean `install_required` field was rejected because JSON cannot distinguish `false` from "field absent on an old server", and treating an absent field as "skip" silently bypasses enforcement in mixed-version deployments. Presence-of-WrapperBinary is fail-closed: an old server returning its standard populated response triggers an install, exactly as the caller would have wanted.

Two guard rails preserve current behavior:

- `shim_install.mode=off` or wrap-init returns an empty `WrapperBinary`/`NotifySocket` — unchanged; falls into the existing `agentsh exec` proxy (which still carries the `AGENTSH_IN_SESSION=1` recursion guard).
- All other invocations install. Nested invocations — including server-spawned children — install again. That's fine: filters compose; per-invocation cost is acceptable; and `AGENTSH_IN_SESSION=1` is NOT a gate for the install branch (it is caller-controllable — see "Why AGENTSH_IN_SESSION does not gate the install branch" above).

The new branch fires when there's something to actually enforce. `AGENTSH_IN_SESSION=1` no longer gates this path — the install branch runs first.

### Server-side changes

Reuse `/api/v1/sessions/{id}/wrap-init`. Two deltas to that handler:

1. **New request field `Mode string`** (`"agent"` default, `"shim"` for the new path). Lets the server pick lifecycle policy without breaking existing callers.

2. **Per-invocation listener cleanup.** Today's `acceptNotifyFD` goroutine lives for the session — fine for `agentsh wrap` long-lived agents, leaks per-invocation in shim mode. Listener terminates on EOF of the notify_fd (kernel closes it when the wrapped process exits) when `Mode == "shim"`. Agent-mode lifecycle unchanged.

**No server-side install/skip predicate (roborev iteration 2 simplification):** An earlier draft added a `shimInstallRequired` short-circuit that returned an empty response when no enforcement was configured. That predicate could not be made complete: `mainFilterUsesUserNotify` covers notify-based configs but misses non-notify install paths (errno/kill blocked syscalls, blocked socket families with errno/kill, `block_io_uring`, the older `sandbox.unix_sockets.enabled` override). Each missed gate was a silent policy bypass. The right fix is to simplify: `wrapInitCore` now always returns the same populated response regardless of `Mode`. The install/skip decision belongs to the shim (via its `mode=auto/on/off` config). `Mode=="shim"` still governs lifecycle (Task 3: per-invocation listener cleanup).

### Client-side (shim) changes

- New package `internal/shim/kernelinstall` (Linux-only build tag): owns the auto-detect probe, the wrap-init RPC, building the unixwrap exec args, setting marker env vars, fail-closed exit handling.
- `cmd/agentsh-shell-shim/main.go`: insert the new branch **before the existing `if inSession == "1"` recursion guard** (not just before the agentsh-exec proxy — before the AGENTSH_IN_SESSION check itself). This is a security requirement: `AGENTSH_IN_SESSION` is caller-controllable, so gating the install branch on it would let a malicious sandbox-SDK supervisor bypass enforcement by pre-setting the env var. When the install path applies the shim launches `agentsh-unixwrap` as a **child process** via `runAndExit` (the same fork+wait+exit-code-propagate helper the shim already uses for the agentsh-exec proxy). NOT `syscall.Exec`: process replacement loses sandbox-SDK toolbox output capture (Daytona/E2B track the spawned PID's pipes, see the existing comment in main.go around line 235). The wrapper still execve's the user's shell; only the shim→wrapper hop is fork+wait.
- `agentsh-unixwrap` itself: zero changes. The contract it expects (env config, AGENTSH_NOTIFY_SOCK_FD, target argv) is satisfied identically by the shim and by the server's exec path.

### Config

The trusted source is `/etc/agentsh/shim.conf` (root-owned, admin-managed):

```
shim_install=auto    # auto | on | off  (default: auto)
```

Env override: `AGENTSH_SHIM_INSTALL=auto|on|off`. The env var may only **strengthen** enforcement, never weaken it — a malicious sandbox-SDK supervisor could pre-set it to bypass enforcement otherwise. The env var is honored only if it produces a stricter effective mode in the `off < auto < on` ordering.
No marker env is needed or used — install is always attempted on every invocation that meets the decision-tree criteria (see "Why no already-filtered short-circuit" above).

`auto` = "install when wrap-init returns a populated response"; `on` = "install or fail-closed"; `off` = "never install, fall back to today's behavior".

(There is intentionally NO server-side YAML config — the shim only reads `/etc/agentsh/shim.conf`. Adding a YAML field without a propagation path would be operator-confusing. A future iteration could thread a server-advised mode through the wrap-init response as a strengthen-only suggestion; deferred.)

### Failure modes

The table distinguishes two commitment points:

- **Before commit** — the shim has not yet launched the wrapper (wrap-init hasn't returned a usable response). In `auto` mode, these failures fall through silently to the existing agentsh-exec proxy path.
- **After commit** — wrap-init returned a populated response and the shim launched `agentsh-unixwrap` via `runAndExit`. The wrapper's exit code IS the shim's exit code. There is no further "fall through" path — the shim is waiting for the child wrapper to exit, and its exit code propagates directly. Both `auto` and `on` behave identically after commit.

| Situation | Commitment point | `mode=auto` | `mode=on` |
|---|---|---|---|
| Server unreachable (before wrap-init RPC) | Before commit | Fall through to agentsh-exec proxy | Fail-closed, exit 126 |
| `wrap-init` returns 5xx | Before commit | Fall through to agentsh-exec proxy | Fail-closed, exit 126 with hint |
| `wrap-init` returns empty `WrapperBinary`/`NotifySocket` | Before commit | Fall through to agentsh-exec proxy | Fall through (server signal: nothing to install) |
| `agentsh-unixwrap` not on PATH | Before commit (runAndExit fails to start) | Fail-closed, exit 126 | Fail-closed, exit 126 |
| Kernel rejects seccomp/Landlock install (ENOSYS, EPERM) | After commit (wrapper exits non-zero) | Propagate wrapper exit code (whatever `agentsh-unixwrap` returns on install failure — currently 1; the wrapper does not specifically return 126 on install rejection). | Same as `auto`. |
| Wrapper exits non-zero for any other reason | After commit | Propagate wrapper's exit code | Same as `auto`. |

**Key invariant:** once the shim commits to install (wrap-init returned a usable response and `runAndExit` was called), `mode=auto` is identical to `mode=on`. The "auto can fall through" behavior only applies before that commit point — i.e., when the server is unreachable or returns a non-usable response.

### Performance

Per-invocation cost on a path that takes the install branch:

- HTTP `wrap-init` over Unix socket — ~1–5 ms.
- Exec hop into `agentsh-unixwrap` — ~1 ms.
- seccomp install + SCM_RIGHTS handoff + Landlock install — ~100 µs each.

Total: ~5–10 ms per shim invocation. Acceptable for sandbox-SDK use. Nested invocations also pay this cost on every level — there is no safe short-circuit (see "Why no already-filtered short-circuit"). For realistic workloads (nesting depths of 2–3) the total per-pipeline cost stays in the tens of milliseconds.

If a tight `for i in $(seq 1000); do echo $i; done` loop hurts in practice, we have headroom: cache the wrap-init response in the shim process keyed by `(session_id, command_class)`. Out of scope for the initial cut.

### Testing

- **Unit tests:** `internal/shim/kernelinstall` decision tree with mocked wrap-init responses; covers each branch of the decision diagram and each failure mode in the table.
- **Integration tests:** extend the `seccomp_wrapper_test.go` family. New scenarios spawn a process tree that's a *sibling* of the agentsh server (mirroring the sandbox-SDK case) and assert reads of a tempdir-based deny target return non-zero with no leaked content; assert `connect()` to a denied address fails; assert nested `bash -c 'bash -c cat <denyfile>'` installs filters at BOTH levels (filter stacking) AND that the inner shell's read remains blocked. Nested installs are expected — there is no safe "already-filtered" signal, so the design installs on every level.
- **End-to-end repro:** new `Dockerfile.shim-install-test` mirroring `agentsh-tensorlake`'s setup; CI runs Eran's repro grid and asserts every red row turns green.
- **Regression:** the existing `agentsh wrap` path tests must continue to pass unchanged — Mode defaults to `"agent"`, the server's existing lifecycle behavior applies.

## Open issues called out in the spec

- **Wrap-init listener lifecycle change** is the riskiest server-side delta (per-exec goroutines instead of session-scoped). Needs explicit teardown test asserting no goroutine leak after 1000 shim invocations against the same session.
- **Per-invocation cost** (~5–10 ms/exec) — measured at design time, validate at implementation time. Cache strategy on hand if needed.
- **Direct SDK exec** (sb.exec without bash) — documented gap, not solved here. Track separately.
- **Daytona / Fargate restricted environments** — not addressed in this design. The verified failure mode in these environments is that `seccomp(SET_MODE_FILTER, NEW_LISTENER)` is rejected by the active kernel security policy (the precise cause varies — no_new_privs is one common factor on processes lacking `CAP_SYS_ADMIN`; other container LSM/seccomp profiles can also block the call). The shim will launch `agentsh-unixwrap` via `runAndExit`, the wrapper's seccomp install will fail, and the wrapper exits non-zero. Because the shim has already committed to install at this point (wrap-init returned a usable response and `runAndExit` was called), **both `mode=auto` and `mode=on` propagate the wrapper's exit code** — there is no silent skip or fall-through in either mode. Closing this gap properly requires either an environment-side change (operator adjusts the container security profile) or a separate enforcement path; ptrace-pid mode (#269) remains the recommendation on these environments.

## Sequencing

Per #268's "Sequencing relative to #267": both ship together as a single feature. The `auto` mode's fallback chain is what wires them into a hierarchy — server-side wrap-init builds whichever combination the kernel supports, the shim doesn't need to know which mechanism is active.

Order of operations after this design lands:

1. Server-side wrap-init `Mode` parameter + per-invocation listener cleanup. No server-side install/skip predicate — the shim's mode=auto/on/off config governs that decision.
2. `internal/shim/kernelinstall` package + decision-tree wiring in `cmd/agentsh-shell-shim/main.go`.
3. Integration tests (sibling-process tree).
4. End-to-end repro Dockerfile.
5. Doc update for `shim_install=auto|on|off` in `/etc/agentsh/shim.conf`.
