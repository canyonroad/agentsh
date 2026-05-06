# Sandbox SDK integrations (Tensorlake / E2B / Modal / Daytona)

When agentsh runs as a service that supervises commands spawned by a sandbox SDK,
the spawned commands are siblings of the agentsh server, not descendants. Kernel
filters loaded on the agentsh server's process (Landlock, seccomp-notify) do not
govern those sibling processes. The `shim_install` feature closes that gap: the
shell shim installs the same filters on its own process before exec'ing the user's
command, so the inherited filter follows the command into whatever process tree the
SDK created.

## The problem

Sandbox SDKs such as Tensorlake, E2B, Modal, and Daytona spawn agent commands
directly — typically via a container exec or a remote shell API call. The spawned
shell is a sibling of the agentsh server process, not a child. Because Linux
Landlock and seccomp-notify filters are inherited only down the fork/exec chain,
none of the file, network, or signal rules configured in the agentsh session apply
to those commands. An agent running in this pattern has no kernel-enforced policy
at all.

## The fix

The agentsh shell shim (`agentsh-shell-shim`) intercepts every command invocation.
With `shim_install` enabled, the shim calls the agentsh server's `wrap-init`
endpoint before exec'ing the user's shell, installs the session's Landlock and
seccomp filters on its own process, and then hands control to the user's command.
Because the filters are installed before `execve`, the user's command inherits them
regardless of which process tree it is in.

This reuses the existing `agentsh-unixwrap` machinery. No new kernel interfaces are
required. For the full design, see
`docs/superpowers/specs/2026-05-02-shim-kernel-enforcement-design.md`.

## Configuration

The trusted source is `/etc/agentsh/shim.conf` (root-owned, admin-managed):

```
shim_install=auto    # auto | on | off  (default: auto)
```

| Value | Behavior |
|-------|----------|
| `auto` | Shim calls wrap-init and installs when the server returns a populated wrapper response. Falls through to the existing agentsh-exec proxy only when wrap-init itself fails (server unreachable, 5xx, network error) — not after the wrapper has launched. |
| `on` | Shim must install. Any wrap-init failure or empty response exits 126 with a hint pointing to this doc. |
| `off` | Shim never attempts install. Equivalent to pre-#267 behavior. |

Once the shim has launched `agentsh-unixwrap` as a child, the wrapper's exit code
is terminal in both `auto` and `on` mode — there is no fall-through after that point.

**Environment variable override:** `AGENTSH_SHIM_INSTALL=auto|on|off`

The env var may only **strengthen** enforcement, never weaken it. If the env var
would produce a weaker mode than `/etc/agentsh/shim.conf` (e.g., config says `on`
and env says `off`), the env var is silently ignored and the config wins. This
prevents a malicious sandbox-SDK supervisor from pre-setting the env var to bypass
enforcement.

## What happens per shim invocation

**Decision tree:**

```
shim_install=off?  →  skip (fall through to agentsh-exec proxy)
     ↓
Call wrap-init
     ↓
wrap-init error?
  mode=auto  →  skip (server unreachable / 5xx)
  mode=on    →  exit 126 with hint
     ↓
WrapperBinary or NotifySocket empty?
  mode=auto  →  skip
  mode=on    →  exit 126 (empty response treated as failure)
     ↓
Install proceeds (relay + exec)
```

**Relay protocol:**

1. Shim calls `wrap-init` and receives `WrapperBinary` + `NotifySocket` path.
2. Shim creates an AF_UNIX SOCK_SEQPACKET socketpair. Parent end stays in the shim;
   child end becomes fd 3 in the wrapper.
3. Sets `AGENTSH_NOTIFY_SOCK_FD=3` in the wrapper environment.
4. Launches `agentsh-unixwrap` as a **child process** (not `syscall.Exec`). The
   shim stays alive as the parent so sandbox toolboxes that track the spawned PID's
   output do not lose it.
5. Shim acts as relay: receives the seccomp notify fd from the wrapper via
   SCM_RIGHTS on the parent socketpair end, dials the server's NotifySocket,
   forwards the notify fd, then sends the ACK byte back through the socketpair.
   The wrapper's `waitForACK` unblocks.
6. `agentsh-unixwrap` applies Landlock, then exec's the user's shell.
7. The user's command runs under both filters. The shim waits for the wrapper child
   to exit and propagates its exit code via `os.Exit`.

Nested shim invocations (`bash -c "bash -c ..."`) used to install at every level
and rely on filter stacking up to the kernel's 64-filter limit. As of v0.19.2
(#288), the shim's kernelinstall path consults `/proc/self/status`
`Seccomp_filters:` and **skips wrap-init when a filter has already been inherited
from an ancestor** — that count is kernel-maintained and unforgeable from
userland, unlike env-var markers. The first invocation in a session installs;
nested shells inherit and short-circuit. This avoids the stacking failure mode
that surfaced as masked `ECANCELED` (real `EFAULT`) on Runloop devboxes (#282).
Env-var markers are still not used; the kernel-side filter count is the
authority.

## Limitations

- **Signal filter rules not enforced in shim mode.** When the session has
  signal-filter rules enabled, `WrapperEnv` includes `AGENTSH_SIGNAL_SOCK_FD=4`.
  The shim does not open `SignalSocket` or pass an inherited fd 4, so the shim
  strips `AGENTSH_SIGNAL_SOCK_FD` from the wrapper environment. Signal-rule
  enforcement remains a server-spawned-only feature until a future iteration extends
  the relay to handle the second socketpair. Operators relying on signal rules must
  use the server-spawned path.

- **Direct SDK exec without bash bypasses the shim.** Calls of the form
  `sb.exec("cat", [...])` that invoke the binary directly (without going through the
  shell shim) are not intercepted. The fix on that path is to integrate the SDK with
  `agentsh exec` directly. Tracked as a separate concern.

- **Restricted seccomp environments (Daytona, Fargate, some container LSM
  profiles).** These environments set `no_new_privs` or restrict `prctl`, causing
  the wrapper's seccomp install to fail with EPERM. Once the shim has committed to
  install (wrap-init returned a usable response and the wrapper was launched), the
  wrapper exits non-zero and the shim propagates that exit code as-is in both
  `mode=auto` and `mode=on` — there is no silent skip. The current
  `agentsh-unixwrap` exits with status `1` on install failure (not 126); the shim
  faithfully relays that. To avoid breakage on these environments, set
  `shim_install=off` in `/etc/agentsh/shim.conf` and use ptrace-pid mode (#269)
  instead.

- **Per-invocation cost ~5–10 ms** (HTTP wrap-init round trip + exec hop + filter
  install). Acceptable for sandbox-SDK use cases; not recommended for workloads that
  fork thousands of short-lived commands per second.

## See also

- Issue #267: sandbox-SDK sibling-process-tree enforcement gap
- Issue #268: shim_install design and implementation tracking
- Issue #282: nested-shim filter stacking failure on Runloop, fixed by the
  `/proc/self/status` short-circuit in #288 (v0.19.2)
- Issue #283: unixwrap pre-resolves the command path before installing the
  seccomp filter so `exec.LookPath` probes are not intercepted by the
  file-monitor handler (v0.19.2)
- Design spec: `docs/superpowers/specs/2026-05-02-shim-kernel-enforcement-design.md`
