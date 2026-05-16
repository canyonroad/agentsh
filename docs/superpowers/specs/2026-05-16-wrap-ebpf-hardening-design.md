# Wrap eBPF Hardening - Design Spec

**Date:** 2026-05-16
**Status:** Approved
**Author:** design session between Eran Sandler and Codex

## Problem

Issue #343 reports that domain-based `network_rules` can be bypassed under
`agentsh wrap` when a wrapped process or subprocess removes `HTTP_PROXY`,
`HTTPS_PROXY`, or related proxy environment variables.

The report is directionally correct, and the local code shows the gap is
broader than child env stripping:

- `agentsh exec` injects the session network proxy into command env.
- `agentsh wrap` only injects LLM base URLs and does not inject the session
  network proxy env.
- eBPF network enforcement is attached through the exec cgroup hook.
- the Linux wrap path starts the seccomp notify handler but never moves the
  wrapped agent tree into a cgroup with eBPF attached.

As a result, a direct network connection from a wrapped process may bypass the
proxy and avoid domain-based policy evaluation. CIDR and port rules remain
enforceable only through mechanisms that see the final IP/port.

## Goal

Make `agentsh wrap` use the same two-layer network posture as `agentsh exec`
for this issue:

1. normal HTTP clients receive the session network proxy env; and
2. the wrapped agent process tree is attached to cgroup/eBPF before the real
   agent is allowed to exec.

This should close the proxy-env bypass for `agentsh wrap` without adding DNS
syscall parsing in this change.

## Non-Goals

- Do not implement DNS packet parsing or DNS syscall interception.
- Do not implement native domain matching inside the BPF program.
- Do not change the policy language.
- Do not redesign the LLM proxy env behavior.
- Do not change macOS or Windows wrap behavior beyond preserving existing
  build compatibility.

## Current Architecture

### Exec path

`internal/api/exec.go` builds the command env with `buildPolicyEnv`. When
`Session.ProxyURL()` is present, it sets:

- `HTTP_PROXY`
- `HTTPS_PROXY`
- `ALL_PROXY`
- `http_proxy`
- `https_proxy`
- `all_proxy`
- `NO_PROXY`
- `no_proxy`

The exec path also calls `a.cgroupHook(...)`, which delegates to
`applyCgroupV2`. That function creates a per-command cgroup and, when
configured, attaches the existing cgroup eBPF connect/sendmsg programs.

### Wrap path

`internal/cli/wrap.go` fetches or creates a session and keeps
`sess.LLMProxyURL`, but does not keep or apply `sess.ProxyURL`.

On Linux, `internal/cli/wrap_linux.go` starts `agentsh-unixwrap`, passes it a
socketpair, and starts a `postStart` goroutine. The wrapper installs seccomp
notify, sends the notify fd to the CLI over the socketpair, and then waits for
an ACK from the CLI before execing the real agent.

The CLI forwards the notify fd to the server over the `wrap-init` Unix socket.
The server receives the fd in `internal/api/wrap.go` and starts
`startNotifyHandlerForWrap`. Today the server sees the CLI process as the Unix
socket peer, not the wrapper child PID, so it cannot attach the correct process
to a cgroup.

## Recommended Design

### 1. Inject network proxy env in `agentsh wrap`

Extend the wrap env construction so the CLI keeps `sess.ProxyURL` and appends
the same network proxy variables that `agentsh exec` uses.

The env helper should be local to the CLI package unless a clean shared helper
already exists at implementation time. It should:

- remove stale proxy keys from the inherited environment before appending
  session-controlled values;
- set uppercase and lowercase proxy variables to `sess.ProxyURL`;
- preserve existing `NO_PROXY` / `no_proxy` values where possible;
- ensure `localhost,127.0.0.1` are present in both `NO_PROXY` and `no_proxy`;
- keep LLM proxy env handling separate from network proxy env handling.

This layer is for compatibility and observability. It is not treated as the
security boundary.

### 2. Add a server-acknowledged notify-fd handshake

Change the Linux notify-fd forwarding protocol between the CLI and server.

The CLI should send the seccomp notify fd together with metadata containing the
`agentsh-unixwrap` child PID. After sending, the CLI must wait for a one-byte
server response:

- `1`: server finished pre-ACK setup and started the notify handler;
- `0`: server rejected setup.

Only after receiving `1` may the CLI ACK `agentsh-unixwrap`. If the server
rejects setup or the response is missing, the CLI must not ACK the wrapper.
The wrapper will fail before execing the real agent, which is the desired
fail-closed behavior for this setup phase.

The protocol should remain compatible with existing shim forwarding paths:

- if no metadata is present, the server may continue without wrap eBPF attach
  when eBPF is disabled;
- if cgroup/eBPF attach is required but no wrapper PID is provided, the server
  should reject setup before the wrapper ACK.

### 3. Attach cgroup/eBPF before wrapper ACK

After the server receives the notify fd and wrapper PID, it should apply the
existing cgroup/eBPF setup to the wrapper PID before it tells the CLI to ACK
the wrapper.

The server-side order should be:

1. receive notify fd and metadata;
2. validate wrapper PID is positive;
3. create a per-wrap command ID, such as `wrap-<short-uuid>`;
4. apply the cgroup/eBPF hook to the wrapper PID;
5. start the seccomp notify handler;
6. write success to the CLI connection;
7. clean up the cgroup/eBPF resources when the notify handler exits.

Because `agentsh-unixwrap` waits for the CLI ACK before execing the real agent,
this avoids a window where the agent could connect before eBPF is attached.
Child processes inherit the wrapper's cgroup, so the whole wrapped process tree
is covered.

### 4. Make eBPF-enabled cgroup creation explicit

`applyCgroupV2` currently treats empty resource limits as a reason to skip
cgroup creation when cgroup enforcement is unavailable. That is acceptable for
pure resource limits but not for eBPF, because eBPF attach requires a cgroup
even when memory/CPU/PID limits are zero.

Update this path so `sandbox.network.ebpf.enabled=true` is considered a reason
to require a concrete cgroup. If cgroups are unavailable and eBPF is required,
the caller should fail closed. If eBPF is merely enabled but not required, the
current non-required behavior may continue to degrade with an event, but it
must not silently imply that wrap is protected.

This change benefits both `exec` and `wrap` and prevents false-positive eBPF
configuration.

### 5. Keep failure semantics explicit

For `agentsh wrap`:

- if cgroups/eBPF are disabled, existing wrap behavior continues plus proxy env
  injection when `ProxyURL` is set;
- if eBPF attach succeeds, the wrapper is ACKed and the agent starts;
- if eBPF is required and attach fails, the server rejects the setup and the
  wrapper is not ACKed;
- if cgroups are unavailable and eBPF is required, the wrapper is not ACKed;
- if cgroups/eBPF are optional and attach fails, emit the same style of
  `ebpf_unavailable` or `ebpf_attach_failed` event used by exec and continue
  only when the existing config semantics allow it.

## Domain Enforcement Notes

This design does not make BPF match domain strings. The current BPF program
sees IP address, port, protocol, and cgroup ID. Domain-based rules are mapped
to IP/port entries by resolving literal domains in userspace and refreshing
those entries on a configured interval.

That means:

- literal domain rules can be enforced as resolved IP/port maps;
- wildcard domains remain non-strict;
- shared CDN IPs and fast-changing DNS still have the usual IP-mapping caveats;
- DNS-over-HTTPS, DNS-over-TLS, `/etc/hosts`, cached results, and hardcoded IPs
  are not solved by DNS syscall interception in this change.

The reason this still fixes #343 is that a process which strips proxy env no
longer gets an unmonitored direct connect path under `agentsh wrap`; eBPF sees
the final connect attempt from the wrapped cgroup.

## Files Expected To Change

- `internal/cli/wrap.go`
  - keep `sess.ProxyURL`;
  - append network proxy env for wrapped agents.

- `internal/cli/wrap_linux.go`
  - send wrapper PID metadata with the notify fd;
  - wait for server success before ACKing `agentsh-unixwrap`.

- `internal/shim/kernelinstall/install_linux.go`
  - preserve compatibility with the server's notify handshake, or update the
    shim relay to send equivalent PID metadata when feasible.

- `internal/api/wrap.go`
  - receive notify fd metadata;
  - reject required eBPF setup when no wrapper PID is available;
  - coordinate server response to the CLI.

- `internal/api/wrap_linux.go`
  - apply cgroup/eBPF setup to the wrapper PID before starting the notify
    handler or before acknowledging success;
  - clean up cgroup/eBPF resources when the notify handler exits.

- `internal/api/cgroups.go`
  - treat eBPF-enabled setup as requiring a concrete cgroup, not only resource
    limits.

- Tests under `internal/cli`, `internal/api`, and `internal/shim/kernelinstall`.

- Docs under `docs/ebpf.md` or `docs/security-modes.md`.

## Test Strategy

### Unit tests

- `internal/cli`
  - `buildWrapEnv` or the new helper adds network proxy env from `ProxyURL`.
  - inherited stale proxy env is replaced by the session proxy.
  - existing `NO_PROXY` is preserved and extended with localhost entries.
  - LLM proxy env remains separate from network proxy env.
  - Linux notify forwarding waits for server success before wrapper ACK.
  - Linux notify forwarding returns an error on server rejection.

- `internal/api`
  - notify fd receiver parses wrapper PID metadata.
  - missing PID is accepted only when cgroup/eBPF setup is not required.
  - required eBPF with missing PID rejects setup.
  - cgroup/eBPF setup is called with the wrapper PID before success is written.
  - cleanup returned by the cgroup/eBPF setup runs when the notify handler
    exits.
  - `applyCgroupV2` requires a concrete cgroup when eBPF is enabled.

- `internal/shim/kernelinstall`
  - relay forwarding remains compatible with the server handshake.

### Integration or best-effort tests

Where the environment supports cgroup v2 and eBPF:

- run a wrapped process that strips proxy env and attempts a direct TCP
  connection;
- verify a `net_connect` or blocked event is emitted from eBPF;
- verify the connection is denied when policy-derived BPF maps deny it.

These tests should skip when eBPF or writable cgroups are unavailable.

## Rollout

This is a Linux-only hardening change for the wrap path. Non-Linux builds must
continue to compile with stubs unchanged.

The safest rollout sequence is:

1. add proxy env injection tests and implementation;
2. add the server-acknowledged notify-fd protocol tests and implementation;
3. add cgroup/eBPF pre-ACK attach tests and implementation;
4. tighten `applyCgroupV2` behavior for eBPF-enabled setup;
5. add docs and best-effort integration coverage.

Each step can be committed independently.

## Open Constraints

- The implementation must not rely on `/tmp`; use `os.TempDir()` or existing
  helpers for temporary paths.
- Path construction must use `filepath.Join`.
- Windows and macOS builds must remain green.
- The server must not trust the Unix socket peer PID for the wrapper PID,
  because the peer is the CLI relay process.
- The CLI must not ACK `agentsh-unixwrap` until the server has completed the
  cgroup/eBPF setup decision.

## Alternatives Considered

### Proxy env only

Rejected as the complete fix. It improves normal client behavior but remains
bypassable by clearing env.

### eBPF/cgroup only

Rejected as the complete fix. It provides the hard enforcement layer but misses
the compatibility and observability benefits of proxy env injection for normal
HTTP clients.

### DNS syscall interception in this change

Rejected for this issue scope. DNS syscall interception helps attribution and
can improve domain policy behavior for normal UDP DNS, but it does not close
hardcoded-IP, cached-DNS, DoH, DoT, or hosts-file paths. The security boundary
for this fix should be final connect enforcement via cgroup/eBPF.

## Self-Review

- The design covers the accepted scope: proxy env injection plus cgroup/eBPF
  attachment for `agentsh wrap`.
- It explicitly excludes DNS syscall interception.
- It defines the required ordering to avoid the pre-exec race.
- It identifies the important compatibility risk with shim forwarding.
- It calls out the existing `applyCgroupV2` empty-limits behavior that could
  otherwise make eBPF appear enabled without a concrete cgroup.
