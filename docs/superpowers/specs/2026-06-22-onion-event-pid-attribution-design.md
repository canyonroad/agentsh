# Onion / Connection-Vector Event PID Attribution — Design

**Status:** Implemented (PR pending)

**Builds on:** [Tor Access Control — Design](2026-06-14-tor-access-control-design.md)
(Phase 1 deny/audit, PR #424; Phase 2 onion gateway, PR #428), [Phase 3 —
fail-open gap closed](2026-06-20-tor-access-control-phase3-design.md) (PR #429),
and [Phase 4 — SOCKS RESOLVE](2026-06-22-tor-access-control-phase4-design.md)
(PR #430). This is the "PID/command attribution" item carried forward as
out-of-scope by every prior phase.

## Summary

Four `tor_control` events emitted from the transparent-interception layer carry
`pid: 0`: `onion_dns`, `onion_http`, the Phase-2 `onion` SOCKS gateway, and the
`relay_ip` / `socks_port` transparent-TCP vector. This change replaces that
hardcoded zero with the session's current command-process PID, which the session
already tracks and exposes. It adds **no new event type, config knob, or data
path** — it passes a value that already exists into a builder parameter that
already exists.

## Motivation

The framing "these events report `target` only" is pessimistic. Every one of
these events already carries a correct `sessionID` **and** `commandID` — the
interceptors read `sess.CurrentCommandID()` at emission time, the same source the
normal `dns_query` / `net_connect` events use. The single field hardcoded to a
placeholder is the numeric `pid`:

```go
tor.BuildControlEvent(d.sessionID, commandID, 0, …)   // dns.go
```

The ptrace-path Tor events (`ptrace_handlers.go`) carry a real PID because ptrace
fires synchronously in the offending syscall's context (`nc.PID`). The
transparent-interception-path events do not, only because the emission sites
never read the PID the session already holds. Supplying it lets the two event
families line up on a common `pid` key for cross-referencing.

## Scope decisions (locked)

- **All four interception-path sites, not just the two named.** The backlog item
  named `onion_dns` / `onion_http`, but the identical `pid: 0` placeholder
  appears at all four sites below. The fix is the same value at each; leaving two
  still emitting `pid: 0` would make the audit log inconsistent. Fix all four.

  | Vector | Emission site |
  |---|---|
  | `onion_dns` | `internal/netmonitor/dns.go` (`BuildControlEvent(…, 0, …)`) |
  | `onion_http` | `internal/netmonitor/proxy.go` (`BuildControlEvent(…, 0, …)`) |
  | `onion` (SOCKS gateway) | `internal/netmonitor/socks.go` (`emitOnionEvent` → `BuildControlEvent(…, 0, …)`) |
  | `relay_ip` / `socks_port` | `internal/netmonitor/transparent_tcp.go` (`BuildControlEvent(…, 0, …)`) |

- **Mechanism: thread `sess.CurrentProcessPID()`.** The session already exposes
  `Session.CurrentProcessPID()` (`internal/api/manager.go`), written by the exec
  handlers when a command process starts, alongside the `CurrentCommandID()` the
  events already use. The interceptors simply read it and pass it where they
  currently pass `0`.

- **Rejected: eBPF connect-time PID cross-referencing.** Recovering the *exact
  leaf* process that emitted the traffic would require a new BPF hash keyed on the
  connection tuple, populated by the existing `connect()` hooks, cross-referenced
  synchronously from the interceptor goroutines. It is TCP-only (does not cover
  the UDP DNS path at all), Linux-only, and substantial new plumbing — over-built
  for an audit-fidelity improvement. Not in scope.

- **No new config knobs / event type / data path.** `types.Event.PID` and
  `BuildControlEvent(sessionID, commandID string, pid int, v Verdict)` already
  exist; the OCSF registry is untouched (consistent with Phases 2–4).

## Architecture: pass the value that already exists

Three of the four sites have the `Session` in scope and call `BuildControlEvent`
directly — a one-line change each, `0` → `sess.CurrentProcessPID()`:

- `dns.go` — `d.sess.CurrentProcessPID()`
- `proxy.go` — `p.sess.CurrentProcessPID()`
- `transparent_tcp.go` — the `relay_ip` / `socks_port` event, `t`-receiver's
  session (the same `sess` already used for `CurrentCommandID()` at this site).

The SOCKS gateway path is one chain deeper. `emitOnionEvent` is called from
`gatewayConnect` / `gatewayResolve`, which are invoked by `handleTorSocks`, which
is called from `transparent_tcp.go` — where the `Session` **is** in scope and
`commandID` is already read via `CurrentCommandID()`. So read
`CurrentProcessPID()` at that same call site and thread a `pid int` parameter
down the existing chain alongside `commandID`:

```
transparent_tcp.go: pid := sess.CurrentProcessPID()  // next to the existing commandID read
  → handleTorSocks(…, commandID, pid, …)
    → gatewayConnect(…, commandID, pid, …) / gatewayResolve(…, commandID, pid, …)
      → emitOnionEvent(emit, sessionID, commandID, pid, v, socksCmd)
        → BuildControlEvent(sessionID, commandID, pid, v)
```

Threading `pid` as a value (not passing the `Session` object) keeps
`emitOnionEvent` and the gateway handlers pure and value-driven — matching how
they already take `sessionID` and `commandID` — so the existing in-memory handler
tests stay simple (they pass a known `pid` and assert it on the event).

`BuildControlEvent` itself is unchanged: it already accepts and stamps `pid`.

## Semantics (stated honestly)

The attributed PID is the **session's current command-process PID** — the root of
the process tree for the command currently executing in the session. It is **not
guaranteed to be the exact leaf subprocess** that issued the DNS query, HTTP
request, or connect: per-process identity is lost when traffic crosses the veth
into the host-side interceptors, and the originating call may come from any
descendant of the command process. This is the same basis `commandID` already
uses, and it is the "which command did this" attribution an auditor wants. Each
emission site gets a short comment stating this so the approximation is not
mistaken for precise per-syscall attribution.

## Edge case: idle session

If an interceptor fires while no command is running (rare — the session enforces
serial command execution, and these interceptors normally fire during an active
command), `CurrentProcessPID()` returns 0 and `CurrentCommandID()` returns `""`.
We emit `pid: 0` honestly in that case — there is no command process to
attribute — exactly as `commandID` is already empty there. No special-casing.

## PID-namespace verification (confirmed)

`SetCurrentProcessPID` is called with `cmd.Process.Pid` (`internal/api/exec.go:357`,
`internal/api/exec_stream.go:434`) and `ps.PID()` (`internal/api/pty_core.go:202`)
— all host-side PIDs of the command process as agentsh observes it. The
ptrace-path Tor events use `nc.PID`, also a host-side PID from the ptrace
subsystem. Both event families therefore carry `pid` in the same namespace and
cross-reference cleanly.

## Events / observability

Reuse the existing `tor_control` event. The only change to existing records is
that `PID` is now populated (non-zero) when a command is running, instead of
always `0`. `Fields` are unchanged. **No new `events.EventType`** → the OCSF
registry and its exhaustiveness test are untouched.

## Configuration

**No new config knobs.** PID attribution is automatic wherever these events are
already emitted. Nothing to opt into or out of.

## Testing

All four sites are unit-testable by driving the interceptor / handler with a
session (or value) reporting a known command-process PID and asserting the
emitted `tor_control` event carries it.

1. **SOCKS gateway (`socks.go`)**: extend the existing `assertOnionEvent` helper
   to assert `ev.PID`; drive `handleTorSocks` (allowed CONNECT and allowed
   RESOLVE) with a known non-zero `pid` and assert it lands on the emitted event.
   A denied request likewise stamps the `pid` on its deny event.
2. **`onion_dns` (`dns.go`)**: a DNS query for a `.onion` with a session stub
   reporting a known PID emits a `tor_control{vector: onion_dns}` event whose
   `PID` equals that value.
3. **`onion_http` (`proxy.go`)**: a proxied request to a `.onion` host with a
   session stub reporting a known PID emits `tor_control{vector: onion_http}`
   carrying that `PID`.
4. **`relay_ip` / `socks_port` (`transparent_tcp.go`)**: the transparent-TCP Tor
   event carries the session's current PID.
5. **Idle session**: when the session reports PID 0 / empty command, the event is
   emitted with `pid: 0` (no panic, no special value).

Where a full interceptor is awkward to stand up in a unit test, test at the
narrowest seam that still exercises "the session's `CurrentProcessPID()` reaches
the event" (e.g. a small session interface / stub), rather than booting the whole
netns data path. The implementation plan will pick the concrete seam per site.

## Non-Goals

- **Exact leaf-subprocess attribution.** The reported PID is the command-process
  root, not the precise descendant that made the call. Closing that gap needs
  eBPF tuple→PID cross-referencing (TCP-only, no DNS) — explicitly rejected above.
- **Per-individual-PID attribution for DNS.** UDP DNS queries cannot be
  attributed below the session/command granularity given the netns/veth
  architecture; the command-process PID is the floor.
- **New config surface, new event type, new data path.** All derive from the
  existing session state and the existing `tor_control` event.
- **Changing `commandID` behavior.** Already correct; untouched.

## Out of scope / future (tracked, not built here)

Carried forward from Phase 4, independent of this change:

- **`RESOLVE_PTR` (0xF1) support** — if a concrete consumer appears.
- **Stream isolation / SOCKS-auth pass-through** — the gateway forces upstream
  no-auth; per-stream isolation via SOCKS username/password
  (`IsolateSOCKSAuth`) is unavailable through the gateway.
