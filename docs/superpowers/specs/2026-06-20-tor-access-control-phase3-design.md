# Tor Access Control — Phase 3 Design (close the allow-mode fail-open gap)

**Status:** Draft — proposed

**Builds on:** [Tor Access Control — Design](2026-06-14-tor-access-control-design.md) (Phase 1 deny/audit, PR #424; Phase 2 onion gateway, PR #428).

## Summary

Phase 2's onion gateway gives true per-`.onion` allow/deny, but only for Tor
SOCKS connections that reach agentsh's transparent-TCP interceptor. In any
session where the app reaches a loopback Tor daemon that is **not** routed
through that interceptor, allow-mode silently degrades to Phase-1 *unfiltered*
allow: Tor is permitted and the `onion_rules` are never consulted. For a
security control whose entire purpose is to *permit specific onions while
denying the rest*, a silent fail-open at its finest granularity is the gap
worth closing.

Phase 3 closes it from both ends:

1. **Force-redirect (netns transparent mode):** agentsh itself guarantees the
   app's connection to the configured `socks_ports` lands in the gateway, by
   adding a loopback DNAT rule inside the session network namespace. The
   gateway "just works" — no operator routing required.
2. **Fail-closed (every other mode):** when allow-mode `onion_rules` are
   configured but the gateway cannot be wired for the session, agentsh denies
   Tor for that session (Phase-1 deny semantics) and emits an audit event,
   rather than allowing unfiltered Tor.

Phase 3 adds **no new data path** and **no new event type**.

## Motivation

The Phase 2 spec documents this limitation honestly ("Honest scope (Phase 2)")
but leaves the failure *silent*: an operator who configures
`mode: allow` + `onion_rules`, expecting per-onion enforcement, gets unfiltered
Tor whenever their Tor daemon is reached over loopback outside interception —
with nothing in the audit stream to say enforcement did not happen.

Root cause, concretely: `internal/netmonitor/netns_linux.go` sets up the netns
NAT so that all outbound TCP is DNAT'd to the host interceptor —

```
iptables -t nat -A OUTPUT -d <hostIP>      -j RETURN        # host veth: don't redirect
iptables -t nat -A OUTPUT -d 127.0.0.0/8   -j RETURN        # loopback: don't redirect  <-- the gap
iptables -t nat -A OUTPUT -p tcp           -j DNAT --to <hostTCP>
```

The `127.0.0.0/8 RETURN` rule deliberately exempts loopback from redirection.
A Tor daemon on `127.0.0.1:9050` is therefore reached directly, bypassing the
interceptor (and thus the gateway) entirely.

## Architecture: one decision, two branches

Phase 3 introduces a single per-session predicate evaluated at session startup,
after the transparent-network attempt:

```
gatewayActive := GatewayActive(policy)          // mode==allow && len(onion_rules)>0
interceptorUp := tryStartTransparentNetwork succeeded

switch {
case !gatewayActive:                 // deny/audit, or allow with no onion_rules
    // Phase 1 / Phase 2 unchanged; Phase 3 inert.
case gatewayActive && interceptorUp: // BRANCH 1
    installForceRedirect()           // fully install, or fall to fail-closed
case gatewayActive && !interceptorUp:// BRANCH 2
    failClosedDenyTor()
}
```

No change to `transparent_tcp.go`, `socks.go`, or the SOCKS5 data path. Phase 3
is entirely in the *wiring* that decides whether a session's Tor traffic reaches
the existing gateway, and what happens when it cannot.

## Branch 1 — Force-redirect (netns transparent mode)

**Mechanism:** iptables loopback-DNAT inside the session netns. (The rejected
alternative — ptrace `connect()` sockaddr-rewrite — is invasive on the hot
syscall path, must handle the IPv4/IPv6/blocking/`EINPROGRESS` matrix, and the
non-netns modes it would additionally cover have no interceptor to redirect
into anyway; see Non-Goals.)

**File:** `internal/netmonitor/netns_linux.go`.

The netns setup already receives `hostTCP` (the interceptor `host:port`) and
writes the OUTPUT nat rules. Phase 3 adds a `torRedirectPorts []int` parameter,
populated **only** when `GatewayActive()` holds for the session. For each port,
insert — **before** the existing `-d 127.0.0.0/8 -j RETURN` rule, so it takes
precedence:

```
iptables -t nat -A OUTPUT -d 127.0.0.1 -p tcp --dport <port> -j DNAT --to-destination <hostTCP>
```

and enable routing of loopback-originated packets inside the netns:

```
sysctl -w net.ipv4.conf.all.route_localnet=1
```

Result: the app's `connect(127.0.0.1:9050)` crosses the veth to the existing
interceptor; `SO_ORIGINAL_DST` recovers `127.0.0.1:9050`; the existing
`torGatewayFor(dstPort)` hook in `transparent_tcp.handle` matches the port and
routes the stream through `handleTorSocks`. Per-onion filtering applies exactly
as in Phase 2 — Phase 3 only guarantees the bytes get there.

**Rule ordering is a correctness invariant.** The per-port DNAT rules MUST be
emitted before the `127.0.0.0/8 RETURN` rule. If they followed it, the RETURN
would short-circuit loopback traffic and the redirect would never fire.

**Fully installed or deny — no half-redirect.** `route_localnet` or the DNAT
insert can fail on a restricted host. If **any** force-redirect step fails to
install, the session MUST NOT proceed with "interceptor up, Tor unfiltered." It
tears the partially-installed rules back to a known state and transitions to
Branch 2 (fail-closed deny). A force-redirect is all-or-nothing.

**route_localnet scope.** `route_localnet=1` is set on `net.ipv4.conf.all` inside the session netns; its
effect is contained to the sandbox network namespace (the sysctl write occurs
inside the per-session netns, so it does not alter host routing).

## Branch 2 — Fail-closed (gateway not wired)

**Trigger:** `GatewayActive()` policy, but the session did not bring up the
netns interceptor (proxy-env fallback), or force-redirect could not be fully
installed (per Branch 1).

**Enforcement — reuse Phase-1 deny, per session.** The shared `tor.Policy` is
built once at server start and is attached to the global engine; it MUST NOT be
mutated for one session. Instead, fail-closed builds a **session-scoped policy
clone** from the same resolved config with `Mode` forced to `deny`, and
attaches it to the session's engine (`policyEngineFor(s)`). Semantically:

> Run this session as if `tor.mode: deny`.

This reuses every Phase-1 deny vector unchanged — execve kills the Tor client
binary, the connect vector denies the SOCKS/control ports, relay-IP and
onion-name vectors apply — on whatever enforcement subsystem is live for the
session. No new enforcement code path is introduced.

**Honest-scope floor.** Fail-closed deny is only as strong as the enforcement
subsystem available. In proxy-env fallback with ptrace active, the connect and
execve vectors still bite. If *no* enforcement subsystem is active for the
session (no ptrace, no netns — pure passthrough), even deny cannot be enforced;
Phase 3 does not pretend otherwise — the audit event carries `enforced: false`
(see Events). This is the irreducible floor, documented rather than papered
over, consistent with the Phase 1/2 "Honest scope" sections.

**Dual connect-eval paths.** The Phase-1 SOCKS-port connect deny must fire on
whichever connect-evaluation path is live in the degraded mode. The connect
vector is evaluated on the ptrace connect path (`CheckNetwork` →
`CheckNetworkCtx`), which is the path active in proxy-env fallback; the
implementation must confirm the session-scoped deny policy is consulted there,
not only on the transparent-TCP `CheckNetworkIP` path (which by definition is
absent when the interceptor did not come up).

## Configuration

**No new config knobs.** All behavior derives from existing config:

- Force-redirect activates automatically when `GatewayActive()` and the netns
  interceptor is up.
- Fail-closed activates automatically when `GatewayActive()` but the interceptor
  is not up (or force-redirect could not fully install).
- Ports redirected = the configured `tor.socks_ports` (default `[9050, 9150]`),
  all of them.

Operators who deliberately want allow-without-gateway retain two existing
escape hatches: empty `onion_rules` (→ Phase-1, Tor allowed unfiltered, no
gateway) or `mode: audit`. There is nothing new to opt out of.

**Static advisory (optional, cheap).** At server start, if `mode: allow` +
`onion_rules` are configured but the platform fundamentally cannot host the
gateway (non-Linux, or netns unsupported), emit a single startup log line so
the operator knows every session will fail-closed. Advisory only; enforcement
remains per-session.

## Events / observability

Reuse the existing `tor_control` event (`Type: "tor_control"`, free-form
`Fields map[string]any`). **No new `events.EventType`** → the OCSF registry is
untouched, the same approach Phase 2 used for `vector: onion`.

- **New session-level vector value** `VectorGateway = "gateway"` (in
  `internal/tor/policy.go`), distinct from the per-CONNECT `VectorOnion`.
- **New free-form `reason` key** in `Fields` (the map permits this with no
  schema change).
- **Emit exactly one session-scoped `gateway` event at the branch decision:**
  - Force-redirect installed →
    `{vector: gateway, decision: allow, target: "127.0.0.1:9050,9150", reason: "force_redirect_installed"}`
    — distinguishes "gateway armed and enforcing" from plain Phase-1 allow.
  - Fail-closed deny →
    `{vector: gateway, decision: deny, reason: <cause>}` where `<cause>` ∈
    `{proxy_env_fallback, force_redirect_install_failed}`.
  - Honest-scope floor (fail-closed but nothing can enforce) → the same deny
    event additionally carries `enforced: false`, so the record never implies a
    block it cannot deliver.
- **Per-CONNECT `vector: onion` events are unchanged** from Phase 2.

## Testing

Security-critical invariants are factored into pure functions so they are
unit-testable without root; netns/iptables end-to-end is gated integration.

1. **Force-redirect rule generation** (`netns_linux.go`): separate rule-list
   construction from execution. Given `socks_ports=[9050,9150]` + `hostTCP`, the
   generated sequence contains a loopback-DNAT per port **positioned before** the
   `127.0.0.0/8 RETURN` rule, and includes the `route_localnet` sysctl. Assert
   the DNAT-before-RETURN ordering explicitly.
2. **Branch predicate** (`app.go`): pure
   `(gatewayActive, interceptorUp) → {forceRedirect | failClosed | none}`,
   table-driven: allow+rules+up → force-redirect; allow+rules+down →
   fail-closed; deny/audit → none; allow+empty-rules → none.
3. **Fail-closed policy clone**: the per-session policy is built from the same
   config with `Mode=deny`; `EvalConnect/EvalExecve/EvalOnionName` then return
   deny verdicts; the **shared Policy is not mutated** (a concurrent allow-mode
   session is unaffected).
4. **Partial-install → fail-closed**: inject a forced install failure; assert
   the session ends in fail-closed deny, not interceptor-up-with-unfiltered-Tor.
5. **Events**: force-redirect → one `gateway/allow/force_redirect_installed`;
   fail-closed → one `gateway/deny/<reason>`; floor → `enforced: false` present.
6. **Integration (gated, root + Linux)**: one end-to-end test in the existing
   netns integration suite — session with `mode: allow` + `onion_rules` + a fake
   Tor SOCKS on `127.0.0.1:9050`; connect through it; assert an allowed `.onion`
   passes and a denied one is reset — proving loopback traffic actually reaches
   the gateway. Gated like the repo's other netns tests.
7. **Cross-compile**: `netns_linux.go` is linux-only; `GOOS=windows go build
   ./...` must stay clean (no new params leaking into shared code without stubs).

## Non-Goals

- **ptrace `connect()` sockaddr-rewrite as the force-redirect mechanism.**
  Rejected in favor of netns loopback-DNAT: it is invasive on the hot syscall
  path, must cover the full connect matrix, and the only modes it would
  additionally reach have no interceptor to redirect into (they are the
  fail-closed branch by definition).
- **Making the gateway work in non-netns modes.** Proxy-env fallback has no
  transparent interceptor; Phase 3's answer there is fail-closed deny, not a
  second gateway implementation.
- **New config surface.** Behavior is derived from existing `tor.mode` /
  `onion_rules` / `socks_ports`; no new knobs (YAGNI).
- **Non-Linux enforcement.** Force-redirect is Linux/netns-only (matches the
  repo posture); other platforms with allow-mode `onion_rules` fail-closed, and
  the static advisory names that at startup.

## Out of scope / future (tracked, not built here)

These remain candidates for later, independent of this gap:

- **Gateway SOCKS protocol completeness** — `handleTorSocks` accepts only SOCKS
  `CONNECT` (0x01); Tor's `RESOLVE` (0xF0) / `RESOLVE_PTR` (0xF1) extensions are
  rejected as "unsupported command." Apps resolving `.onion` names over SOCKS
  break or route around policy.
- **Stream isolation / SOCKS-auth pass-through** — the gateway forces upstream
  no-auth; operators relying on per-stream isolation via SOCKS
  username/password (`IsolateSOCKSAuth`) cannot use it through the gateway.
- **PID/command attribution for `onion_dns` / `onion_http` events** — those
  layers report `target` only.
