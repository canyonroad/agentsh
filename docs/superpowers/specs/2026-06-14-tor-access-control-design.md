# Tor Access Control — Design

**Date:** 2026-06-14
**Status:** Approved — Phase 1 implemented
**Related:** `internal/policy/engine.go` (`CheckExecve`, `CheckNetworkIP`,
`CheckNetworkCtx`), `internal/netmonitor/dns.go`, `internal/netmonitor/proxy.go`,
`internal/netmonitor/transparent_tcp.go`, `internal/threatfeed/`,
`internal/config/config.go`, `internal/events/types.go`,
`internal/ocsf/registry.go`. Builds on the connect-redirect machinery
(`docs/plans/2026-01-29-network-redirect-design.md`) and the Process
Network ACL (`docs/plans/2026-01-13-process-network-acl-design.md`).

## Summary

Add a top-level **`tor:` policy block** that gives agentsh a single,
declarative, **deny-by-default** posture toward the Tor network. The
block is a *coordinating macro*: one intent (`deny | audit | allow`)
expands into consistent enforcement across the five distinct ways a
sandboxed process can reach Tor, and every hit emits a uniform
`tor_control` audit event tagged with the vector that fired.

The threat is evasion: an AI agent that runs `tor` (or `torsocks`, a
bridge, a SOCKS proxy) to tunnel around agentsh's carefully-built
network egress allowlist. Tor traffic is encrypted to relays, so once
an agent is on the Tor network its real destinations are invisible to
every IP/DNS/host control agentsh has. The only effective response is
to stop the agent reaching the Tor network in the first place.

**Deny-by-default.** With no `tor:` block configured at all, Tor is
denied. Operators must explicitly opt out (`tor.mode: allow` or
`tor.enabled: false`) to permit it. The default posture requires **no
external network fetch** — it relies on the four cheap doors (client
binaries, local SOCKS/control ports, `.onion` DNS, `.onion` HTTP) plus
a built-in set of Tor directory-authority IPs that alone break Tor
bootstrap.

Phase 1 (this spec, the deliverable) is **category control**: block or
audit Tor as a whole. Phase 2 (sketched, not built) is a SOCKS-aware
onion gateway for per-`.onion` allow/deny when Tor is deliberately
permitted.

## Motivation

agentsh's network controls — PNACL, `CheckNetworkIP/Ctx`, threat
feeds, the HTTP/DB proxies — all reason about a connection's
*destination*: its host, IP, CIDR, port, SNI, or HTTP Host. Tor
defeats all of them at once. An agent that bootstraps a Tor client
opens an encrypted circuit to a guard relay and then reaches anything
— including any `.onion` service and any clearnet host — with the real
target buried inside the encrypted stream. From agentsh's vantage the
only thing visible is "a TLS connection to some relay IP," and the
agent's entire egress policy is bypassed.

Tor is therefore best treated as a *category* to be denied by default,
the same way the socket-family-block spec treats niche kernel socket
families: near-zero legitimate use inside an agent workload, high
evasion value, so deny unless explicitly needed.

The good news is that four of the five enforcement points already
exist; this design coordinates them and adds one new primitive
(IP/CIDR membership) plus the feed that populates it.

## The five vectors

A process reaches Tor through exactly one (or more) of these doors.
Phase 1 closes all five.

| # | Vector | What it catches | Hook |
|---|---|---|---|
| 1 | **Client processes** | Agent runs `tor`/`obfs4proxy`/`snowflake-client`/`lyrebird`/`meek-client`/`torsocks`/Tor Browser | `CheckExecve` → ptrace deny (**exists**) |
| 2 | **Local SOCKS/control ports** | App speaks SOCKS to a local Tor daemon at `127.0.0.1:9050/9150`, control at `9051` | `connect()` seccomp-notify, sees loopback sockaddr (**exists, small wiring**) |
| 3 | **`.onion` DNS** | A `.onion` name (RFC 7686) reaches the resolver | DNS interceptor name match → REFUSED (**exists**) |
| 4 | **`.onion` HTTP** | A `.onion` Host fetched through agentsh's HTTP proxy | proxy Host match → 403 (**exists**) |
| 5 | **Relay IPs** | The Tor daemon dials guard / middle / exit / dir-authority IPs directly | IP/CIDR match in `CheckNetworkIP` (**net-new**) |

Vectors 1–4 do not depend on any feed. Vector 5 uses a built-in
directory-authority seed (feed-independent) plus an optional onionoo
relay feed.

The `.onion` DNS (3) and `.onion` HTTP (4) rows are two enforcement
points and two distinct `tor_control` event vectors (`onion_dns`,
`onion_http`), but they share a single `vectors.onion` config toggle:
blocking `.onion` over DNS while permitting it over the HTTP proxy is
incoherent, so one toggle governs both. The other vectors remain
independently toggleable.

## Non-Goals

- **Per-`.onion` allow/deny in Phase 1.** Allowing `a.onion` while
  denying `b.onion` through the *same* local Tor requires reading the
  `.onion` target out of the SOCKS5 CONNECT handshake — a stateful
  MITM proxy. Deferred to Phase 2. Phase 1 blocking an onion is free
  (kill the transport); *permitting a specific* onion is the hard part.
- **Enumerating private bridges.** Bridges are deliberately unlisted,
  so the relay-IP feed cannot know them. Bridge-based Tor is still
  caught by vectors 1–4 (the agent still runs a client binary and
  dials a local SOCKS port). Relay-IP blocking is defense-in-depth for
  the daemon's *direct* egress, not the sole control. Documented, not
  pretended.
- **Per-port precision on relay IPs.** Relay-IP matching (vector 5) is
  IP-based and **port-agnostic**: a connection to *any* port of a seed
  or feed relay IP is treated as Tor. A few directory-authority IPs sit
  in netblocks shared with non-Tor services, so under deny-by-default a
  sandboxed agent that legitimately dials such an IP on an unrelated
  port is blocked as `relay_ip`. This is the intended conservative
  posture (the same trade-off as the bridge limitation); the operator's
  escape hatch is `vectors.relay_ips: false` or `tor.mode: audit`.
- **Deep Tor protocol fingerprinting** (recognizing the Tor link
  handshake on an arbitrary TLS connection). Out of scope; the five
  vectors above are cheaper and sufficient.
- **Mandatory phone-home.** The onionoo feed is opt-in. The
  deny-by-default posture must hold with zero external fetches.
- **Replacing PNACL / threat feeds / network rules.** The `tor:` block
  sits alongside them and takes precedence in `deny` mode; it does not
  subsume general network policy.
- **Non-Linux enforcement parity.** Enforcement is Linux-first
  (matches the repo posture). Cross-platform hooks that already exist
  (execve, DNS, HTTP proxy) carry over; the `connect()`/relay-IP path
  rides the Linux seccomp/network layer. The config parses everywhere
  (cross-compile builds clean); platforms without the underlying
  subsystem degrade per "Honest scope" below.

## Configuration

New top-level block, sibling of `threat_feeds` and `policies`:

```yaml
tor:
  # Tri-state, codebase convention (*bool): absent/nil → true.
  # Deny-by-default: omitting the whole block denies Tor.
  enabled: true

  # deny (default) | audit | allow
  #   deny  → on a Tor match, short-circuit to deny; emit tor_control{decision:deny}
  #   audit → on a Tor match, do NOT block on account of Tor; emit
  #           tor_control{decision:audit}, then fall through to normal
  #           policy (a user rule may still deny it — audit never loosens)
  #   allow → Tor vectors are no-ops (Tor permitted); normal policy still
  #           applies to non-Tor traffic. Phase 2 attaches onion_rules here.
  mode: deny

  # All default true. Lets an operator relax one door without losing the rest.
  vectors:
    processes:   true
    socks_ports: true
    onion:       true   # one toggle for both .onion DNS and .onion HTTP
    relay_ips:   true

  client_binaries: [tor, obfs4proxy, snowflake-client, lyrebird, meek-client, torsocks]
  socks_ports:     [9050, 9150]
  control_ports:   [9051]
  socks_loopback_only: true   # only treat those ports as Tor when dest is loopback

  relay_feed:
    enabled: false            # opt-in; deny-by-default does NOT require this
    sources: ["https://onionoo.torproject.org/details"]
    local_lists: ["/etc/agentsh/tor-relays.txt"]
    sync_interval: 6h
```

**Defaults resolution (`ResolveTorConfig`).** A missing block, or
`enabled` unset, resolves to `enabled: true, mode: deny` with all
vectors on and the built-in seed active. Empty `mode` → `deny`. This
mirrors the `*bool` tri-state already used for `WaitKillable` and the
"unset → recommended default" pattern in the socket-family-block spec.

**Escape hatches.** `tor.enabled: false` disables Tor controls
entirely; `tor.mode: allow` permits Tor (and, in Phase 2, scopes it
via `onion_rules`).

**Upgrade / migration note (deny-by-default activates on upgrade).**
Because `tor:` is deny-by-default, an existing deployment whose config
has **no `tor:` block** will, on upgrade to a build containing this
feature, immediately begin denying all five Tor vectors — client
binaries, the local SOCKS/control ports (`9050/9150/9051`), `.onion`
DNS/HTTP, and the built-in directory-authority IPs — for agents that
never opted in. This is the intended posture, not a regression. An
operator who needs Tor, or who wants a gentler rollout, must set one of
the following **before** upgrading:

- `tor.mode: audit` — observe via `tor_control{decision:audit}` events
  without blocking, then tighten to `deny` once the impact is understood;
  or
- `tor.enabled: false` — disable the Tor controls entirely.

This default-on, high-impact behavior change **must be called out in the
release notes** for the version that ships Phase 1, so operators can opt
out ahead of time.

## Architecture

### Coordinator, not rule synthesis

Two ways to expand the macro were considered:

- **(A, chosen) Dedicated checks consulting a shared `tor.Policy`.**
  Each enforcement point asks `tor.Policy` "is this Tor, and what's the
  mode?" before normal rule evaluation. A Tor match in `deny` mode
  overrides any user `allow`. Every hit emits a uniform `tor_control`
  event tagged with its vector. One config source of truth; clean
  precedence; Tor-specific observability.
- **(B, rejected) Rule synthesis.** Generate ordinary
  execve/network/DNS rules from the `tor:` block at load. Less wiring,
  but events surface as generic "network deny," precedence with user
  rules is murky, and there is no "Tor" concept in the audit trail.

`tor.Policy` (new, `internal/tor/`) holds the resolved config, the
compiled client-binary matchers, the port sets, and the relay IP set.
It exposes:

- `EvalExecve(path, argv) (TorVerdict, ok)`
- `EvalConnect(ip, port) (TorVerdict, ok)` — covers both SOCKS/control
  ports (vector 2) and relay IPs (vector 5)
- `EvalOnionName(host) (TorVerdict, ok)` — covers `.onion` for DNS and
  HTTP (vectors 3, 4)

`TorVerdict` carries `{vector, mode, decision, target}`. `ok=false`
means "not Tor, fall through to normal policy." The existing
enforcement points each gain a short pre-check that calls the relevant
`Eval*` and, on `ok`, applies the verdict and emits the event.

### Per-vector integration

1. **Processes** — `CheckExecve` calls `EvalExecve`. Match (basename or
   path glob against `client_binaries`) in `deny` mode → existing deny
   path (`EACCES`). `audit` → allow + event.
2. **SOCKS/control ports** — the `connect()` seccomp-notify handler
   calls `EvalConnect`. Port ∈ `socks_ports ∪ control_ports` (and, if
   `socks_loopback_only`, dest is loopback) → deny/audit. This path,
   not iptables transparent redirect, is what sees loopback
   destinations.
3. **`.onion` DNS** — the DNS interceptor calls `EvalOnionName` on the
   parsed QNAME. `.onion` suffix in `deny` mode → REFUSED response.
4. **`.onion` HTTP** — the HTTP proxy calls `EvalOnionName` on the
   extracted Host. `.onion` in `deny` mode → 403.
5. **Relay IPs** — `CheckNetworkIP` calls `EvalConnect`; on relay-IP
   membership in `deny` mode → deny. (Net-new; see below.)

### Precedence and fail-closed

- In `deny` mode a Tor verdict **short-circuits to deny** and overrides
  any user `allow` rule at the same enforcement point — Tor checks run
  first.
- In `audit` mode a Tor verdict emits the event and **falls through**
  to normal policy; it never loosens a decision a user rule would make
  (a user `deny` still denies).
- In `allow` mode the Tor vectors are no-ops; normal network policy is
  unchanged for non-Tor traffic.
- Vectors 1–4 are independent of any feed; each holds even if the
  others or the feed are unavailable. (The `.onion` DNS and HTTP
  enforcement points share the single `vectors.onion` toggle — see "The
  five vectors" — but are otherwise independent doors.)
- If the relay feed fails to load: fall back to last-good disk cache →
  built-in directory-authority seed + `local_lists`. Never silent
  fail-open. A `tor_control` feed-status warning is logged/metered.

### Honest scope (subsystem dependence)

Default-deny is enforced **per vector whose underlying subsystem is
active**: vector 1 needs execve monitoring; vectors 2 and 5 need the
connect/network interception layer; vector 3 needs the DNS
interceptor; vector 4 needs the HTTP proxy. Where a subsystem is
disabled, that door degrades to no-op (in `deny`) or is simply not
observed. This is documented rather than papered over; the spec does
not claim a door it cannot enforce.

## The net-new mechanism: IP/CIDR membership + relay feed

The threat-feed store matches **domains only** (`Check(domain)`), and
`CheckNetworkIP` has no feed check today. Rather than overload the
threat-feed subsystem with IP semantics, add a small reusable
primitive and let `tor.Policy` own its relay set.

- **`internal/ipset` (new, small).** Efficient IPv4/IPv6 + CIDR
  membership (sorted ranges or a binary trie). Reusable; the
  threat-feed store may adopt it later.
- **`tor.Policy.IsRelay(ip)`** consults that set; wired into
  `CheckNetworkIP` only when `vectors.relay_ips` is on.
- **Built-in seed (feed-independent).** The ~9 Tor directory-authority
  IPs plus bundled fallback-dir IPs ship hardcoded. A Tor client must
  reach a dir authority / fallback dir to bootstrap, so this alone
  breaks Tor — and it needs no fetch, which is what makes
  deny-by-default work out of the box.
- **Feed source: onionoo** (`onionoo.torproject.org/details`, the Tor
  Project's official API). Parse every relay's `or_addresses` into the
  set — **all relays, not just exits**, because the local daemon dials
  *guard* (entry) nodes first; blocking only exits would not stop
  bootstrap. Disk-cached, `sync_interval` refresh (default 6h),
  `local_lists` for curated/air-gapped IPs. The feed dataset is large
  (~8k relays); the loader streams/parses to the `ipset` and caches the
  compiled set to disk (reuse the threatfeed syncer/cache pattern).
- **Limitation:** bridges are unlisted (see Non-Goals).

## Events / observability

One new event type:

```
EventTorControl events.EventType = "tor_control"
```

Fields: `vector` (`process|socks_port|onion_dns|onion_http|relay_ip`),
`mode` (`deny|audit|allow`), `decision` (`deny|audit|allow`), `target`
(binary path / `.onion` host / `ip:port`), `rule: "tor"`, plus the
standard base process fields (pid, process name, executable, cmdline,
uid/gid, username). `audit` mode emits the same event with
`decision: audit`.

**Attribution caveat.** The `pid`/`command_id` fields are populated only
where the firing enforcement layer knows the originating process. The
ptrace execve and network paths carry a real `pid` (with an empty
`command_id`, matching the sibling `ptrace_execve`/`ptrace_network`
events). The DNS, HTTP-proxy, and transparent-TCP layers operate on a
query/connection and emit `pid: 0`, because the originating PID is not
resolved at that layer; those records are correlated by session and
`target` instead. Threading a PID into those layers is possible future
work, not a Phase 1 guarantee.

**Registration requirement.** Any new `events.EventType` must also be
added to `internal/ocsf/registry.go` (`pendingTypes` or a real OCSF
class mapping), or `TestExhaustiveness_AllEventTypesRegistered` fails —
in a package this change does not otherwise touch. A full
`go test ./...` is therefore part of "done." Map `tor_control` to an
appropriate OCSF network/security-finding class in the registry.

Feed status (loaded / stale / failed, relay-set size, last sync) goes
to logs and metrics, **not** a second event type — keeping the OCSF
surface to one new type.

## Testing

**Unit**
- `tor.Policy` decisions across every vector × mode (`deny/audit/allow`).
- `ipset` membership: IPv4, IPv6, CIDR boundaries, empty set.
- onionoo parser: `or_addresses` extraction, IPv6 forms, malformed input.
- Precedence: a Tor `deny` verdict overrides a user `allow` rule.
- Degraded path: feed disabled/empty → built-in dir-authority seed
  still blocks; feed fetch failure → last-good cache used, warning emitted.
- Defaults resolution: absent block → `enabled+deny+all vectors`.

**Integration (Linux)**
- Fake `tor` binary → exec denied (`EACCES`) + one `tor_control` event.
- Fake SOCKS listener on `127.0.0.1:9050` → `connect()` denied.
- `.onion` DNS query → REFUSED.
- `.onion` fetch via the HTTP proxy → 403.
- `connect()` to a seeded relay IP → denied.
- `audit` mode → each of the above is permitted but emits a
  `tor_control{decision:audit}` event.
- One `tor_control` event per fired vector, with correct `vector`/`target`.

**Gates**
- Full `go test ./...` (OCSF exhaustiveness lives outside the changed packages).
- `GOOS=windows go build ./...` cross-compile (per CLAUDE.md / AGENTS.md).
- roborev between tasks; fix everything above low before proceeding.

## Phase 2 (sketch — documented, not built)

When `tor.mode: allow` and an `onion_rules:` list is present, agentsh
becomes a **managed Tor egress**:

1. Redirect the app→`127.0.0.1:9050` connection, via the existing
   connect-redirect machinery, into agentsh's own SOCKS5 front-end.
2. New `internal/netmonitor/socks.go` parses the SOCKS5 greeting +
   CONNECT request and extracts the target host (`.onion` or clearnet).
3. Match the target against `onion_rules` (and clearnet-via-Tor rules)
   through `tor.Policy`.
4. Allowed streams are forwarded to the *real* Tor SOCKS daemon;
   denied streams are reset. Stateful, fail-closed.

Reuses connect-redirect, `tor.Policy`, and the `tor_control` event
schema (new `vector: onion`). This is the only path that yields true
per-`.onion` granularity, and it is deferred until there is a concrete
need to *permit* specific onions rather than block Tor wholesale.

```yaml
# Phase 2 illustration only — not parsed in Phase 1.
tor:
  mode: allow
  onion_rules:
    - onion: "abcdefghij…234567.onion"
      decision: allow
    - onion: "*"
      decision: deny
```
