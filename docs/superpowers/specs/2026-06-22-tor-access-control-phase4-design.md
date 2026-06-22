# Tor Access Control — Phase 4 Design (SOCKS RESOLVE in the onion gateway)

**Status:** Implemented (PR pending)

**Builds on:** [Tor Access Control — Design](2026-06-14-tor-access-control-design.md) (Phase 1 deny/audit, PR #424; Phase 2 onion gateway, PR #428) and [Phase 3 — fail-open gap closed](2026-06-20-tor-access-control-phase3-design.md) (PR #429).

## Summary

The Phase 2 onion gateway terminates the client's SOCKS5 handshake and filters
per-`.onion` — but `handleTorSocks` accepts only the `CONNECT` command (0x01);
every other command is rejected as "unsupported command." After Phase 3
force-redirects **all** `socks_ports` traffic into the gateway, a Tor-aware
client that issues a SOCKS `RESOLVE` (0xF0) — the standard Tor extension for
resolving a hostname *through* Tor without leaking DNS to the local resolver —
is now redirected into the gateway and rejected. The result is fail-closed
(nothing leaks) but breaks allow-mode usability: an app permitted to reach
`foo.onion` cannot resolve names over Tor at all.

Phase 4 closes that usability gap by making the gateway **command-aware**:
`RESOLVE` (0xF0) is filtered through the same `onion_rules` as `CONNECT` and,
when allowed, forwarded to the real Tor SOCKS daemon and its single reply
relayed back. `RESOLVE_PTR` (0xF1) and all other non-`CONNECT` commands are
**deliberately** rejected with the correct SOCKS error code.

Phase 4 adds **no new data path**, **no new event type**, and **no new config
knobs**.

## Motivation

`RESOLVE` is how Tor-aware tooling avoids a DNS leak: instead of resolving a
hostname with the system resolver (plaintext, off-Tor) and then connecting to
the resulting IP, the client asks Tor to resolve the name inside the circuit.
Before Phase 3 a loopback Tor daemon outside agentsh's interception answered
these directly; after Phase 3 they are force-redirected into the gateway, where
the CONNECT-only parser rejects them. For a control whose allow-mode purpose is
"permit specific onions, deny the rest," refusing the very resolution step a
permitted client needs is an avoidable rough edge.

Root cause, concretely: `internal/netmonitor/socks.go` —

```go
if head[1] != socksCmdConnect {
    return socksReq{}, fmt.Errorf("socks: unsupported command 0x%02x", head[1])
}
```

The request wire format of `RESOLVE` is identical to `CONNECT`
(`VER CMD RSV ATYP ADDR PORT`), and the existing `readSocksReply` already
parses every reply address type — so the gap is narrow and the fix is local.

## Scope decisions (locked)

- **`RESOLVE` (0xF0): filter-and-forward.** Evaluated through the existing
  `onion_rules` exactly like `CONNECT`; allowed → forwarded to upstream Tor and
  the single reply relayed; denied/unmatched → fail-closed (`not allowed`).
- **`RESOLVE_PTR` (0xF1): deliberately unsupported.** Its target is an IP
  (reverse DNS), which `onion_rules` (`.onion`/host globs matched with
  `filepath.Match`) cannot naturally express; agent tooling essentially never
  uses reverse-DNS-over-Tor. Rejected with SOCKS `command not supported`
  (0x07). Leaving it rejected is already fail-closed-safe (nothing leaks). A
  future phase can add it if a real need appears.
- **No `.onion`-RESOLVE special-casing.** Resolving a `.onion` to an IP is
  meaningless (onions have no IP); real Tor returns its own error. An allowed
  `.onion` RESOLVE is simply forwarded and Tor's error reply relayed — honest,
  zero extra code.
- **No new config knobs.** Behavior derives entirely from the existing
  `onion_rules` / `socks_ports`. Gateway activation is unchanged
  (`GatewayActive()` = mode==allow && len(onion_rules)>0).

## Architecture: one command-aware path

Phase 4 generalizes the existing `handleTorSocks` rather than adding a parallel
handler (which would duplicate the greeting, target evaluation, and upstream
handshake for no benefit). After the greeting and no-auth method selection, the
request is read by a command-aware parser and dispatched on the command byte:

```
greeting → no-auth → readSocksRequest → switch cmd:
    CONNECT (0x01)     → eval → forward → relay reply → splice   (tunnel; unchanged)
    RESOLVE (0xF0)     → eval → forward → relay reply → close    (request/reply; new)
    RESOLVE_PTR (0xF1) → reply command-not-supported (0x07); close
    other              → reply command-not-supported (0x07); close
```

No change to `transparent_tcp.go`, the force-redirect, or the SOCKS5 *data*
path for CONNECT. The command byte is only known after the SOCKS request is
read inside the gateway, so dispatch necessarily lives here, not in the
transparent-TCP layer.

## Request parsing generalization

`internal/netmonitor/socks.go`:

- `socksReq` gains a `cmd byte` field carrying the request command.
- `readSocksConnect` becomes `readSocksRequest`: it reads `cmd = head[1]` and
  accepts `0x01` (CONNECT) and `0xF0` (RESOLVE). For `0xF1` it returns a typed
  sentinel error (`errResolvePtrUnsupported`) so the handler can map it to the
  `command not supported` reply; for any other command it returns the existing
  "unsupported command" error, which the handler also maps to `0x07`. Address
  parsing (`atypIPv4`/`atypIPv6`/`atypDomain`) is unchanged and shared.
- `encodeConnectReq` becomes `encodeReq`: it emits `req.cmd` rather than a
  hardcoded `socksCmdConnect`, so the forwarded request carries CONNECT or
  RESOLVE faithfully.
- New constants: `socksCmdResolve = 0xF0`, `socksCmdResolvePtr = 0xF1`,
  `socksRepCmdNotSupported = 0x07`.

`EvalSocksTarget(host, port)` is **port-agnostic** — it matches host globs and
uses the port only to build the `Target` string — so a RESOLVE request (which
typically carries port 0) is evaluated correctly with no rule-semantics change.

## RESOLVE forwarding and reply

For an **allowed** RESOLVE, the handler reuses the existing upstream
SOCKS-client handshake unchanged: greeting (one method, no-auth), read and
validate the method-selection reply (must be no-auth), then
`up.Write(encodeReq(req))` with `cmd == 0xF0`. It then reads exactly one reply
with the existing `readSocksReply` (which already parses `atypIPv4`/`IPv6`/
`atypDomain` reply addresses — Tor's RESOLVE answer is the resolved IP, or an
error reply such as host-unreachable) and relays it verbatim to the client.
The reply is relayed **whatever its REP code**, so the client receives Tor's
real result, including errors. Then the connection closes — there is **no
`splice`**: RESOLVE is a single request/reply, not a tunnel.

For a **denied/unmatched** RESOLVE the handler replies `not allowed` (0x02) and
emits the deny event, exactly as CONNECT does — no upstream connection is made.

## RESOLVE_PTR and other unsupported commands

`RESOLVE_PTR` (0xF1) and any non-CONNECT/non-RESOLVE command are answered with
SOCKS `command not supported` (0x07) and the connection closed. This corrects a
latent inaccuracy: today such commands fall through `readSocksConnect`'s generic
error and the client receives `general failure` (0x01), a misleading code. No
`tor_control` event is emitted for these — no `onion_rules` decision was made
(consistent with the existing "no verdict → emit nothing" path). The startup
posture and `onion_rules` are unaffected.

## Events / observability

Reuse the existing `tor_control` event (`Type: "tor_control"`, free-form
`Fields map[string]any`). **No new `events.EventType`** → the OCSF registry is
untouched, consistent with Phase 2 (`vector: onion`) and Phase 3
(`vector: gateway`).

- **New free-form `socks_cmd` key** in `Fields`, value `"resolve"` for a
  RESOLVE decision and `"connect"` for a CONNECT decision. The per-CONNECT
  events gain `socks_cmd: "connect"` for symmetry; this is the only change to
  existing CONNECT event records.
- The command string is threaded into the onion event's `Fields` (carried on
  the `tor.Verdict` or passed to the event builder — an implementation detail;
  the contract is that `Fields["socks_cmd"]` is present).
- **Emit exactly one `vector: onion` event per evaluated request** (CONNECT or
  RESOLVE), `decision: allow|deny`, `target: host:port`, `pid: 0` (same
  correlation-by-session-and-target limitation as the other connection-layer
  vectors).
- RESOLVE_PTR / unsupported commands emit **no** event.

## Configuration

**No new config knobs.** RESOLVE filtering is automatic whenever the gateway is
active (`mode: allow` + `onion_rules`); it uses the same rules and the same
`socks_ports`. There is nothing new to opt into or out of.

## Testing

Security and protocol invariants are unit-testable without root (the gateway
runs over in-memory/loopback connections), reusing the existing
`fakeTorUpstream*` / `driveClient` helpers in `socks_handler_test.go`.

1. **Request parsing** (`readSocksRequest`): parses a CONNECT and a RESOLVE
   request identically except for `cmd`; returns the typed sentinel for
   `RESOLVE_PTR` (0xF1); returns the unsupported-command error for an arbitrary
   other command (e.g. BIND 0x02).
2. **RESOLVE allowed**: target matches an allow rule → the gateway performs the
   upstream handshake, forwards a RESOLVE (cmd 0xF0) to a fake Tor upstream that
   answers with a resolved-IP reply, and relays that reply verbatim to the
   client; assert the connection is **not** spliced (no tunnel) and one
   `tor_control{vector: onion, socks_cmd: "resolve", decision: allow}` event is
   emitted.
3. **RESOLVE denied**: target matches no rule (or a deny rule) → client receives
   `not allowed` (0x02), no upstream dial, one deny event with
   `socks_cmd: "resolve"`.
4. **RESOLVE_PTR**: client sends 0xF1 → receives `command not supported`
   (0x07); no upstream dial; no event emitted.
5. **CONNECT regression**: an allowed CONNECT still tunnels (splices) and now
   carries `socks_cmd: "connect"` in its event; a denied CONNECT still replies
   `not allowed`.
6. **Fail-closed parity**: upstream dial failure on an allowed RESOLVE →
   `general failure` (0x01); a malformed request → `general failure`.
7. **RESOLVE error relay**: a fake upstream that returns a non-success RESOLVE
   reply (e.g. host-unreachable) has that reply relayed verbatim to the client
   (the client sees Tor's real error, and the stream is not spliced).

## Non-Goals

- **`RESOLVE_PTR` (0xF1) support.** Reverse-DNS-over-Tor targets an IP that
  `onion_rules` cannot naturally express, and agent tooling does not use it.
  Deliberately rejected with `command not supported`; a cheap follow-up if a
  real need appears.
- **UDP `ASSOCIATE` (0x03) and `BIND` (0x02).** Tor's SOCKS does not provide
  general UDP, and BIND is unused by the agent threat model. Rejected with
  `command not supported`.
- **New config surface, new event type, new data path.** All derive from the
  existing `onion_rules` / `socks_ports` and the existing `tor_control` event.
- **PID/command attribution for the onion events.** Still `pid: 0`,
  correlated by session and target — unchanged from Phase 2, tracked
  separately.

## Out of scope / future (tracked, not built here)

Carried forward from Phase 3, independent of this gap:

- **`RESOLVE_PTR` support** (above) — if a concrete consumer appears.
- **Stream isolation / SOCKS-auth pass-through** — the gateway forces upstream
  no-auth; operators relying on per-stream isolation via SOCKS
  username/password (`IsolateSOCKSAuth`) cannot use it through the gateway.
- **PID/command attribution for `onion_dns` / `onion_http` events** — those
  layers report `target` only.
