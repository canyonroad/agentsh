# db-access Plan 04b₂ — Upstream Wiring + Passthrough Modes (design)

Status: design approved 2026-05-10. Implementation plan to follow via writing-plans.

Cross-references:
- Macro design: `docs/superpowers/specs/2026-05-10-db-plan-04-pg-proxy-skeleton-design.md`
- Roadmap: `docs/superpowers/specs/2026-05-08-db-access-phase-1-roadmap-design.md` §3 Plan 04
- Spec: `docs/agentsh-db-access-spec.md` v0.8 §9.1, §11.1, §11.3, §13, §15, §16
- Predecessor plan: `docs/superpowers/plans/2026-05-10-db-plan-04b-handshake-tls.md`
- Predecessor spec snapshot: `docs/superpowers/specs/2026-05-10-db-plan-04b-handshake-tls.md` (the 04b implementation plan, which lists the deferred items 04b₂ ships).

This doc takes 04b's "inbound handshake completes, then a synthetic `ErrorResponse(0A000, UPSTREAM_NOT_YET_WIRED)`" behavior and replaces it with a real upstream handshake. After 04b₂ ships, a `pgx` client can connect through the proxy, complete authentication against the real upstream, and observe a clean close at the first upstream `ReadyForQuery`. Plan 04c then replaces the close-at-RFQ terminator with the Q-frame classify-and-forward loop.

## 1. Scope

### In scope (the entire 04b "out of scope" list, minus GSSENC opt-in)

1. Un-reject `tls_mode: passthrough` services at `Server.New` (the 04b rejection is removed).
2. Upstream TCP dial.
3. Upstream TLS for `terminate_reissue` (system roots, verify-full equivalent: MinVersion=TLS12, ServerName from `upstream` host).
4. Auth-byte forwarding loop (client ↔ upstream) until the first upstream `ReadyForQuery`.
5. SCRAM-SHA-256-PLUS detection + fail-closed + `db_handshake_fail` lifecycle event.
6. `passthrough` mode bidirectional byte-pump after the inbound `'S'` response.
7. Replication opt-in: `match_kind: replication` connection rule routing. On allow, forward StartupMessage to upstream, then enter a bidirectional byte-pump until close, and emit `degraded_visibility_warning{reason: replication_passthrough}`.
8. `CancelRequest`: `match_kind: cancel` connection-rule evaluation; on allow, dial upstream plaintext, write the client's 16-byte cancel packet verbatim, close. **Un-mapped** — Plan 06 adds the (PID, Secret) mapping table.
9. `degraded_visibility_warning` lifecycle event with `reason` field populated.
10. Per-mode spine round-trip tests against a fake `pgproto3.Backend`-speaking upstream.

The `terminate_plaintext_upstream` locality check (loopback / RFC1918 / `trusted_network: true`) is already enforced at policy-load by `internal/db/policy/validate.go` (via `isLoopbackOrPrivate`). 04b₂ does not need to add anything in `Server.New` for this — the supervisor will reject misconfigured services before the proxy ever sees them.

### Out of scope (deferred)

- GSSENC opt-in (`allow_gss_encryption: true`) — Plan 05 per Plan-04 design doc D3.
- BackendKeyData mapping (PID/secret rewriting) — Plan 06.
- `'Q'`-frame classify / forward / synthesize-deny; `db_statement` events — Plan 04c.
- RFQ status-byte tracker — Plan 04c.
- Frame budget cap (`MaxQueryBytes`) — Plan 04c.

### Decisions settled during brainstorming (2026-05-10)

- **D1.** One brainstorming pass covers the full deferred scope. If writing-plans surfaces size issues, split into 04b₂ / 04b₃ at that point (matches the 04b precedent).
- **D2.** `terminate_*` connections **close at first upstream `ReadyForQuery`** in 04b₂. The byte-passthrough loop is reserved for the modes that intentionally do not classify (passthrough, replication-allowed, cancel forwarded). Plan 04c replaces the close-at-RFQ terminator with the Q-frame classify loop.
- **D3.** Upstream TLS is system-roots-only verify-full equivalent. A test-only `Config.UpstreamTLSConfigForTest *tls.Config` field overrides when non-nil; production callsites leave it nil. No per-service skip-verify YAML knob.
- **D4.** SCRAM-SHA-256-PLUS detection lives inside the auth-forward loop, on the upstream→client direction, via typed `pgproto3.Frontend.Receive` and a scan of `*pgproto3.AuthenticationSASL.AuthMechanisms`.
- **D5.** `connState` is extended with upstream-side fields directly (no new sub-struct). Plan 04c/05 will refactor as the responsibility grows.
- **D6.** Replication opt-in is purely connection-rule-driven. `handleStartupMessage` selects `MatchKind=replication` when `replication` parameter is truthy and `MatchKind=connect` otherwise; a single evaluator call drives both default-deny (no rule) and opt-in (allow rule).
- **D7.** StartupMessage forwarding to upstream is re-encoded via `pgproto3.Frontend.Send`, not byte-perfect. Under `terminate_*`, inbound TLS termination has already broken channel binding, so byte fidelity is not load-bearing. SCRAM-PLUS fail-closes for the same reason.

## 2. Per-mode flow

| Mode | Inbound handshake | StartupMessage allow path | 04b₂ end-of-life |
|---|---|---|---|
| `terminate_reissue` | inbound TLS, leaf signed by AgentSH CA (04b) | dial upstream → `tls.Client` (system roots, verify-full) → forward StartupMessage → pump auth (peek for SCRAM-PLUS) → forward upstream RFQ → **close** | client received successful login + RFQ; proxy closes cleanly |
| `terminate_plaintext_upstream` | inbound TLS (04b) | dial upstream plaintext (loopback/RFC1918/trusted_network gated at `New` for IP literals, at dial for hostnames) → forward StartupMessage → pump auth → forward RFQ → **close** | same |
| `passthrough` | respond `'S'`, no inbound TLS terminate (NEW) | n/a — proxy never sees StartupMessage | dial upstream plaintext + **bidir byte-pump** until close. No DVW (service-level opt-out per spec §11.1). |
| terminate_* + replication=true (allowed rule) | terminate inbound TLS as usual | dial upstream → terminate or plaintext per service mode → forward StartupMessage with `replication` param → **bidir byte-pump** until close + DVW(`replication_passthrough`) | byte-pump |
| any + CancelRequest | accept | n/a | eval match_kind=cancel; allow → dial upstream plaintext, write client's 16-byte packet, **close** |

Subtlety: a `passthrough` listener cannot distinguish a CancelRequest from a connection at the byte level. Cancel governance under passthrough is degraded by design, matching spec §15.

## 3. Components

### New files (Linux-only unless noted)

- `internal/db/proxy/postgres/upstream.go` — `dialUpstream(ctx, svc)` returns `(net.Conn, *pgproto3.Frontend, error)`. For `terminate_reissue` wraps the dialed conn in `tls.Client` with system-root verify-full (MinVersion=TLS12, ServerName from `upstream` host). For `terminate_plaintext_upstream` returns the raw TCP conn. Honors `cfg.UpstreamTLSConfigForTest *tls.Config` when non-nil.
- `internal/db/proxy/postgres/upstream_test.go` — TLS round-trip against a test CA in a custom pool; verify-full rejects unknown-CA cert; plaintext dial against a `net.Listener`; ServerName carries upstream host; `UpstreamTLSConfigForTest` override path.
- `internal/db/proxy/postgres/authforward.go` — `forwardAuth(ctx, pc)` pumps frames between client `*Backend` and upstream `*Frontend` until upstream sends `ReadyForQuery`. On `*pgproto3.AuthenticationSASL`, scans `AuthMechanisms` for `SCRAM-SHA-256-PLUS`; if found, closes upstream + synthesizes `ErrorResponse(28000, SCRAM_PLUS_FAIL_CLOSED)` to client + returns a sentinel error so the caller emits `db_handshake_fail`. Captures `*pgproto3.BackendKeyData` into `connState.upstreamBKD` before forwarding. All other frames re-encoded and forwarded.
- `internal/db/proxy/postgres/authforward_test.go` — fake upstream scripts: AuthOK; SCRAM-256 only (forwards); SCRAM-256-PLUS (fail-closed); cleartext password; upstream ErrorResponse forwarded verbatim; upstream mid-SASL close → 08006.
- `internal/db/proxy/postgres/passthrough.go` — `bytePump(ctx, a, b net.Conn) error`. Symmetric bidir copy with one goroutine per direction; returns when either side closes or ctx is done.
- `internal/db/proxy/postgres/passthrough_test.go` — `net.Pipe()` pairs: normal close, ctx cancel, mid-stream EOF on either side.
- `internal/db/proxy/postgres/cancel.go` — `forwardCancel(ctx, svc, clientPacket []byte) error`. Dials plaintext (cancel is always plaintext per PG protocol), writes the 16-byte packet verbatim, closes. No auth, no TLS.
- `internal/db/proxy/postgres/cancel_test.go` — fake upstream listener captures the 16-byte payload; deny-path asserts no dial.
- `internal/db/proxy/postgres/testupstream_test.go` (test-only) — `newFakeUpstream(t, opts ...)` exposes a listener + cleanup. Backend role; pgx's `pgproto3.NewBackend` is what a server uses, so our fake upstream impersonates a server. Reused across `authforward_test.go`, `cancel_test.go`, and the spine round-trip tests.

### Modified files

- `internal/db/proxy/postgres/server.go`:
  - Remove the `tls_mode: passthrough` rejection from `New`.
  - Add `UpstreamTLSConfigForTest *tls.Config` field to `Config`.
- `internal/db/proxy/postgres/server_test.go`:
  - Flip `TestServer_New_RejectsPassthroughService` → `TestServer_New_AllowsPassthroughService`.
- `internal/db/proxy/postgres/proxyconn.go`:
  - Extend `connState`:
    ```go
    upstream        net.Conn
    upstreamFE      *pgproto3.Frontend
    upstreamBKD     struct{ PID, Secret uint32 }
    degradedReason  string
    ```
  - Ensure `pc.run`'s deferred path closes `upstream` on exit.
- `internal/db/proxy/postgres/handshake.go`:
  - `handleSSLRequest` adds a `passthrough` arm: respond `'S'` (when client sent SSLRequest), peek ≤4 KiB via existing `extractSNI`, dial upstream plaintext, write the peeked bytes, hand off to `bytePump`. Also handles the no-SSL passthrough arm (`StartupMessage` straight on a passthrough service) by branching into the same dial-and-pump path at the top of `dispatchStartup`.
  - `handleStartupMessage` removes the `replication=true` default-deny short-circuit; selects `MatchKind` based on `replication` and lets the evaluator decide.
  - On allow: branch to `dialUpstreamAndForward` (terminate_*) or `forwardReplicationStartupAndPump` (replication-allowed). Remove the `upstream_not_yet_wired` synthesized error.
  - `CancelRequest` arm: call `evaluateConnect` with `MatchKind=cancel`; on allow → `forwardCancel`; on deny → silent close.
- `internal/db/events/lifecycle.go` — add `DegradedReason string` (`replication_passthrough` / `gssenc_passthrough` / `tls_passthrough`). The `tls_passthrough` value is reserved for symmetry with Plan 05; 04b₂ never sets it (spec §11.1 is explicit).
- `internal/db/events/lifecycle_test.go` — round-trip + omitempty test.

### Package boundaries

Unchanged. `internal/db/proxy/postgres` still imports only `effects`, `policy`, `events`, `service`, `tlsleaf`, `classify/postgres`. No new external dependencies.

## 4. Data flow

### Allow-path under `terminate_*`

```
client--TLS-->proxy : SSLRequest, then StartupMessage (post-TLS)
proxy              : parse params, eval match_kind=connect, allow
proxy--TCP-->upstream
  if terminate_reissue: tls.Client (system roots, verify-full, ServerName=upstream-host)
proxy--PG-->upstream : Send(StartupMessage) via pgproto3.Frontend
loop forwardAuth:
  upstream--PG-->proxy : Receive() typed message
    if *AuthenticationSASL: scan AuthMechanisms for SCRAM-SHA-256-PLUS:
        - close upstream
        - synthesize ErrorResponse(28000, SCRAM_PLUS_FAIL_CLOSED)
        - emit db_handshake_fail(SCRAM_PLUS_FAIL_CLOSED)
        - return sentinel; caller closes client
    if *BackendKeyData: record into connState.upstreamBKD; forward to client
    if *ReadyForQuery: forward to client; break loop
    else: forward to client
  client--PG-->proxy : Receive() — forward to upstream
return; deferred cleanup closes both conns
```

### Replication opt-in (allowed by rule)

```
parse StartupMessage; replication parameter truthy
evaluate match_kind=replication → allow
dialUpstream(svc)   // terminate or plaintext per service.TLSMode
Send(StartupMessage) to upstream
emit degraded_visibility_warning{reason: replication_passthrough}
bytePump(client, upstream) until either side closes or ctx is done
```

Auth bytes are not inspected on this path; SCRAM-PLUS detection is intentionally skipped because the operator already opted into degraded visibility.

### `passthrough` mode

TLS not terminated on either side. The proxy is just a TCP shovel:

```
client sends SSLRequest (or skips it and goes straight to StartupMessage)
if SSLRequest:
  proxy responds 'S'
  proxy peeks ≤4 KiB of next bytes via extractSNI; record sniHostname (advisory)
  proxy dialUpstream plaintext
  proxy writes the peeked bytes to upstream first, then bytePump
else (plain-StartupMessage on a passthrough service):
  proxy dialUpstream plaintext
  proxy writes the read bytes to upstream first, then bytePump
no DVW (service-level opt-out, spec §11.1)
```

The upstream connection is **plaintext TCP**: we forward the client's already-encrypted bytes; the client's `SSLRequest` is the first thing upstream sees, and upstream's own `'S'` response is pumped back to client. The proxy never initiates SSLRequest of its own toward upstream in passthrough mode.

### `CancelRequest`

```
client connects, sends CancelRequest (16 bytes: 4 len + 4 magic + 4 PID + 4 Secret)
proxy evaluates match_kind=cancel
  deny → close silently (cancel has no error response per PG protocol)
  allow → forwardCancel:
    dial(svc.Upstream) plaintext (no SSLRequest, no auth)
    write the 16-byte client packet verbatim
    close upstream + client
```

## 5. Error mapping

| Failure | Client sees | Lifecycle event |
|---|---|---|
| Upstream dial timeout / refused | `ErrorResponse(SQLSTATE 08006, code=UPSTREAM_DIAL_FAIL, message)` + close | `db_handshake_fail{error_code: UPSTREAM_DIAL_FAIL}` |
| Upstream TLS handshake failure (terminate_reissue) | `ErrorResponse(08006, UPSTREAM_TLS_FAIL, message)` + close | `db_handshake_fail{error_code: UPSTREAM_TLS_FAIL}` |
| SCRAM-SHA-256-PLUS detected | `ErrorResponse(28000, SCRAM_PLUS_FAIL_CLOSED, "AgentSH DB proxy cannot terminate channel-bound SCRAM (SCRAM-SHA-256-PLUS). Disable channel binding upstream or use TLS passthrough; see docs/agentsh-db-access-spec.md §13.")` + close | `db_handshake_fail{error_code: SCRAM_PLUS_FAIL_CLOSED}` |
| Plaintext-upstream service declared with unsafe upstream | (already rejected at policy-load by `internal/db/policy/validate.go` — service never reaches proxy startup) | none |
| Replication opt-in denied (no rule, default) | unchanged from 04b: `ErrorResponse(28000, replication denied)` + close | none new |
| CancelRequest denied | silent TCP close | none |
| Upstream returns ErrorResponse during auth (e.g. wrong password) | forwarded to client verbatim, then close | none (real PG error, not synthesized) |

Stripped-message rule: upstream TLS error strings can leak internal hostnames or certificate details. Wrap with a fixed prefix and include the upstream `error.Error()` only when it does not match a small disallow-list (we keep this simple — include verbatim for 04b₂; tighten if security review requires).

## 6. Test strategy

### Unit tests, per file

| File | Coverage |
|---|---|
| `upstream_test.go` | `dialUpstream` happy path against `tls.Server` with test CA in a custom system pool; verify-full rejects unknown-CA cert; plaintext dial against `net.Listener`; ServerName carries upstream host; `UpstreamTLSConfigForTest` overrides system roots. |
| `authforward_test.go` | (a) AuthOK + ParameterStatus + BackendKeyData + RFQ('I') all forwarded, BKD captured, loop exits cleanly. (b) SASL SCRAM-256 only → forwarded both ways. (c) SASL with PLUS → fail-closed; client gets `28000`, upstream closed, one `db_handshake_fail` event. (d) Upstream ErrorResponse → forwarded. (e) Upstream mid-SASL close → 08006. |
| `passthrough_test.go` | `bytePump` via `net.Pipe()` pairs: bytes flow both directions, close terminates the pump, ctx cancel terminates the pump. |
| `cancel_test.go` | Fake upstream listener captures 16-byte cancel payload; deny-path asserts no dial. |
| `server_test.go` (additions) | `TestServer_New_AllowsPassthroughService` (flips 04b's reject test). Locality is already covered by `internal/db/policy/validate.go` tests; nothing new here. |
| `connect_rule_test.go` (additions) | Replication opt-in: `match_kind=replication, decision=allow` → allow; no rule → deny. Cancel: `match_kind=cancel` allow + deny. |
| `handshake_test.go` (additions) | Passthrough first-arm (SSLRequest then bytes pumped) + no-SSL arm (StartupMessage straight to pump); replication opt-in (bytes forwarded, DVW emitted); cancel allow + deny wired to `forwardCancel`. |
| `lifecycle_test.go` (additions) | `DegradedReason` round-trip + omitempty for `replication_passthrough` and `gssenc_passthrough`. |
| `tls_test.go` (updates) | Existing `TestTLS_TerminateReissue_RoundTrip` updated: instead of asserting `ErrorResponse(0A000)` after StartupMessage, assert the proxy dials the test's fake upstream and forwards the StartupMessage. Becomes the spine round-trip seed test. |

### Spine round-trip tests (against fake upstream)

1. `TestSpine_TerminateReissue_AuthOK_CloseAtRFQ` — `pgx` client through proxy → fake upstream scripts AuthOK + BKD + RFQ('I'). Assert client receives RFQ, BKD captured, proxy closes.
2. `TestSpine_TerminatePlaintextUpstream_AuthOK_CloseAtRFQ` — same shape, plaintext upstream over loopback.
3. `TestSpine_TerminateReissue_ScramPlus_FailClosed` — PLUS in SASL list → client `28000`; one `db_handshake_fail` event.
4. `TestSpine_Passthrough_BytePump` — passthrough service, fake upstream echoes plain TCP; client bytes round-trip.
5. `TestSpine_ReplicationOptIn_BytePump_EmitsDVW` — terminate_reissue + match_kind=replication allow rule; client sends StartupMessage with `replication=true`; bytes pump; one `degraded_visibility_warning{replication_passthrough}` event.
6. `TestSpine_Cancel_AllowedForwardsUnmapped` — allow rule with `match_kind=cancel`; fake upstream listener captures exactly the client's 16 bytes.
7. `TestSpine_Cancel_DeniedSilentClose` — deny rule; fake upstream listener sees zero connections.

Tests 1 uses real `jackc/pgx`. Tests 2-3 may use pgx or a hand-rolled client. Tests 4-7 use hand-rolled clients (no protocol semantics to assert).

### Fake upstream helper

`testupstream_test.go` exports:

```go
func newFakeUpstream(t *testing.T, opts ...fakeOpt) *fakeUpstream
// opts: withSASLMechanisms(...), withAuthOK(), withScript(func(*pgproto3.Backend) error), ...
// returns a listener address; proxy is configured with that as svc.Upstream
```

Re-used across spine tests; each composes a minimal upstream script.

### Cross-compile

`GOOS=windows go build ./...` and `GOOS=darwin go build ./...` after every task touching the proxy package. The Linux build tag on `proxy/postgres/*.go` and the existing `stub_other.go` keep this green.

### Pre-existing flakes

None of the new tests touch `internal/store`. The MEMORY.md-tracked Windows-only flakes (`TestFlushLoop_PeriodicSync`, `TestStore_*EmitsTransportLoss*`) are not regressions if they trip on rerun.

## 7. Open questions and risks

### Open questions to flag (not blockers)

1. **Upstream verify-full with `UpstreamTLSConfigForTest`.** A `nil`-defaulted field on `Config`; nothing prevents production code from accidentally setting it. The alternative — a `_test.go`-suffixed file with an internal setter only reachable from tests — is louder but more code. Comment-as-guard accepted; revisit if it leaks.

2. **`pgproto3.Frontend.Send(StartupMessage)` byte fidelity.** Re-encoding may differ from the client's exact bytes. PG accepts any valid encoding, but picky replication-control tools could break. If a report surfaces post-04b₂, swap to byte-buffered forwarding. Release-notes mention rather than design-around.

3. **DVW `tls_passthrough` reserved but unused.** Spec §11.1 explicitly: no per-connection DVW under `tls_mode: passthrough`. We keep the enum value for symmetry with `gssenc_passthrough` (Plan 05). If the spec moves to "one DVW on first-passthrough-connect-per-service" we'd wire it then.

4. **Cancel under passthrough.** Cancels and connections look identical at byte-pump entry. Cancel governance is degraded under passthrough by design, matching spec §15. Same release-notes mention as in 04b.

### Risks

- **SCRAM-SHA-256-PLUS prevalence.** Default modern Postgres builds advertise PLUS in the SASL mechanism list. Many operators trying `terminate_reissue` against a real cluster will hit `SCRAM_PLUS_FAIL_CLOSED` immediately. Mitigation: loud error message pointing at §13; documented workaround (disable upstream channel binding or use passthrough). Credential broker (Phase 4) is the long-term fix.
- **Upstream dial latency cascades into client timeout.** No retry, no backoff — one attempt, fail-closed. Acceptable for Phase 1.
- **BackendKeyData captured but un-mapped.** `connState.upstreamBKD` records real upstream PID/Secret and we forward them verbatim to client. Plan 06 will swap in a mapping table. Until then, a CancelRequest dispatch with client-visible values is forwarded un-mapped — but those values ARE the upstream's real PID/Secret in 04b₂, so cancel actually works end-to-end. That's a happy accident worth a loud release-notes call-out: Plan 06's mapping will break this and replace with the proper mapped path. Phase 1 operators upgrading 04b₂ → 06 may be confused by the regression. Flag in both 04b₂ and 06 release notes.

### Deferred (unchanged from 04b's deferred list)

- **Plan 04c.** Q-frame classify → forward / synthesize-deny; `db_statement` events; RFQ status-byte tracker; frame budget cap; spine test with real DBEvent assertions.
- **Plan 05.** Extended Query state machine; `allow_gss_encryption: true` GSSENC opt-in; in-tx approval; `rollback_then_continue`; FunctionCall protocol; COPY data frames.
- **Plan 06.** BackendKeyData mapping table; cancel governance via mapping lookup; R20 commit ordering.
- **Plan 07.** Out-of-process proxy under distinct SessionID; SO_PEERCRED → SessionID resolution; unavoidability bundle.

## 8. Done definition

Plan 04b₂ is done when:

1. `internal/db/proxy/postgres` builds on Linux; `GOOS=windows go build ./...` and `GOOS=darwin go build ./...` are green.
2. All unit tests above pass.
3. All 7 spine round-trip tests pass.
4. A YAML config with `unavoidability: observe` and a `terminate_reissue` service pointing at a real Postgres (no channel binding) lets a `pgx` client `Connect()` through the proxy, observes the connection complete, and observes a clean close at the first upstream `ReadyForQuery`. (Manual smoke; not committed.)
5. The 04b smoke driver (`cmd/dbproxy-smoke/main.go` if it was committed) is updated to talk to a real PG instead of synthesizing `0A000`, or removed.
6. Plan release notes include the "cancel happens to work un-mapped" call-out per §7 risks.
