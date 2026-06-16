# Approved-Instance Authentication to Watchtower (agentsh client side, v1)

**Date:** 2026-06-16
**Status:** Design — brainstormed, awaiting spec review before planning
**Author:** Eran Sandler (with Claude)

## Summary

Only **approved** agentsh and Beacon instances should be allowed to connect to
Watchtower (WT). Both connect over the **same** WTP gRPC bidirectional stream, so
one credential scheme covers both, distinguished by a **type** carried on the
credential's server-side record (not self-asserted by the client).

The chosen model is **per-instance API keys with a key ID** (`<kid>.<secret>`),
presented in the existing `authorization: Bearer` gRPC metadata over TLS. v1 trust
logic is deliberately minimal — **a valid (present, unexpired, unrevoked) key is
trusted** — but the credential's *shape* (a public `kid` plus an opaque secret,
backed by a per-key registry row on the WT side) gives us granular revocation and
per-instance attribution immediately, and turns the eventual identity-based trust
(Phase 2) into a server-side validation change rather than a re-architecture.

This document is scoped to the **agentsh client side only** (this repo). Watchtower
is a separate repo (`canyonroad/watchtower`); its key registry, auth interceptor,
and the binding of the authenticated principal to policy resolution are specified
here **only as the contract the client depends on**, and are tracked for a separate
WT-side spec (see Non-goals).

## Context and motivation

- The WTP transport **already** supports exactly one of: a bearer token
  (`audit.watchtower.auth.token_file` / `token_env`) or mTLS client cert
  (`client_cert_auth`), mutually exclusive, over optional TLS
  (`internal/store/watchtower/dialer.go`, `internal/config/config.go:1224`).
  So this work is **convention + hardening + a forward-compat seam**, not new
  transport plumbing.
- agentsh is increasingly deployed inside **ephemeral agent sandboxes**. The
  credential is expected to be **injected at spawn time as an environment
  variable** (`token_env`), not baked into the image. The injection channel need
  not be secret; the value must instead be **per-instance and revocable** (and,
  in Phase 2, short-lived) so that reading it from the environment buys an
  attacker little.
- The decision-context policy-resolution feature
  (`2026-06-16-identity-context-policy-request-design.md`) has WT resolve the
  enforced policy from a **self-reported** `DecisionContext`. Its security note
  explicitly assumes the connection is authentic ("agentsh reports context
  honestly… it already holds the WT bearer/cert; WT decides how much to trust").
  Authenticating *which* instance is connecting is what makes that assumption
  hold. The complementary fix — having WT bind the authenticated principal to an
  approved identity so a self-reported context can only **narrow** privileges,
  never widen them — lives on the WT side and is deferred to that repo's spec.

## Decisions

1. **Per-instance API keys with a key ID.** Credential string is `<kid>.<secret>`:
   a non-secret key ID and an opaque secret. Chosen over a single shared key
   (no per-instance revocation/attribution) and over jumping straight to signed
   short-TTL tokens (requires a minter + in-session refresh now, explicitly
   deferred).
2. **v1 trust = validity only.** Present + unexpired + unrevoked ⇒ trusted.
   No identity binding logic in v1.
3. **Type is a server-side property of the key**, not self-asserted by the
   client. agentsh and Beacon present their own keys; a `type` (`agentsh` |
   `beacon`) lives on the WT registry row. A self-asserted type would be
   untrusted, so the client does not send one.
4. **Transport unchanged in shape:** credential rides `authorization: Bearer`
   gRPC metadata, beneath the WTP app messages. **No `wtp-protos` change in v1.**
   Auth success/failure is signaled with gRPC status codes at the stream
   interceptor, not with a new proto message.
5. **`kid` is for attribution only.** The client splits on the first `.` and logs
   only the `kid`; the secret is never logged. A value with no `.` is treated as
   an opaque legacy bearer token (logged as a short salted hash), preserving
   back-compat with today's plain bearer tokens.
6. **One new abstraction: a per-Dial `CredentialSource`.** The dialer fetches the
   credential through a function at each Dial instead of reading a static string
   once. v1 sources are static (env / file); this is what lets Phase 2 plug in
   rotating/attested credentials with no transport change.
7. **TLS coupling is warn-only.** When auth is configured together with a
   plaintext/insecure transport, log a loud startup WARN (matching today's
   `tls.insecure` behavior); do not hard-fail.
8. **Auth-reject must not reconnect-storm.** A gRPC `Unauthenticated` /
   `PermissionDenied` at stream open is classified distinctly: clamp reconnect
   backoff straight to its max, log a clear ERROR (with `kid`), and emit a
   reason-labeled reconnect metric — instead of the fast exponential ramp that
   transient dial errors get today.

## Non-goals (v1)

- **Watchtower-side key registry, auth interceptor, and principal→policy
  binding** (including the `DecisionContext`-narrowing fix). These live in
  `canyonroad/watchtower` and are tracked as a **separate WT-side spec**. This
  document only fixes the client contract they consume.
- **Signed / attested short-TTL tokens** (JWT/PASETO, cloud instance-identity
  documents, k8s projected ServiceAccount tokens, SPIFFE/SPIRE). Phase 2.
- **In-session credential refresh / re-auth on a live stream.** v1 fetches the
  credential per Dial (so a reconnect picks up a rotated file), but does not
  refresh mid-stream. Phase 2.
- **A `type` field on the wire**, mTLS changes, or any change to policy signing,
  the install hook, or the integrity chain.
- **Hard-failing on plaintext + auth** (warn-only, per Decision 7).

## Architecture

All changes are client-side and localized to the watchtower store/transport and
config layers.

- **`CredentialSource`** *(new; package `internal/store/watchtower/transport`)* —
  `type CredentialSource interface { Bearer(ctx context.Context) (string, error) }`
  (or an equivalent `func`). Returns the bearer value to present. Returning an
  empty string ⇒ no `authorization` header (anonymous, for local/test servers).
- **Static sources** *(new; small)* — an env-backed and a file-backed
  implementation. The config layer selects one from
  `audit.watchtower.auth.token_env` / `token_file` (already present) and wires it
  into `watchtower.Options`.
- **Dialer** (`internal/store/watchtower/dialer.go`) — replaces the static
  `opts.AuthBearer` read with a call to the `CredentialSource` at Dial time;
  appends `authorization: Bearer <value>` only when non-empty. mTLS path
  unchanged.
- **Reconnect loop** (`internal/store/watchtower/transport/transport.go`,
  `runConnecting` / the `StateConnecting` arm at ~`:1238`) — adds
  auth-reject classification: on `codes.Unauthenticated` / `codes.PermissionDenied`
  from stream open, log ERROR, set the next backoff to `BackoffMax`, and count a
  reason-labeled reconnect.
- **Config** (`internal/config/config.go`, `WatchtowerAuthConfig` /
  `validateWatchtower`) — adds the warn-only TLS-coupling check; auth-source
  exclusivity (`config.go:1224`) is unchanged.

Reused unchanged: the WTP stream, batcher, replay/backoff machinery, the
SessionInit/SessionAck flow, the DecisionContext reporting, and the integrity
chain.

### Data flow

```
spawn ephemeral sandbox
  -> control plane sets env var (e.g. AGENTSH_WT_TOKEN = "<kid>.<secret>")
config: audit.watchtower.auth.token_env = AGENTSH_WT_TOKEN
  -> envCredentialSource selected, wired into watchtower.Options
WTP Dial (each connect / reconnect)
  -> CredentialSource.Bearer(ctx) -> "<kid>.<secret>"
  -> gRPC metadata: authorization: Bearer <kid>.<secret>
  -> log attribution: kid only (secret never logged)
Watchtower stream interceptor (WT repo)
  valid+unexpired+unrevoked -> stream proceeds -> SessionInit/SessionAck as today
  invalid/revoked          -> gRPC Unauthenticated
Client on Unauthenticated/PermissionDenied at stream open
  -> ERROR log (with kid) + reason-labeled reconnect metric
  -> backoff clamped to BackoffMax (no fast ramp); reconnect keeps retrying slowly
     (a file-backed key replaced out-of-band is picked up on the next Dial)
```

## Credential format

```
credential := <kid> "." <secret>
  kid    : non-secret, URL-safe, identifies the registry row (logged, metered)
  secret : opaque high-entropy value (never logged)
legacy   : a value with no "." is presented verbatim as the bearer; logged as a
           short salted hash (back-compat with existing plain bearer tokens)
```

Parsing rule: split on the **first** `.` only (the secret may itself contain
`.`). The client performs **no** validation of the secret's structure — validity
is the server's job.

## Config

No new YAML keys are strictly required for v1 (the env/file sources already
exist). The auth block stays:

```yaml
audit:
  watchtower:
    tls:
      insecure: false          # warn-only coupling: auth + insecure => startup WARN
    auth:
      # exactly one of:
      token_env: AGENTSH_WT_TOKEN   # ephemeral agentsh: spawner-injected env var
      token_file: /etc/agentsh/wt.key  # persistent Beacon: on-disk credential
      client_cert_auth: false        # alternative: mTLS (isolated/persistent)
```

Validation changes:
- Keep the existing "exactly one of token_file / token_env / client_cert_auth"
  rule (`config.go:1224`).
- **Add** a warn-only check: if any auth source is set **and** the transport is
  plaintext/insecure (`tls.insecure: true`) for a non-loopback endpoint, log a
  loud startup WARN that the bearer secret will traverse plaintext.

## Error handling & security

- **Auth reject (bad/revoked/expired key):** classified at stream open as a
  distinct, non-fast-retry condition — clamp backoff to `BackoffMax`, ERROR log
  with `kid`, reason-labeled reconnect metric. Not treated as a fatal
  `StateShutdown`, so an out-of-band credential replacement (file source) or a
  Phase-2 refreshing source recovers without a process restart. (Today such a
  dial error is transient and fast-retries — the storm this prevents.)
- **Secret redaction (invariant):** the secret appears **only** in outbound gRPC
  metadata. It must never reach `slog`, error wraps, the GOAWAY-message log path,
  or any WTP app message / audit payload. Logs carry `kid` (or a salted hash for
  legacy values) only.
- **TLS:** warn-only coupling (Decision 7). Operators are responsible for not
  shipping bearer secrets over plaintext outside loopback; the WARN makes the
  risk loud.
- **Plaintext/insecure transport** remains a deliberate, WARN-logged choice as it
  is today.
- **Relationship to DecisionContext (#426):** v1 authenticates the connection; it
  does **not** yet stop a holder of a valid key from reporting a fabricated
  `DecisionContext` to obtain a weaker policy. That escalation is closed on the WT
  side by binding the authenticated principal (via `kid`) to an approved identity
  and letting the self-reported context only narrow — deferred to the WT-side
  spec. This is called out so the deferral is explicit, not forgotten.

## Phase 2 (unblocked, not built now)

- Swap the WT interceptor's registry lookup for **verifying a signed/attested
  short-TTL token** (control-plane-minted, or platform-attested via cloud
  instance-identity / projected ServiceAccount tokens). The agent side changes
  only the `CredentialSource` implementation (return a refreshing token);
  transport, config shape, and `kid` attribution are unchanged.
- Add **in-session refresh** so a token expiring mid-stream is renewed without a
  reconnect.
- Implement the **WT-side principal→approved-identity binding + context
  narrowing** that closes the forged-context escalation.

## Testing (agentsh side, TDD)

- **CredentialSource (unit, table-driven):** env source reads the named var;
  file source reads the file (and re-reads on the next Dial); empty value ⇒ no
  header; `<kid>.<secret>` parses to the right `kid`; legacy no-dot value is
  presented verbatim and logged as a hash.
- **Redaction (unit):** drive a Dial and an auth-reject through a captured log
  buffer; assert the secret never appears and the `kid` does.
- **Dialer (unit):** `authorization: Bearer` is set from the source and absent
  when the source returns empty; mTLS path unaffected.
- **Config validation (unit):** auth-source exclusivity preserved; auth +
  `tls.insecure` for a non-loopback endpoint emits the WARN (and does **not**
  error).
- **Reconnect classification (unit):** a fake dialer returning
  `status.Error(codes.Unauthenticated, …)` at stream open ⇒ backoff clamped to
  max, ERROR logged, reason-labeled reconnect counted; a transient dial error
  still fast-retries.
- **Integration (extend `internal/store/watchtower/testserver`):** assert the
  server received the expected `authorization` metadata; simulate an
  `Unauthenticated` reject and assert the client's slow-retry behavior.
- **Cross-cutting gates (AGENTS.md / CLAUDE.md):** full `go test ./...` and
  `GOOS=windows go build ./...` (the credential sources must compile and degrade
  cross-platform).

## Open items for planning

- Exact `CredentialSource` interface shape (`interface` vs `func`) and where the
  static sources live (`transport` vs a small `auth`-adjacent helper).
- The precise reconnect-metric reason label (extend the existing
  `wtp_reconnects_total{reason=…}` series; pick `auth_rejected`).
- Confirm the loopback-exemption predicate for the TLS WARN (endpoint host
  parse), consistent with how the endpoint is already parsed in the dialer.
