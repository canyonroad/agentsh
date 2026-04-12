# HTTP Services Cookbook

This page is a practical, recipe-first guide to agentsh's **http_services** policy block:
how to route an agent's outbound HTTP API calls through the proxy gateway, restrict
which methods and paths are allowed, gate writes behind an approval prompt, and audit
sensitive operations without blocking them.

For the full policy language reference (variables, network redirect, signal rules,
troubleshooting), see [`docs/operations/policies.md`](../operations/policies.md). For the
complete `http_services:` configuration reference including env var rules and validation
guarantees, see [Declared HTTP Services](../llm-proxy.md#declared-http-services).

## How http_services routing works

Declaring a service in `http_services:` does two things at once:

1. The proxy exposes `/svc/<name>/` as a gateway for that service. Child processes receive
   `<NAME>_API_URL=http://127.0.0.1:PORT/svc/<name>/` (or the name set in `expose_as`) in
   their environment. Code that uses this variable as its base URL automatically routes
   through the gateway.

2. The netmonitor blocks direct HTTP/HTTPS connections to the upstream hostname and all
   declared aliases. The agent cannot reach the host except through the gateway, so all
   traffic is subject to the declared rules.

Rules are evaluated in declaration order; the first rule whose `methods` and `paths` both
match wins. If no rule matches, the service's `default` applies (`deny` when not set).

## How credential substitution works

When an `http_services` entry includes a `secret:` block, agentsh performs credential
substitution so the agent never sees the real credential:

1. **At session start**, agentsh fetches the real secret from the provider declared
   in `providers:` (Vault, keyring, AWS SM, etc.).
2. **A fake credential** with the same format and length is generated using `secret.format`.
3. **The agent receives** `<NAME>_API_URL=http://127.0.0.1:PORT/svc/<name>/` and interacts
   with the gateway using the fake credential — it never sees the real one.
4. **On egress**, the gateway replaces fakes with reals in the request body, headers,
   query string, and URL path. If `inject.header` is configured, the real credential is
   injected into the specified header from scratch.
5. **On response**, the gateway replaces any reals in the response body with fakes before
   returning to the agent.
6. **Leak guard** blocks requests that carry a fake credential to the wrong service (cross-
   service use) or to an unmatched host (exfiltration attempt), returning 403.

Credential substitution composes with path/verb rules: a service can have both `secret:`
and `rules:` — the gateway evaluates rules first, then performs substitution on allowed
requests.

## Recipe: allow an agent to read but not write a GitHub repo

An agent that needs to read issues but must not be allowed to create or modify them:

```yaml
http_services:
  - name: github
    upstream: https://api.github.com
    aliases: [api.github.com]
    default: deny

    rules:
      - name: read-issues
        methods: [GET]
        paths:
          - /repos/*/*/issues
          - /repos/*/*/issues/*
        decision: allow

      - name: read-repo-meta
        methods: [GET]
        paths:
          - /repos/*/*
        decision: allow
```

The agent receives `GITHUB_API_URL=http://127.0.0.1:PORT/svc/github/`. Code that appends
`repos/owner/repo/issues` to that base URL will be forwarded. Any other method or path
hits `default: deny` and gets a 403.

**How to verify:** Run the agent and tail the session log:

```bash
agentsh session logs <session-id> --type=llm
```

Entries with `"service_kind": "http_service"` and `"service": "github"` appear for each
proxied request. Direct connections to `api.github.com` appear as
`http_service_denied_direct` events.

## Recipe: gate writes behind an approval prompt

Add a rule before the catch-all deny that requires a human to approve issue creation:

```yaml
http_services:
  - name: github
    upstream: https://api.github.com
    aliases: [api.github.com]
    default: deny

    rules:
      - name: read-issues
        methods: [GET]
        paths:
          - /repos/*/*/issues
          - /repos/*/*/issues/*
        decision: allow

      - name: create-issue-needs-approval
        methods: [POST]
        paths:
          - /repos/*/*/issues
        decision: approve
        message: "Agent wants to create an issue in this repo. Approve?"
        timeout: 5m
```

When the agent POSTs to `/repos/owner/repo/issues`, the request is held and the approval
prompt is shown through the configured approval channel (terminal, TOTP, WebAuthn, or
API). If denied, the agent receives a 403. See [`docs/approval-auth.md`](../approval-auth.md)
for approval channel configuration.

The `message` field is shown to the approver alongside the request method and path, so
write something a human can act on without reading raw JSON.

## Recipe: expose an internal microservice at a custom env var

When a service has both a public DNS name and an internal alias, list both. Use `expose_as`
to choose a meaningful env var name:

```yaml
http_services:
  - name: orders
    upstream: https://orders.internal.example.com
    expose_as: INTERNAL_ORDERS_URL
    aliases:
      - orders.internal.example.com
      - orders-api.corp.example.com
    allow_direct: false
    default: deny

    rules:
      - name: read-order
        methods: [GET]
        paths:
          - /orders/*
          - /orders/*/items
        decision: allow

      - name: update-order-status
        methods: [PATCH]
        paths:
          - /orders/*/status
        decision: approve
        message: "Agent wants to update order status. Approve?"
        timeout: 2m
```

The agent receives `INTERNAL_ORDERS_URL=http://127.0.0.1:PORT/svc/orders/`. The
netmonitor blocks direct connections to both `orders.internal.example.com` and
`orders-api.corp.example.com`, so the agent cannot bypass the gateway by using either
hostname directly.

## Recipe: audit a third-party API without blocking

When you want full visibility into what an agent does with a third-party API but do not
need to block individual operations, set `default: allow` and add `decision: audit` rules
for paths you want to track closely:

```yaml
http_services:
  - name: stripe
    upstream: https://api.stripe.com
    aliases: [api.stripe.com]
    default: allow    # allow all paths not matched by a rule below

    rules:
      - name: audit-charges
        methods: ["*"]
        paths:
          - /v1/charges
          - /v1/charges/*
        decision: audit

      - name: audit-payouts
        methods: ["*"]
        paths:
          - /v1/payouts
          - /v1/payouts/*
        decision: audit
```

`decision: audit` forwards the request to the upstream and logs it to `llm-requests.jsonl`
with `"service_kind": "http_service"`. Paths not matched by any rule fall through to
`default: allow` and are still logged (without the explicit `audit` tag), because the
gateway records every proxied request.

## Recipe: route GitHub through the gateway with a Vault-backed token

Declare a Vault provider and a GitHub service with credential injection and read-only
rules:

```yaml
providers:
  vault:
    type: vault
    address: https://vault.corp.internal
    auth:
      method: token
      token_ref: keyring://agentsh/vault_token
  keyring:
    type: keyring

http_services:
  - name: github
    upstream: https://api.github.com
    aliases: [api.github.com]
    default: deny

    secret:
      ref: vault://kv/data/github#token
      format: "ghp_{rand:36}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"

    rules:
      - name: read-issues
        methods: [GET]
        paths:
          - /repos/*/*/issues
          - /repos/*/*/issues/*
        decision: allow
```

The agent receives `GITHUB_API_URL=http://127.0.0.1:PORT/svc/github/`. When it reads
issues, the gateway evaluates the allow rule, substitutes the fake token with the real
Vault-sourced token, and forwards to `api.github.com` over TLS. The real token never
enters the agent's address space.

## Recipe: use OS keyring for a simple API key

For a service that only needs credential injection without path filtering:

```yaml
providers:
  keyring:
    type: keyring

http_services:
  - name: anthropic
    upstream: https://api.anthropic.com
    secret:
      ref: keyring://agentsh/anthropic_key
      format: "sk-ant-{rand:93}"
    inject:
      header:
        name: x-api-key
        template: "{{secret}}"
```

No `rules:` or `default:` — the service allows all requests (credentials-only mode).
The gateway injects the real API key on every request and scrubs it from responses.

## Recipe: credentials and filtering combined

A service with both credential injection and per-path rules:

```yaml
http_services:
  - name: stripe
    upstream: https://api.stripe.com
    aliases: [api.stripe.com]
    default: deny

    secret:
      ref: vault://kv/data/stripe#api_key
      format: "sk_live_{rand:48}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"

    rules:
      - name: read-customers
        methods: [GET]
        paths:
          - /v1/customers
          - /v1/customers/*
        decision: allow

      - name: create-charge-needs-approval
        methods: [POST]
        paths:
          - /v1/charges
        decision: approve
        message: "Agent wants to create a Stripe charge. Approve?"
        timeout: 2m
```

The agent can read customers freely. Creating charges requires operator approval.
The real Stripe API key is injected on allowed requests and never visible to the agent.

## Gotchas

**Paths are globs with `/` as the separator, not regex.**
`/repos/*/*/issues` matches `/repos/owner/repo/issues` but not
`/repos/owner/repo/labels`. Use the `gobwas/glob` documentation as reference; the
key difference from shell globs is that `/` is treated as a separator character.

**`*` does not cross segment boundaries.**
`/repos/*/issues` matches `/repos/owner/issues` but not `/repos/owner/repo/issues`
because there are two segments (`owner` and `repo`) between `repos` and `issues`. Use
`**` for multi-segment matches: `/repos/**/issues` matches both.

**Traversal is rejected before rule matching.**
Paths containing `//`, `.`, or `..` segments are rejected with 403 before any rule is
evaluated. Do not write rules intended to match those patterns — they will never fire.

**A single trailing slash is stripped before matching.**
`/repos/owner/repo/issues/` is treated the same as `/repos/owner/repo/issues` during
rule evaluation. Write rules without trailing slashes.

**Declaring a service blocks direct access to its host.**
Setting `allow_direct: false` (the default) means any direct connection to the upstream
host or its aliases is blocked at the network layer. Set `allow_direct: true` only as an
escape hatch when a third-party SDK cannot be pointed at a custom base URL.

**Env var names collide with the LLM proxy.**
The names `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, and `AGENTSH_SESSION_ID` are reserved.
Using a service name that would derive one of these names (e.g. `name: openai_base`) will
fail at policy load. Use `expose_as` to choose a different name if your service name would
collide, or rename the service.

## Cross-references

- **Full http_services reference:** [`docs/llm-proxy.md#declared-http-services`](../llm-proxy.md#declared-http-services)
  — complete config schema, env var contract, decision flow, fail-closed behavior, logging.
- **Policy language reference:** [`docs/operations/policies.md`](../operations/policies.md)
  — variables, network redirect, signal rules, troubleshooting.
- **Approval channels and auth:** [`docs/approval-auth.md`](../approval-auth.md)
  — how `decision: approve` reaches a human, anti-self-approval, WebAuthn/TOTP/API modes.
- **Command policies cookbook:** [`docs/cookbook/command-policies.md`](command-policies.md)
  — parallel guide for `command_rules`.
