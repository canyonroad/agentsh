# Embedded LLM Proxy

agentsh includes an embedded HTTP proxy that intercepts all LLM API requests from AI agents, providing Data Loss Prevention (DLP), usage tracking, and audit logging.

## Overview

When enabled, the proxy:

1. **Starts automatically** with each session, binding to a random available port
2. **Sets environment variables** (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`) so agents route through the proxy
3. **Detects the LLM provider** (Anthropic, OpenAI API, ChatGPT) from request headers
4. **Applies DLP redaction** to request bodies before forwarding to upstream
5. **Logs requests and responses** with token usage to session storage
6. **Extracts token usage** for cost attribution and monitoring

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI Agent Session                          │
│  ┌────────────┐    ┌─────────────────┐    ┌─────────────────┐   │
│  │   Agent    │───▶│  Embedded Proxy │───▶│  LLM Provider   │   │
│  │ (Claude,   │    │                 │    │  (Anthropic,    │   │
│  │  Codex,    │    │  • DLP redact   │    │   OpenAI, etc.) │   │
│  │  etc.)     │◀───│  • Log request  │◀───│                 │   │
│  └────────────┘    │  • Track usage  │    └─────────────────┘   │
│                    └─────────────────┘                          │
│                           │                                     │
│                           ▼                                     │
│                    ┌─────────────────┐                          │
│                    │ Session Storage │                          │
│                    │ llm-requests.jsonl                         │
│                    └─────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

### Proxy Configuration

```yaml
# In server-config.yaml or session config
proxy:
  mode: embedded           # embedded | disabled
  port: 0                  # 0 = random available port

  # Provider base URLs (customize for alternative endpoints)
  providers:
    anthropic: https://api.anthropic.com
    openai: https://api.openai.com
```

### Custom Provider URLs

You can configure custom base URLs to route traffic to alternative LLM endpoints:

```yaml
proxy:
  mode: embedded
  providers:
    # Use LiteLLM as an OpenAI-compatible proxy
    openai: http://localhost:8000

    # Use a corporate Anthropic gateway
    anthropic: https://llm-gateway.corp.example.com/anthropic
```

**Use cases:**
- **LiteLLM/vLLM**: Route to self-hosted OpenAI-compatible endpoints
- **Azure OpenAI**: Point to Azure OpenAI Service endpoints
- **Corporate gateways**: Route through internal proxies for compliance
- **Local development**: Test against mock LLM servers

**ChatGPT login flow:** When `providers.openai` is set to the default URL (`https://api.openai.com`), OAuth tokens (non `sk-*` Bearer tokens) are automatically routed to the ChatGPT backend. Custom URLs route all traffic to the configured endpoint.

### DLP Configuration

```yaml
dlp:
  mode: redact             # redact | disabled

  # Built-in patterns (all enabled by default)
  patterns:
    email: true            # user@example.com
    phone: true            # 555-123-4567, (555) 123-4567
    credit_card: true      # 4111-1111-1111-1111
    ssn: true              # 123-45-6789
    api_keys: true         # sk-xxx, api-xxx, key_xxx

  # Custom patterns for organization-specific data
  custom_patterns:
    - name: customer_id          # Internal name (for logs)
      display: identifier        # Display name (shown in redacted output)
      regex: "CUST-[0-9]{8}"

    - name: internal_project
      display: project_code
      regex: "PROJ-[A-Z]{3}-[0-9]{4}"
```

### Storage Configuration

```yaml
storage:
  store_bodies: false      # Store full request/response bodies (Phase 2)
  retention:
    max_age_days: 30
    max_size_mb: 500
    eviction: oldest_first # oldest_first | largest_first
```

## Dialect Detection

The proxy automatically detects the LLM provider from request headers:

| Provider | Detection Method |
|----------|------------------|
| Anthropic | `x-api-key` header present, or `anthropic-version` header |
| OpenAI | `Authorization: Bearer *` header present |

**Note:** ChatGPT OAuth tokens (Bearer tokens without `sk-` prefix) are automatically routed to the ChatGPT backend when using the default OpenAI URL. When a custom `providers.openai` URL is configured, all OpenAI-dialect traffic routes to that endpoint.

Requests without recognized auth headers receive a `400 Bad Request` response.

## DLP Redaction

### How It Works

1. Request body is parsed as JSON
2. All string values are scanned against enabled patterns
3. Matches are replaced with `[REDACTED:pattern_name]`
4. Redaction metadata is logged (field path, pattern type, count)

### Example

**Original request:**
```json
{
  "messages": [{
    "role": "user",
    "content": "Email john@example.com about project CUST-12345678"
  }]
}
```

**After DLP redaction:**
```json
{
  "messages": [{
    "role": "user",
    "content": "Email [REDACTED:email] about project [REDACTED:identifier]"
  }]
}
```

**Log entry includes:**
```json
{
  "dlp": {
    "redactions": [
      {"field": "messages[0].content", "type": "email", "count": 1},
      {"field": "messages[0].content", "type": "customer_id", "count": 1}
    ]
  }
}
```

## Token Usage Tracking

The proxy extracts token usage from LLM responses and normalizes across providers:

| Provider | Response Format | Normalized |
|----------|-----------------|------------|
| Anthropic | `usage.input_tokens`, `usage.output_tokens` | Same |
| OpenAI | `usage.prompt_tokens`, `usage.completion_tokens` | `input_tokens`, `output_tokens` |

Usage is logged with each response and aggregated in session reports.

## Storage Format

Requests and responses are logged to `~/.agentsh/sessions/<session-id>/llm-requests.jsonl`:

**Request entry:**
```json
{
  "id": "req_abc123",
  "session_id": "sess_xyz",
  "timestamp": "2026-01-02T10:30:00Z",
  "dialect": "anthropic",
  "request": {
    "method": "POST",
    "path": "/v1/messages",
    "body_size": 1234,
    "body_hash": "sha256:..."
  },
  "dlp": {
    "redactions": [...]
  }
}
```

**Response entry:**
```json
{
  "request_id": "req_abc123",
  "session_id": "sess_xyz",
  "timestamp": "2026-01-02T10:30:01Z",
  "duration_ms": 1500,
  "response": {
    "status": 200,
    "body_size": 2048
  },
  "usage": {
    "input_tokens": 150,
    "output_tokens": 892
  }
}
```

## CLI Commands

### Proxy Status

```bash
# Status for latest session
agentsh proxy status

# Status for specific session
agentsh proxy status <session-id>

# JSON output
agentsh proxy status --json
```

**Output:**
```
Session: abc123
Proxy: running on 127.0.0.1:54321
Mode: embedded
DLP: redact (5 patterns active)
Requests: 42 (3 with redactions)
Tokens: 15,230 in / 28,456 out
```

### Session Logs with LLM Filter

```bash
# Show only LLM events
agentsh session logs <session-id> --type=llm

# Available types: llm, fs, net, exec
```

### Reports with LLM Stats

Session reports automatically include LLM usage when available:

```bash
agentsh report <session-id> --level=detailed
```

**Report includes:**

```markdown
## LLM Usage

| Provider | Requests | Input Tokens | Output Tokens |
|----------|----------|--------------|---------------|
| anthropic | 35 | 12,450 | 24,890 |
| openai | 7 | 2,780 | 3,566 |

## DLP Events

| Pattern | Redactions | Affected Requests |
|---------|------------|-------------------|
| email | 12 | 8 |
| api_key | 3 | 2 |
```

## Environment Variables

The proxy sets these environment variables for agent processes:

| Variable | Value | Purpose |
|----------|-------|---------|
| `ANTHROPIC_BASE_URL` | `http://127.0.0.1:<port>` | Route Anthropic SDK through proxy |
| `OPENAI_BASE_URL` | `http://127.0.0.1:<port>` | Route OpenAI SDK through proxy |
| `AGENTSH_SESSION_ID` | Session ID | Correlate agent requests with session |
| `<NAME>_API_URL` (or `expose_as`) | `http://127.0.0.1:<port>/svc/<name>/` | Route child code to a declared `http_services` upstream; one variable per service. Names must not collide with the three reserved names above. |

## Declared HTTP Services

`http_services:` is a top-level YAML policy block that lets operators declare named HTTP upstream services a child process can reach through the proxy gateway. Each entry gives a service a URL-safe name, binds it to an upstream HTTPS URL, and defines per-method, per-path rules — so an agent can be allowed to read GitHub issues but blocked from creating them, or gated behind an approval prompt for any write.

The gateway exposes each declared service as a path prefix `/svc/<name>/`. Child processes receive an env var (`<NAME>_API_URL` by default, or the name set in `expose_as`) pointing at that prefix — they treat it as the base URL and append their own paths. The proxy strips the prefix, evaluates the remaining path and method against the rules, and forwards to the upstream on allow.

### Configuration example

```yaml
http_services:
  - name: github                          # URL-safe identifier; used in /svc/github/
    upstream: https://api.github.com      # must be https unless allow_direct is set
    expose_as: GITHUB_API_URL             # optional; default is GITHUB_API_URL here too
    aliases: [api.github.com]             # extra hostnames for the fail-closed host check
    allow_direct: false                   # if false (default), direct calls to the host are blocked
    default: deny                         # allow | deny; applied when no rule matches

    rules:
      - name: read-issues
        methods: [GET]                    # empty or "*" means any method
        paths:
          - /repos/*/*/issues
          - /repos/*/*/issues/*
        decision: allow
        message: "reading issues is allowed"

      - name: create-issue-needs-approval
        methods: [POST]
        paths:
          - /repos/*/*/issues
        decision: approve
        message: "Agent wants to create an issue: approve?"
        timeout: 5m
```

### Env var contract

When the proxy starts, it injects one env var per declared service into the child process environment:

- The name is `<NAME>_API_URL` where `<NAME>` is the uppercased `name` field.
- If `expose_as` is set, that exact string is used instead.
- The value is the proxy base URL with the service prefix appended, e.g. `http://127.0.0.1:PORT/svc/github/`.
- Child code should treat this as the new base URL and append its own path segments — e.g. `/repos/owner/repo/issues` becomes `http://127.0.0.1:PORT/svc/github/repos/owner/repo/issues`.
- Env var names must match `[A-Za-z_][A-Za-z0-9_]*`, must not be `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, or `AGENTSH_SESSION_ID`, and must be unique across all declared services (comparison is case-insensitive on Windows).

### Credential substitution fields

When a service entry includes a `secret:` block, agentsh performs credential substitution
so the agent never sees the real credential. The following fields control this behaviour:

| Field | Required | Description |
|-------|----------|-------------|
| `secret.ref` | No | Secret store URI, e.g. `vault://kv/data/github#token`. Scheme must match a declared `providers:` entry. |
| `secret.format` | With `secret.ref` | Fake credential template, e.g. `ghp_{rand:36}`. Must have `{rand:N}` with N >= 24. |
| `inject.header.name` | No | Header to inject the real credential into, e.g. `Authorization`. Requires `secret`. |
| `inject.header.template` | With `inject.header.name` | Template string, must contain `{{secret}}`. E.g. `Bearer {{secret}}`. |
| `scrub_response` | No | Replace real credentials in response bodies with fakes. Defaults to `true` when `secret` is present, `false` otherwise. |

### Decision flow

For each request arriving at `/svc/<name>/...`:

1. The service is looked up by name from the path prefix.
2. The remaining path is checked for traversal: `//`, `.`, and `..` segments are rejected with 403 before any rule runs. A single trailing slash is stripped before matching.
3. Rules are evaluated in declaration order. The first rule whose `methods` and `paths` both match wins.
4. If no rule matches, the service's `default` applies (`deny` if not set).
5. `allow` forwards the request to the upstream; `deny` returns 403; `approve` gates on the approvals manager; `audit` logs and forwards.

### Fail-closed host enforcement

When a service is declared with `allow_direct: false` (the default), the netmonitor blocks direct HTTP/HTTPS connections to the upstream hostname and all aliases. The child process can only reach that host through the gateway prefix. This ensures all traffic is subject to the declared rules.

When a direct attempt is blocked, an `http_service_denied_direct` event is emitted in the audit stream. Setting `allow_direct: true` opts a single service out of this constraint — use it only as an escape hatch, for example when a third-party SDK cannot be configured to use a custom base URL.

### Logging

HTTP service requests are logged to the same JSONL file as LLM requests (`~/.agentsh/sessions/<session-id>/llm-requests.jsonl`). Log entries carry a `service_kind` discriminator: `"llm"` for LLM proxy traffic and `"http_service"` for declared service traffic. The same storage helpers (`StoreRequestBody`, `StoreResponseBody`) and body-hash recording that apply to LLM entries apply here, so requests and responses are stored and retrievable through the same session-log commands.

### When to use http_services

Use `http_services` when you want to expose a specific, audited surface of a third-party API to an agent, while blocking everything else on that host. If you only need to allow the agent to reach a host without per-path rule enforcement, a `network_rules` allow is simpler. If you need to allow a host but do not want the per-method/path audit trail, use network rules. `http_services` is the right tool when you need the combination of: specific allowed paths, block-everything-else on that host, approval gating for sensitive operations, and a full request/response audit log.

Use `http_services` with `secret:` when you want the gateway to manage credentials on
behalf of the agent — the agent never sees the real credential, and the gateway injects
it on allowed requests. This is the recommended pattern for any service where the agent
needs to authenticate but should not hold the credential directly.

## Security Considerations

### What the Proxy Protects Against

| Threat | Protection |
|--------|------------|
| PII leakage to LLM | DLP redaction removes sensitive data before it reaches the provider |
| Credential exposure | API key patterns detect and redact secrets in prompts |
| Untracked LLM usage | All requests logged with token counts for cost attribution |
| Shadow AI | Agents must route through proxy; direct calls bypass session controls |

### What the Proxy Does NOT Protect Against

| Threat | Reason |
|--------|--------|
| Encoded/obfuscated PII | Regex patterns only match plain text |
| PII in images/files | Only text content is scanned |
| Malicious agent bypassing proxy | Agent could ignore env vars (defense in depth with network rules) |
| LLM provider data retention | Data reaches provider after redaction |

### Best Practices

1. **Enable network rules** to block direct LLM API access, forcing agents through the proxy
2. **Review custom patterns** to cover organization-specific sensitive data
3. **Monitor redaction logs** to detect and address data leakage attempts
4. **Set retention policies** appropriate for your compliance requirements

## Troubleshooting

### Proxy Not Starting

```bash
# Check proxy status
agentsh proxy status

# Check session logs for errors
agentsh session logs <session-id> --type=llm
```

### Requests Not Routed Through Proxy

Verify environment variables are set:
```bash
echo $ANTHROPIC_BASE_URL
echo $OPENAI_BASE_URL
```

If empty, the proxy may be disabled or failed to start.

### DLP Not Redacting Expected Patterns

1. Verify DLP mode is `redact` (not `disabled`)
2. Check that the relevant pattern is enabled
3. For custom patterns, verify the regex syntax

### High Latency

The proxy adds minimal overhead (<10ms typically). If experiencing high latency:
1. Check network connectivity to upstream
2. Verify storage disk I/O isn't saturated
3. Consider increasing storage retention eviction frequency
