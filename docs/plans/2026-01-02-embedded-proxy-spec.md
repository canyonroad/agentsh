# Embedded LLM Proxy Specification

**Date:** 2026-01-02
**Status:** Approved

## 1. Purpose and Scope

The embedded LLM proxy intercepts all LLM API requests from agents running under agentsh, providing:

- **DLP protection**: Redact PII before requests reach LLM providers
- **Audit logging**: Record all request/response pairs for compliance and debugging
- **Token tracking**: Extract usage metrics for cost attribution

The proxy operates in passthrough mode, supporting Anthropic, OpenAI (API key), and OpenAI (ChatGPT login) dialects. It detects the provider automatically from request characteristics.

### In Scope

- Embedded proxy (one per session)
- Local storage only
- DLP with redaction mode
- Configurable body storage with retention policy
- Token usage extraction

### Out of Scope (Deferred)

- Collector streaming
- External proxy mode
- Tokenization mode (reversible DLP)
- Rate limiting
- C&C integration

## 2. Session Lifecycle Integration

The proxy integrates with agentsh's existing session lifecycle:

```
agentsh session start --policy=default
    │
    ├── 1. Create session directory (~/.agentsh/sessions/<id>/)
    ├── 2. Start embedded proxy
    │       └── Bind to random available port (e.g., 52341)
    ├── 3. Set environment variables for agent:
    │       ANTHROPIC_BASE_URL=http://127.0.0.1:52341
    │       OPENAI_BASE_URL=http://127.0.0.1:52341
    │       AGENTSH_SESSION_ID=<id>
    ├── 4. Apply FUSE mount, network policy, etc. (existing)
    └── 5. Start agent process

agentsh session stop / agent exits
    │
    ├── 1. Agent process terminates
    ├── 2. Proxy drains pending requests (graceful shutdown)
    ├── 3. Proxy writes final stats to session
    └── 4. Cleanup (existing: FUSE unmount, etc.)
```

The proxy binds to `127.0.0.1` only (no external access). If the proxy fails to start, session creation fails (hard dependency).

## 3. Dialect Detection and Routing

The proxy auto-detects the LLM provider and routes to the correct upstream:

```
Request arrives
    │
    ├── Check x-api-key header present?
    │   └── Yes → Anthropic → api.anthropic.com
    │
    ├── Check anthropic-version header present?
    │   └── Yes → Anthropic → api.anthropic.com
    │
    ├── Check Authorization: Bearer header
    │   ├── Token starts with "sk-" → OpenAI API → api.openai.com
    │   └── Token doesn't start with "sk-" → ChatGPT login → chatgpt.com/backend-api/
    │
    └── No auth headers → Error (400 Bad Request)
```

### Upstream URL Rewriting

| Detected Mode | Upstream Base | Path Handling |
|---------------|---------------|---------------|
| Anthropic | `https://api.anthropic.com` | Passthrough (e.g., `/v1/messages`) |
| OpenAI API | `https://api.openai.com` | Passthrough (e.g., `/v1/chat/completions`) |
| ChatGPT login | `https://chatgpt.com/backend-api` | Rewrite: prepend `/backend-api` if needed |

### Auth Handling

The proxy is transparent to authentication:

| Provider | Auth Headers (passthrough) |
|----------|---------------------------|
| Anthropic | `x-api-key` or `Authorization: Bearer` |
| OpenAI API | `Authorization: Bearer sk-...` |
| ChatGPT login | `Authorization: Bearer <oauth-token>` |

The proxy:
- Forwards auth headers unchanged to upstream
- Redacts auth headers in logs (shows `[REDACTED]`)
- Does not validate or modify credentials

All upstreams are configurable to support proxies, private deployments, or Azure OpenAI.

## 4. DLP Processing

DLP runs on request bodies before forwarding to upstream. Response bodies are logged but not modified.

### Processing Flow

```
Request body received
    │
    ├── Parse as JSON (LLM APIs are JSON)
    │
    ├── Walk JSON structure, scan string values
    │   └── For each string field:
    │       ├── Match against PII patterns
    │       └── If match: redact in-place, record event
    │
    ├── Re-serialize JSON
    │
    └── Forward modified body to upstream
```

### Built-in PII Patterns

| Type | Pattern | Example Match |
|------|---------|---------------|
| Email | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | `john@example.com` |
| Phone | `(?:\+1)?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}` | `(555) 123-4567` |
| Credit Card | `\b(?:\d[ -]*?){13,19}\b` | `4111-1111-1111-1111` |
| SSN | `\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b` | `123-45-6789` |
| API Keys | `(?i)(?:sk\|api\|key\|secret\|token)[-_]?[a-zA-Z0-9]{20,}` | `sk-proj-abc123...` |

### Redaction Format

```
Before: "Contact john@example.com or call 555-123-4567"
After:  "Contact [REDACTED:email] or call [REDACTED:phone]"
```

### Custom Patterns

Custom patterns support separate internal name (for logs) and display name (sent to LLM):

```yaml
custom_patterns:
  - name: internal_customer_id    # Internal name (for logs/events)
    display: identifier           # Display name (sent to LLM)
    regex: "CUST-[0-9]{8}"
```

Result:
```
# What the LLM sees:
"Contact [REDACTED:identifier] for details"

# What gets logged internally:
{"type": "internal_customer_id", "count": 1}
```

### DLP Event Logging

```json
{
  "request_id": "req_abc123",
  "redactions": [
    {"field": "messages[0].content", "type": "email", "count": 1},
    {"field": "messages[0].content", "type": "phone", "count": 1}
  ]
}
```

## 5. Storage and Retention

Request/response logs stored alongside existing session data:

```
~/.agentsh/sessions/<session-id>/
├── events.jsonl           # Existing execution events
├── llm-requests.jsonl     # LLM request/response logs
└── llm-bodies/            # Full bodies (when enabled)
    ├── req_abc123.json
    └── req_abc123.resp.json
```

### Log Entry Format (llm-requests.jsonl)

```json
{
  "id": "req_abc123",
  "timestamp": "2026-01-02T10:30:00Z",
  "dialect": "anthropic",
  "request": {
    "method": "POST",
    "path": "/v1/messages",
    "body_size": 1234,
    "body_hash": "sha256:a1b2c3..."
  },
  "response": {
    "status": 200,
    "body_size": 5678,
    "duration_ms": 1234
  },
  "usage": {
    "input_tokens": 150,
    "output_tokens": 892
  },
  "dlp": {
    "redactions": [...]
  }
}
```

### Streaming Response Handling

Streaming SSE responses are buffered until complete, then logged as a single entry. This simplifies implementation and provides complete audit entries.

### Retention Policy

- Runs on session start (lightweight check)
- Deletes entire sessions, not individual files
- Logs eviction events

Configuration:
```yaml
storage:
  store_bodies: false           # Full bodies off by default
  retention:
    max_age_days: 30            # Delete sessions older than N days
    max_size_mb: 500            # Max total storage size
    eviction: oldest_first      # oldest_first | largest_first
```

## 6. Token Usage Extraction

The proxy extracts token counts from provider responses for cost attribution.

### Anthropic Response

```json
{
  "usage": {
    "input_tokens": 150,
    "output_tokens": 892
  }
}
```

### OpenAI Response

```json
{
  "usage": {
    "prompt_tokens": 150,
    "completion_tokens": 892,
    "total_tokens": 1042
  }
}
```

Token counts are normalized to `input_tokens` / `output_tokens` in logs regardless of provider.

## 7. CLI Integration

### Session Start (Proxy Auto-starts)

```bash
$ agentsh session start --policy=default

Session abc123 started
  Proxy: http://127.0.0.1:52341
  DLP: redact (email, phone, credit_card, ssn, api_keys)

Export for agent:
  export ANTHROPIC_BASE_URL=http://127.0.0.1:52341
  export OPENAI_BASE_URL=http://127.0.0.1:52341
```

### Proxy Status Command

```bash
$ agentsh proxy status

Proxy: running on :52341
Mode: embedded
DLP: redact (5 patterns active)
Requests: 23 (2 with redactions)
Tokens: 12,450 in / 34,200 out
```

### View LLM Logs

```bash
$ agentsh session logs <session-id> --type=llm

req_001  10:30:01  anthropic  /v1/messages  200  1.2s  150→892 tokens
req_002  10:30:15  anthropic  /v1/messages  200  0.8s  892→456 tokens  [2 redactions]
req_003  10:31:02  openai     /v1/chat/completions  200  2.1s  200→1024 tokens
```

### Enhanced Report

```bash
$ agentsh report <session-id> --level=detailed

## LLM Usage
| Provider  | Requests | Tokens In | Tokens Out | Errors |
|-----------|----------|-----------|------------|--------|
| Anthropic | 45       | 12,450    | 34,200     | 0      |
| OpenAI    | 3        | 600       | 1,500      | 1      |

## DLP Events
| Type  | Redactions |
|-------|------------|
| email | 12         |
| phone | 3          |
```

## 8. Configuration

Complete configuration in `~/.agentsh/config.yaml`:

```yaml
proxy:
  # embedded (default) | disabled
  mode: embedded

  # Port for embedded proxy (0 = random available)
  port: 0

  # Upstream overrides (optional)
  upstreams:
    anthropic: https://api.anthropic.com
    openai: https://api.openai.com
    chatgpt: https://chatgpt.com/backend-api

dlp:
  # redact | disabled
  mode: redact

  patterns:
    email: true
    phone: true
    credit_card: true
    ssn: true
    api_keys: true

  custom_patterns:
    - name: internal_customer_id
      display: identifier
      regex: "CUST-[0-9]{8}"

storage:
  store_bodies: false
  retention:
    max_age_days: 30
    max_size_mb: 500
    eviction: oldest_first
```

### Environment Variable Overrides

| Env Var | Effect |
|---------|--------|
| `AGENTSH_PROXY_MODE` | Override proxy mode |
| `AGENTSH_DLP_MODE` | Override DLP mode |
| `AGENTSH_PROXY_PORT` | Override proxy port |

## 9. Implementation Components

| Component | Location | Description |
|-----------|----------|-------------|
| Proxy server | `internal/llmproxy/proxy.go` | HTTP reverse proxy, lifecycle management |
| Dialect detection | `internal/llmproxy/dialect.go` | Provider detection, URL rewriting |
| DLP processor | `internal/llmproxy/dlp.go` | Pattern matching, redaction |
| Storage | `internal/llmproxy/storage.go` | JSONL logging, body storage |
| Token extraction | `internal/llmproxy/usage.go` | Parse usage from responses |
| Config | `internal/config/proxy.go` | Proxy and DLP configuration |
| CLI commands | `internal/cli/proxy.go` | Status, logs commands |
| Session integration | `internal/session/proxy.go` | Lifecycle hooks |

## 10. Dependencies

- Existing session lifecycle (`internal/session/`)
- Existing config loading (`internal/config/`)
- Existing storage paths (`~/.agentsh/sessions/`)
- Standard library: `net/http`, `net/http/httputil`

## 11. Future Phases (Not in This Spec)

| Feature | Description |
|---------|-------------|
| Tokenization mode | Reversible DLP with token store |
| Collector streaming | Events to hosted/self-hosted collector |
| External proxy mode | Disable embedded, use central proxy |
| C&C policy sync | Dynamic DLP config from central service |
| Rate limiting | Request/token quotas |

## References

- [OpenAI API Reference](https://platform.openai.com/docs/api-reference/introduction)
- [Codex CLI ChatGPT Login](https://help.openai.com/en/articles/11381614-codex-cli-and-sign-in-with-chatgpt)
- [OpenAI API Key Formats](https://community.openai.com/t/how-to-create-an-api-secret-key-with-prefix-sk-only-always-creates-sk-proj-keys/1263531)
