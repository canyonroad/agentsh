# Embedded Proxy Design

**Date:** 2026-01-02
**Status:** Implemented

## Overview

Add an embedded HTTP proxy to agentsh that intercepts LLM API requests from agents, providing:
- DLP (Data Loss Prevention) via PII redaction/tokenization
- Request/response logging for audit trails
- Passthrough support for multiple LLM providers (Anthropic, OpenAI)

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│ agentsh                                                                  │
│  ├── session manager                                                     │
│  ├── embedded proxy (DLP)                                                │
│  │     ├── Anthropic dialect handler                                     │
│  │     ├── OpenAI dialect handler                                        │
│  │     └── DLP processor                                                 │
│  └── local storage                                                       │
│        ~/.agentsh/sessions/<session-id>/                                 │
│            ├── events.jsonl      (existing execution events)             │
│            └── llm-requests.jsonl (new: request/response logs)           │
└──────────────────────────────────────────────────────────────────────────┘
```

## Deployment Modes

### Mode 1: Embedded (Default)

Proxy runs inside agentsh process. Zero configuration required.

```
Agent (Claude Code / Codex / OpenCode)
    │
    │ ANTHROPIC_BASE_URL=http://localhost:<port>
    │ OPENAI_BASE_URL=http://localhost:<port>
    │ SESSION_ID=<session-id>
    │
    ▼
Embedded Proxy (inside agentsh)
    │
    │ Forwards to upstream
    ▼
api.anthropic.com / api.openai.com / chatgpt.com
```

### Mode 2: External Proxy

Embedded proxy disabled; agent points to customer's central proxy.

```
Agent
    │
    │ ANTHROPIC_BASE_URL=https://proxy.customer.com
    │ SESSION_ID=<session-id>
    │
    ▼
Customer's Central Proxy ───stream───▶ Customer's Collector
```

### Mode 3: Disabled

No proxy interception. Direct agent-to-API communication.

## Provider Dialects

The proxy must handle different API formats in passthrough mode, detecting the target provider from the request path or headers.

### Anthropic API

| Property | Value |
|----------|-------|
| Default upstream | `https://api.anthropic.com` |
| Auth header | `x-api-key` or `Authorization: Bearer` |
| Content-Type | `application/json` |
| Streaming | SSE via `stream: true` |
| Key endpoints | `/v1/messages`, `/v1/complete` |

### OpenAI API (API Key mode)

| Property | Value |
|----------|-------|
| Default upstream | `https://api.openai.com/v1` |
| Auth header | `Authorization: Bearer <api-key>` |
| Content-Type | `application/json` |
| Streaming | SSE via `stream: true` |
| Key endpoints | `/v1/chat/completions`, `/v1/responses` |

### OpenAI API (ChatGPT Account Login mode)

When using ChatGPT account login (not API key), tools like Codex CLI use a different backend.

| Property | Value |
|----------|-------|
| Default upstream | `https://chatgpt.com/backend-api/` |
| Auth | OAuth token from ChatGPT login flow |
| Content-Type | `application/json` |
| Note | Different request/response format than standard API |

Reference: [Codex CLI Config](https://github.com/openai/codex/issues/2760) - `chatgpt_base_url` setting.

## Request Flow

```
1. Agent sends request to proxy
2. Proxy detects dialect from:
   - Request path (/v1/messages → Anthropic, /v1/chat/completions → OpenAI)
   - Host header if present
   - Configuration override
3. DLP processor scans request body
   - Redact/tokenize PII before forwarding
   - Log redaction events
4. Proxy forwards to upstream
5. Response streams back through proxy
6. Proxy logs request/response (with DLP applied)
7. Response delivered to agent
```

## DLP Processing

### Redaction vs Tokenization

| Mode | Behavior | Use Case |
|------|----------|----------|
| Redact | Replace PII with `[REDACTED:type]` | Data never leaves org |
| Tokenize | Replace with reversible token | Internal reports can reconstruct |

### PII Types to Detect

- Email addresses
- Phone numbers
- Credit card numbers
- SSN/national IDs
- API keys/secrets (high entropy strings)
- Custom patterns (configurable regex)

### DLP Event Logging

```json
{
  "session_id": "abc123",
  "timestamp": "2026-01-02T10:30:00Z",
  "type": "dlp.redaction",
  "request_id": "req_xyz",
  "redactions": [
    {"field": "messages[0].content", "type": "email", "count": 2},
    {"field": "messages[1].content", "type": "phone", "count": 1}
  ]
}
```

## Storage

### Local Storage (Free Tier)

All data stored locally alongside existing session data:

```
~/.agentsh/sessions/<session-id>/
├── events.jsonl           # existing execution events
├── llm-requests.jsonl     # new: LLM request/response logs
└── dlp-tokens.json        # tokenization map (if using tokenize mode)
```

### Request/Response Log Format

```json
{
  "id": "req_abc123",
  "session_id": "sess_xyz",
  "timestamp": "2026-01-02T10:30:00Z",
  "dialect": "anthropic",
  "request": {
    "method": "POST",
    "path": "/v1/messages",
    "headers": {"x-api-key": "[REDACTED]"},
    "body_hash": "sha256:...",
    "body_size": 1234
  },
  "response": {
    "status": 200,
    "headers": {},
    "body_hash": "sha256:...",
    "body_size": 5678,
    "duration_ms": 1234
  },
  "dlp": {
    "redactions": [...]
  }
}
```

Note: Full bodies stored separately or configurable (size/privacy tradeoffs).

## Collector Streaming (Paid Tier)

When configured, events stream to hosted collector:

```yaml
# ~/.agentsh/config.yaml
collector:
  enabled: true
  endpoint: https://collector.agentsh.io
  api_key: ask_xxx
```

### Stream Protocol

HTTPS POST with batched events:

```
POST /v1/events
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "batch": [
    {"session_id": "...", "type": "llm.request", ...},
    {"session_id": "...", "type": "tool.call", ...}
  ]
}
```

### Buffering

Local buffer for network failures:
```
~/.agentsh/buffer/
└── pending-events.jsonl  # flushed to collector on reconnect
```

## Configuration

```yaml
# ~/.agentsh/config.yaml

proxy:
  # embedded (default) | external | disabled
  mode: embedded

  # Port for embedded proxy (0 = random available port)
  port: 0

  # When mode=external, agent uses this URL
  external_url: https://proxy.customer.com

  # Upstream URLs (auto-detected from dialect, but overridable)
  upstreams:
    anthropic: https://api.anthropic.com
    openai: https://api.openai.com/v1
    chatgpt: https://chatgpt.com/backend-api/

dlp:
  # redact | tokenize | disabled
  mode: redact

  # Built-in patterns
  patterns:
    email: true
    phone: true
    credit_card: true
    ssn: true
    api_keys: true

  # Custom patterns
  custom_patterns:
    - name: internal_id
      regex: "CUST-[0-9]{8}"

collector:
  enabled: false
  endpoint: ""
  api_key: ""
```

## CLI Integration

```bash
# Session start sets up proxy
agentsh session start --policy=default
# Outputs: SESSION_ID=xxx ANTHROPIC_BASE_URL=http://localhost:18080 ...

# Check proxy status
agentsh proxy status
# Outputs: Proxy running on :18080, mode: embedded, dialect: auto-detect

# View LLM request logs
agentsh session logs <session-id> --type=llm

# Report includes LLM stats
agentsh report <session-id> --level=detailed
# Now includes: token counts, request counts, DLP events
```

## Business Model

| Tier | Proxy | Storage | Collector |
|------|-------|---------|-----------|
| Free | Embedded | Local only | ✗ |
| Pro | Embedded | Local + Cloud sync | ✓ Hosted |
| Enterprise | Embedded or External | Customer choice | Self-hosted option |

### Free Tier Value

- Full DLP protection
- Local audit logs
- Privacy (nothing leaves machine)

### Paid Tier Value

- Cross-machine search
- Team visibility
- Long-term retention
- Analytics dashboard
- Compliance exports

## Security Considerations

1. **Credentials**: Proxy sees API keys in headers - must not log them
2. **Local storage**: Session data should have appropriate file permissions
3. **Tokenization keys**: If using tokenize mode, token map is sensitive
4. **Collector transport**: TLS required, API key for auth

## Implementation Phases

### Phase 1: Basic Proxy
- HTTP proxy with dialect detection
- Passthrough to upstream APIs
- Request/response logging (no DLP yet)
- Local storage only

### Phase 2: DLP
- PII detection patterns
- Redaction mode
- DLP event logging

### Phase 3: Tokenization
- Reversible token generation
- Token map storage
- Detokenization for reports

### Phase 4: Collector
- Streaming protocol
- Buffering/retry logic
- Cloud collector service

### Phase 5: External Proxy Mode
- Configuration for external proxy
- Disable embedded proxy
- Session ID correlation

## Open Questions

1. **Body storage**: Store full request/response bodies or just hashes/summaries?
2. **Streaming responses**: How to handle SSE streaming for logging?
3. **Token limits**: Track token usage per session?
4. **Rate limiting**: Should proxy enforce any rate limits?
5. **Multiple agents**: One proxy instance per session or shared?

## References

- [OpenAI API Reference](https://platform.openai.com/docs/api-reference/introduction)
- [Codex CLI ChatGPT Login](https://help.openai.com/en/articles/11381614-codex-cli-and-sign-in-with-chatgpt)
- [Codex CLI Config](https://github.com/openai/codex/issues/2760) - chatgpt_base_url setting
