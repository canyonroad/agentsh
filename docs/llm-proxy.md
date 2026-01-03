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
