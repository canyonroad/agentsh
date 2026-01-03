# Custom Provider Base URLs

## Overview

Allow configuring custom base URLs for LLM providers so the proxy can route traffic to alternative endpoints (self-hosted servers, corporate gateways, provider alternatives) that speak Anthropic or OpenAI dialects.

## Configuration

Rename `proxy.upstreams` to `proxy.providers` with flat URL values:

```yaml
proxy:
  mode: "embedded"
  port: 0
  providers:
    anthropic: "https://api.anthropic.com"   # optional, this is default
    openai: "https://api.openai.com"         # optional, this is default
```

Remove the separate `chatgpt` field entirely.

### Go Struct

```go
type ProxyConfig struct {
    Mode      string               `yaml:"mode"`
    Port      int                  `yaml:"port"`
    Providers ProxyProvidersConfig `yaml:"providers"`
}

type ProxyProvidersConfig struct {
    Anthropic string `yaml:"anthropic"`
    OpenAI    string `yaml:"openai"`
}
```

## Dialect Detection

Simplified to two dialects:

```go
type Dialect int

const (
    DialectUnknown Dialect = iota
    DialectAnthropic
    DialectOpenAI
)

func DetectDialect(r *http.Request) Dialect {
    if r.Header.Get("x-api-key") != "" || r.Header.Get("anthropic-version") != "" {
        return DialectAnthropic
    }
    if r.Header.Get("Authorization") != "" {
        return DialectOpenAI
    }
    return DialectUnknown
}
```

## Routing Logic

ChatGPT login flow is a special case, only active when using the default OpenAI URL:

```go
func (rw *RequestRewriter) GetUpstream(r *http.Request, dialect Dialect) *url.URL {
    if dialect == DialectOpenAI {
        // Custom OpenAI URL: route all traffic there
        if rw.isCustomOpenAI() {
            return rw.configs[DialectOpenAI].Upstream
        }

        // Default OpenAI: check if ChatGPT login (OAuth token, not sk-*)
        auth := r.Header.Get("Authorization")
        if strings.HasPrefix(auth, "Bearer ") && !strings.HasPrefix(auth, "Bearer sk-") {
            return rw.chatGPTUpstream  // hardcoded chatgpt.com/backend-api
        }

        return rw.configs[DialectOpenAI].Upstream
    }

    return rw.configs[dialect].Upstream
}
```

## Defaults

```go
func DefaultProxyConfig() ProxyConfig {
    return ProxyConfig{
        Mode: "embedded",
        Port: 0,
        Providers: ProxyProvidersConfig{
            Anthropic: "https://api.anthropic.com",
            OpenAI:    "https://api.openai.com",
        },
    }
}

const chatGPTUpstream = "https://chatgpt.com/backend-api"

func (cfg ProxyProvidersConfig) IsCustomOpenAI() bool {
    return cfg.OpenAI != "" && cfg.OpenAI != "https://api.openai.com"
}
```

## Files to Modify

| File | Changes |
|------|---------|
| `internal/config/proxy.go` | Rename `ProxyUpstreamsConfig` to `ProxyProvidersConfig`, remove `ChatGPT` field |
| `internal/config/config.go` | Update default loading to use `Providers`, remove ChatGPT default |
| `internal/llmproxy/dialect.go` | Remove `DialectChatGPT`, simplify detection, add ChatGPT routing in `GetUpstream` |
| `internal/llmproxy/proxy.go` | Update initialization to use `cfg.Providers`, add `isCustomOpenAI` flag |
| `internal/llmproxy/*_test.go` | Update tests for new config structure |

## Migration

Clean break - no backward compatibility with `upstreams`. Users must update their config files to use `providers`.

## Usage Examples

```yaml
# Custom LiteLLM server for OpenAI-compatible traffic
proxy:
  providers:
    openai: "https://my-litellm.local:4000"

# Corporate gateway for both providers
proxy:
  providers:
    anthropic: "https://gateway.corp.com/anthropic"
    openai: "https://gateway.corp.com/openai"

# Azure OpenAI
proxy:
  providers:
    openai: "https://my-resource.openai.azure.com/v1"
```
