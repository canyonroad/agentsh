# AgentSH Policy Schema Reference

This file is the authoritative YAML-author-facing schema for AgentSH policy files.
It is read at invocation time by both the `policy-create` and `policy-edit` skills
and must be self-contained — the reader will not have access to the AgentSH source code.

Field names and types are verified against `internal/policy/model.go`.

---

## Top-Level Structure

```yaml
version: 1                    # Required. Always 1.
name: "policy-name"           # Required. Alphanumeric, hyphens, underscores.
description: |                # Required. Multi-line description.
  What this policy does.

metadata: []                  # Optional non-enforcing rule metadata
file_rules: []                # File operation rules
network_rules: []             # Network connection rules
command_rules: []             # Command execution rules
unix_socket_rules: []         # Unix socket rules
registry_rules: []            # Windows registry rules
signal_rules: []              # Signal sending rules
dns_redirects: []             # DNS redirect rules
connect_redirects: []         # TCP connect redirect rules
providers: {}                 # Secret provider declarations for http_services
http_services: []             # Declared HTTP API gateway services
db_services: {}               # Declared database upstreams (Postgres-family only today)
database_rules: []            # Database statement rules
database_connection_rules: [] # Database connection/cancel/replication rules
policies: {}                  # Opaque policy sub-blocks, currently policies.db
resource_limits: {}           # Resource limits
env_policy: {}                # Environment variable policy
audit: {}                     # Audit settings
env_inject: {}                # Injected environment variables (map of key: value)
mcp_rules: {}                 # MCP tool/server rules
process_contexts: {}          # Parent-conditional policies
process_identities: {}        # Process identity definitions
package_rules: []             # Package install check rules
transparent_commands: {}      # Override transparent command set
```

---

## Rule Types

### metadata[]

Metadata is non-enforcing. AgentSH-generated policy bundles use it to correlate generic rule names back to higher-level sources such as DB unavoidability.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| rule_name | string | yes | Name of the rule this metadata describes |
| source | string | yes | Metadata producer, e.g. `db_unavoidability` |
| db_service | string | no | Related DB service name |
| bypass_mode | string | no | Bypass class such as `tcp_direct`, `unix_socket`, `dns_alias`, `port_forward_tool`, `custom_tunnel` |
| destination | string | no | Related destination tuple or local socket class |

### file_rules[]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier (verb-noun) |
| description | string | yes | Human-readable description |
| paths | string[] | yes | Glob patterns. Supports `${PROJECT_ROOT}`, `${HOME}`, `${GIT_ROOT}`, `**`, `*` |
| operations | string[] | yes | `read`, `write`, `delete`, `stat`, `list`, `open`, `create`, `mkdir`, `chmod`, `rename`, `rmdir`, `readlink`, `*` |
| decision | string | yes | `allow`, `deny`, `approve`, `redirect`, `soft_delete` |
| message | string | no | Template string for approve decisions. Variables: `{{.Path}}` |
| timeout | duration | no | Approval timeout (e.g., `5m`, `30s`) |
| redirect_to | string | no | Target directory for redirected file operations |
| preserve_tree | bool | no | Preserve directory structure under redirect target |

### network_rules[]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| description | string | yes | Human-readable description |
| domains | string[] | no | Domain glob patterns (e.g., `*.stripe.com`). At least one of domains/ports/cidrs required. |
| ports | int[] | no | Port numbers (e.g., `[443, 80]`) |
| cidrs | string[] | no | CIDR ranges (e.g., `10.0.0.0/8`) |
| decision | string | yes | `allow`, `deny`, `approve` |
| message | string | no | Template. Variables: `{{.RemoteAddr}}`, `{{.RemotePort}}` |
| timeout | duration | no | Approval timeout |

### command_rules[]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| description | string | no | Human-readable description |
| commands | string[] | yes | Command names (basename matching, glob supported) |
| args_patterns | string[] | no | Regex patterns matched against the full argument string |
| decision | string | yes | `allow`, `deny`, `approve`, `redirect` |
| message | string | no | Template. Variables: `{{.Args}}` |
| redirect_to | object | no | For redirect decision: `{command, args[], args_append[], environment{}}` |
| context | object | no | Process ancestry context (see below) |
| env_allow | string[] | no | Per-command env allowlist (glob) |
| env_deny | string[] | no | Per-command env denylist (glob) |
| env_max_bytes | int | no | Max env size for this command |
| env_max_keys | int | no | Max env keys for this command |
| env_block_iteration | bool | no | Block env enumeration for this command |

**command_rules[].context:**

Two syntaxes supported:

Array form (shorthand):
```yaml
context: [direct]              # Only processes spawned directly by the agent
context: [nested]              # Only subprocesses of subprocesses (depth > 0)
context: [direct, nested]      # All depths (default)
```

Object form (explicit):
```yaml
context:
  min_depth: 0                 # Minimum process ancestry depth
  max_depth: -1                # Maximum depth (-1 = unlimited)
```

Default (if omitted): all depths (`min_depth: 0`, `max_depth: -1`).

**command_rules[].redirect_to object:**

| Field | Type | Description |
|-------|------|-------------|
| command | string | Replacement command to execute |
| args | string[] | Arguments prepended before original args |
| args_append | string[] | Arguments appended after original args |
| environment | map[string]string | Environment variable overrides |

### unix_socket_rules[]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| description | string | yes | Human-readable description |
| paths | string[] | yes | Socket paths. `@name` for abstract namespace. |
| operations | string[] | no | `connect`, `bind`, `listen`, `sendto`. Empty = all. |
| decision | string | yes | `allow`, `deny`, `approve` |
| message | string | no | Approval message |
| timeout | duration | no | Approval timeout |

### registry_rules[] (Windows only)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| description | string | yes | Human-readable description |
| paths | string[] | yes | Registry key paths (e.g., `HKLM\SOFTWARE\...`) |
| operations | string[] | yes | `read`, `write`, `delete`, `create`, `rename` |
| decision | string | yes | `allow`, `deny`, `approve` |
| message | string | no | Approval message |
| timeout | duration | no | Approval timeout |
| priority | int | no | Higher = evaluated first |
| cache_ttl | duration | no | Per-rule cache TTL |
| notify | bool | no | Always emit notification |

### signal_rules[]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| description | string | yes | Human-readable description |
| signals | string[] | yes | Signal names, numbers, or groups: `@all`, `@fatal`, `@job`, `@reload` |
| target | object | yes | `{type, pattern?, min?, max?}`. Types: `self`, `children`, `descendants`, `siblings`, `parent`, `session`, `external`, `system`, `user`, `process`, `pid_range` |
| decision | string | yes | `allow`, `deny`, `audit`, `approve`, `redirect`, `absorb` |
| fallback | string | no | Fallback decision if platform can't enforce |
| redirect_to | string | no | Target signal name (for redirect decision) |
| message | string | no | Human-readable message |
| timeout | duration | no | Approval timeout |

**signal_rules[].target object:**

| Field | Type | Description |
|-------|------|-------------|
| type | string | `self`, `children`, `descendants`, `siblings`, `parent`, `session`, `external`, `system`, `user`, `process`, `pid_range` |
| pattern | string | Process name glob pattern (only for `type: process`) |
| min | int | Required when `type: pid_range`. Must be > 0, min <= max. |
| max | int | Required when `type: pid_range`. Must be > 0, max >= min. |

### dns_redirects[]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| match | string | yes | Regex pattern for hostname |
| resolve_to | string | yes | IP address to return |
| visibility | string | no | `silent`, `audit_only`, `warn` |
| on_failure | string | no | `fail_closed`, `fail_open`, `retry_original` |

### connect_redirects[]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| match | string | yes | Regex pattern for `host:port` |
| redirect_to | string | conditional | New TCP `host:port` destination |
| redirect_to_unix | string | conditional | Unix socket path destination |
| tls | object | no | `{mode, sni?}`. Modes: `passthrough`, `rewrite_sni` |
| visibility | string | no | `silent`, `audit_only`, `warn` |
| message | string | no | Human-readable message |
| on_failure | string | no | `fail_closed`, `fail_open`, `retry_original` |

Exactly one of `redirect_to` or `redirect_to_unix` is required. DB unavoidability bundles use `redirect_to_unix` to route direct Postgres TCP attempts through the per-session DB proxy socket.

**connect_redirects[].tls object:**

| Field | Type | Description |
|-------|------|-------------|
| mode | string | `passthrough` or `rewrite_sni` |
| sni | string | Required when mode is `rewrite_sni` |

### providers{}

`providers` is a map keyed by provider name. Each entry must include `type`; provider-specific fields are decoded by the secrets subsystem. `http_services[].secret.ref` schemes must match one declared provider type.

Supported provider types: `keyring`, `vault`, `aws-sm`, `gcp-sm`, `azure-kv`, `op`.

Common reference URI examples:

```yaml
providers:
  local_keyring:
    type: keyring
  corp_vault:
    type: vault
    address: https://vault.internal
    token_ref: keyring://agentsh/vault_token
```

### http_services[]

Declared HTTP services expose selected upstream API paths to child processes through the AgentSH proxy as `/svc/<name>/...`. Use this when the policy needs method/path control, approval gates, credential substitution, or audited HTTP service traffic. Use `network_rules` instead for simple host/port access.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | URL-safe service name (`[A-Za-z0-9._-]+`) |
| upstream | string | yes | HTTPS base URL |
| expose_as | string | no | Env var name for service URL. Default is `<NAME>_API_URL` |
| aliases | string[] | no | Extra upstream host aliases for direct-access blocking |
| allow_direct | bool | no | Escape hatch; default false blocks direct upstream access |
| default | string | no | `allow` or `deny`; default is fail-closed when rules exist |
| rules | object[] | no | Method/path rules, evaluated first-match-wins |
| secret | object | no | Credential substitution config `{ref, format}` |
| inject | object | no | Request injection config, currently `{header: {name, template}}` |
| scrub_response | bool | no | Whether to scrub fake/real credentials from responses |

**http_services[].rules[]:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| methods | string[] | no | HTTP methods; empty or `*` means any |
| paths | string[] | yes | `/`-separated glob patterns |
| decision | string | yes | `allow`, `deny`, `approve`, `audit` |
| message | string | no | Human-readable message |
| timeout | duration | no | Approval timeout |

**Credential substitution:**

```yaml
http_services:
  - name: github
    upstream: https://api.github.com
    secret:
      ref: vault://kv/data/github#token
      format: ghp_{rand:36}
    inject:
      header:
        name: Authorization
        template: Bearer {{secret}}
    rules:
      - name: allow-read-issues
        methods: [GET]
        paths: ["/repos/*/*/issues*"]
        decision: allow
```

If `secret` is present, `providers` must declare a matching provider type. `inject.header.template` must contain `{{secret}}`. The old top-level `services:` key is invalid; use `http_services:`.

### db_services{} (Postgres-family only)

`db_services` is a map keyed by service name. Current runtime database support is Postgres-family only: `family` must be `postgres`; supported dialect values are `postgres`, `aurora_postgres`, `redshift`, and `cockroachdb`. MySQL, MongoDB, Snowflake, BigQuery, Databricks, ClickHouse, MSSQL, Cassandra, Redis, and Oracle are not current runtime targets.

```yaml
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: pg.internal:5432
    tls_mode: terminate_reissue
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| family | string | yes | Must be `postgres` today |
| dialect | string | yes | `postgres`, `aurora_postgres`, `redshift`, or `cockroachdb` |
| upstream | string | yes | Upstream `host:port` |
| tls_mode | string | yes | `terminate_reissue`, `terminate_plaintext_upstream`, or `passthrough` |
| trusted_network | bool | no | Required for unsafe plaintext upstreams |
| allow_function_call_protocol | bool | no | Opt into PostgreSQL FunctionCall protocol forwarding; default denies it |
| allow_gss_encryption | bool | no | Opt into GSS encryption passthrough with degraded statement visibility |

### database_rules[]

Statement-level database rules apply after the Postgres proxy classifies a statement into effects. Strict coverage applies: every object slot in an effect must be covered by a non-deny rule, and any matching deny wins.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| db_service | string | no | Match one `db_services` entry |
| db_family | string | no | Currently `postgres` |
| db_dialect | string | no | Match one Postgres-family dialect |
| operations | string[] | yes | Operation groups or aliases, e.g. `read`, `write`, `modify`, `delete`, `session`, `transaction`, `bulk_export`, `unknown`, `READ`, `MUTATE`, `*` |
| subtypes | string[] | no | Operation subtype filters |
| objects | string[] | no | Syntactic object-name globs |
| schemas | string[] | no | Schema-name globs |
| relations | string[] | no | Catalog-resolved relation selectors, formatted as `schema.name` |
| functions | string[] | no | Catalog-resolved function selectors, formatted as `schema.name(identity_args)`; `schema.name(*)` matches overloads |
| match_object_resolution | string | no | Resolution tag such as `catalog_resolved`, `qualified_syntactic`, `unqualified_syntactic`, `catalog_unresolved`, or `*` |
| require_where | bool | no | For Postgres `modify`/`delete` rules only: require the top-level `UPDATE` or `DELETE` statement to include a syntactic `WHERE` clause |
| decision | string | yes | `allow`, `deny`, `approve`, `audit`, or statement-level `redirect` |
| message | string | no | Template shown on deny/approve paths |
| timeout | duration | no | Approval timeout |
| deny_mode_in_tx | string | no | For deny rules in transactions: `terminate` or `rollback_then_continue` |
| acknowledge_audit_on_dangerous | bool | no | Required to silence warnings for `audit` on high-risk operations |
| redirect | object | no | Required for `decision: redirect`; see below |

Operation groups are lowercase canonical names: `read`, `write`, `modify`, `delete`, `bulk_load`, `bulk_export`, `schema_create`, `schema_alter`, `schema_destroy`, `privilege`, `transaction`, `session`, `maintenance`, `lock`, `notify`, `procedural`, `unsafe_io`, `unknown`.

Uppercase aliases are also supported: `READ`, `INSERT`, `UPDATE`, `DELETE`, `REMOVE`, `CREATE`, `DROP`, `ALTER`, `TRUNCATE`, `EXPORT`, `LOAD`, `MUTATE`, `SCHEMA`, `MAINTENANCE`, `LOCK_TABLES`, `LISTEN_NOTIFY`, `DANGEROUS`. `*` expands to all known groups except `unknown`.

`require_where: true` is valid only when `operations` expands exclusively to `modify` and/or `delete`; `MUTATE` is rejected because it also includes `write`. The guard is syntactic only, so `WHERE true` satisfies it.

`decision: redirect` is Postgres-only and supports safe read-only relation replacement. It requires `operations` that expand only to read, exactly one canonical `relations` source selector, `match_object_resolution: catalog_resolved`, an eligible terminate-mode Postgres service, and `redirect.relation`.

**database_rules[].redirect object:**

| Field | Type | Description |
|-------|------|-------------|
| relation | string | Canonical target relation formatted as `schema.name` |

### database_connection_rules[]

Connection-level database rules apply to Postgres StartupMessage, CancelRequest, and replication-request handling.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| db_service | string | no | Match one `db_services` entry |
| match_kind | string | no | `connect` (default), `cancel`, or `replication` |
| db_user | string[] | no | Startup user globs; unavailable under passthrough |
| database | string | no | Startup database name; unavailable under passthrough |
| application_name | string | no | Startup application name; unavailable under passthrough |
| client_identity | string | no | AgentSH client identity selector |
| decision | string | yes | `allow`, `deny`, `approve`, or `audit`; `redirect` is invalid here |
| message | string | no | Message returned to the client where protocol mode allows it |
| timeout | duration | no | Approval timeout; invalid for `match_kind: cancel` |

Rules that match a `passthrough` service cannot use `db_user`, `database`, or `application_name`, because AgentSH cannot inspect StartupMessage fields through passthrough TLS. `approve` is invalid for `match_kind: cancel`. `redirect` is invalid for all connection rules.

---

## Top-Level Settings

### resource_limits

| Field | Type | Description |
|-------|------|-------------|
| max_memory_mb | int | Max memory in MB |
| memory_swap_max_mb | int | Max swap in MB (0 = disable) |
| cpu_quota_percent | int | Max CPU % of one core |
| disk_read_bps_max | int64 | Max disk read bytes/sec |
| disk_write_bps_max | int64 | Max disk write bytes/sec |
| net_bandwidth_mbps | int | Max network bandwidth Mbps |
| pids_max | int | Max process count |
| command_timeout | duration | Max time per command |
| session_timeout | duration | Max session lifetime |
| idle_timeout | duration | Kill after idle period |

### env_policy

| Field | Type | Description |
|-------|------|-------------|
| allow | string[] | Glob patterns for allowed env vars |
| deny | string[] | Glob patterns for denied env vars |
| max_bytes | int | Max total env size |
| max_keys | int | Max number of env vars |
| block_iteration | bool | Hide env enumeration |

### audit

| Field | Type | Description |
|-------|------|-------------|
| log_allowed | bool | Log allowed operations |
| log_denied | bool | Log denied operations |
| log_approved | bool | Log approved operations |
| include_stdout | bool | Include stdout in logs |
| include_stderr | bool | Include stderr in logs |
| include_file_content | bool | Include file content in logs |
| retention_days | int | Log retention period |

### env_inject

Simple `map[string]string` — key-value pairs of environment variables to inject into all processes. Example:

```yaml
env_inject:
  BASH_ENV: "/etc/agentsh/bash_restricted.sh"
  NODE_OPTIONS: "--max-old-space-size=512"
```

### mcp_rules

| Field | Type | Description |
|-------|------|-------------|
| enforce_policy | bool | Enable MCP enforcement |
| tool_policy | string | `allowlist` or `blocklist` |
| allowed_tools | object[] | `[{server, tool, content_hash?}]` |
| allowed_servers | object[] | `[{id}]` |
| server_policy | string | Server list policy |
| version_pinning | object | `{enabled, on_change?, auto_trust_first?}` |
| cross_server | object | `{enabled, read_then_send?: {enabled}}` |

### policies.db

Database runtime settings live under `policies.db`.

| Field | Type | Description |
|-------|------|-------------|
| unavoidability | string | `off`, `observe`, or `enforce`; `enforce` blocks direct access to declared DB upstreams from governed processes |
| log_statements | string | `none`, `parameters_redacted` (default), or `full` |
| approval_statement_preview | string | `none`, `redacted` (default), or `full` |
| approval_statement_preview_chars | int | Max preview length, default 200 |
| escalate_unknown_functions | bool | Treat unknown function calls in SELECT as `procedural` unless allowlisted |
| safe_function_allowlist | string[] | Function names that remain read-safe when escalation is enabled |

### package_rules[]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| match | object | yes | `{packages?, name_patterns?, finding_type?, severity?, reasons?, license_spdx?: {allow?, deny?}, ecosystem?}` |
| action | string | yes | `allow`, `warn`, `approve`, `block` |
| reason | string | no | Explanation |

**package_rules[].match object:**

| Field | Type | Description |
|-------|------|-------------|
| packages | string[] | Exact package names |
| name_patterns | string[] | Glob patterns for package names |
| finding_type | string | `vulnerability`, `license`, etc. |
| severity | string | `critical`, `high`, `medium`, `low`, `info` |
| reasons | string[] | Match specific reason codes |
| license_spdx | object | `{allow?: string[], deny?: string[]}` SPDX license matching |
| ecosystem | string | `npm`, `pypi` |

### process_contexts (map[string]ProcessContext)

A map where each key is a context name and each value is a `ProcessContext` object.

| Field | Type | Description |
|-------|------|-------------|
| description | string | Context description |
| identities | string[] | Process identity names that trigger this context |
| chain_rules | object[] | Escape-hatch detection rules (evaluated before context rules) |
| command_rules | CommandRule[] | Override command rules |
| file_rules | FileRule[] | Override file rules |
| network_rules | NetworkRule[] | Override network rules |
| unix_socket_rules | UnixSocketRule[] | Override unix socket rules |
| env_policy | EnvPolicy | Override env policy |
| allowed_commands | string[] | Quick allow list |
| denied_commands | string[] | Quick deny list |
| require_approval | string[] | Quick approval list |
| command_overrides | map | Per-command arg filtering (`{args_allow?, args_deny?, default?}`) |
| default_decision | string | `allow`, `deny`, `approve` (default: `deny`) |
| max_depth | int | Max ancestry depth (0 = unlimited) |
| stop_at | string[] | Stop taint propagation at these process classes |
| pass_through | string[] | Classes that inherit context but don't count toward depth |
| race_policy | object | `{on_missing_parent?, on_pid_mismatch?, on_validation_error?, log_race_conditions?}` |

> **Note:** `stop_at`, `pass_through`, and `race_policy` are advanced ancestry-control fields rarely needed by most policy authors.

### process_identities (map[string]ProcessIdentityConfig)

A map where each key is an identity name and each value is a `ProcessIdentityConfig` object.

| Field | Type | Description |
|-------|------|-------------|
| description | string | Identity description |
| linux | object | `{comm?, exe_path?, cmdline?}` |
| darwin | object | `{comm?, exe_path?, cmdline?, bundle_id?}` |
| windows | object | `{comm?, exe_path?, cmdline?, exe_name?}` |
| all_platforms | object | Same fields, applies everywhere |

Each platform object accepts arrays of patterns:

| Field | Type | Description |
|-------|------|-------------|
| comm | string[] | Process name patterns |
| exe_path | string[] | Executable path patterns |
| cmdline | string[] | Command line patterns |
| bundle_id | string[] | macOS bundle ID (darwin only) |
| exe_name | string[] | Windows exe name (windows only) |

### transparent_commands

| Field | Type | Description |
|-------|------|-------------|
| add | string[] | Additional transparent commands |
| remove | string[] | Remove from built-in defaults |

---

## Evaluation Semantics

- **First match wins**: File, network, command, unix socket, registry, signal, DNS redirect, connect redirect, HTTP service, and package rules are evaluated top-to-bottom within their category. The first matching rule determines the decision. Order matters.
- **DB statement rules**: `database_rules` are not simple first-match-wins. Any matching deny wins. Otherwise every object slot in each classified effect must be covered by at least one matching `allow`, `audit`, `redirect`, or `approve` rule; uncovered objects fail closed as implicit deny.
- **DB connection rules**: all matching `database_connection_rules` are considered and the most restrictive decision wins: `deny > approve > audit > allow`.
- **Default deny**: Convention is to end each rule category with a catch-all deny rule (e.g., `paths: ["**"]`, `domains: ["*"]`).
- **Variable expansion**: `${PROJECT_ROOT}`, `${HOME}`, `${GIT_ROOT}` are expanded at load time.
- **Glob syntax**: `*` matches any characters except `/`. `**` matches any characters including `/`. `?` matches one character.
- **Regex syntax**: `args_patterns`, `dns_redirects[].match`, and `connect_redirects[].match` use Go regexp syntax.
- **Duration syntax**: Go duration strings — `5m`, `30s`, `1h`, `4h30m`.

---

## Idiomatic Examples

**Allow a specific domain:**
```yaml
- name: allow-stripe
  description: Stripe API access
  domains:
    - "api.stripe.com"
    - "*.stripe.com"
  ports: [443]
  decision: allow
```

**Block a sensitive path:**
```yaml
- name: deny-docker-socket
  description: Block Docker socket access
  paths:
    - "/var/run/docker.sock"
  operations: ["*"]
  decision: deny
```

**Require approval for a command with specific args:**
```yaml
- name: approve-npm-publish
  description: Require approval for npm publish
  commands: [npm]
  args_patterns: ["publish.*"]
  decision: approve
  message: "Agent wants to publish: {{.Args}}"
```

**Redirect a dangerous command:**
```yaml
- name: redirect-rm-rf
  description: Redirect rm -rf to safe alternative
  commands: [rm]
  args_patterns: [".*-rf.*"]
  decision: redirect
  redirect_to:
    command: echo
    args: ["rm -rf blocked. Use targeted deletes instead."]
```

**Declare an HTTP service with credential substitution:**
```yaml
providers:
  local_keyring:
    type: keyring

http_services:
  - name: stripe
    upstream: https://api.stripe.com
    secret:
      ref: keyring://agentsh/stripe_api_key
      format: sk_live_{rand:32}
    inject:
      header:
        name: Authorization
        template: Bearer {{secret}}
    rules:
      - name: allow-read-customers
        methods: [GET]
        paths: ["/v1/customers*"]
        decision: allow
      - name: approve-writes
        methods: [POST, DELETE]
        paths: ["/v1/**"]
        decision: approve
```

**Declare Postgres DB policy with redacted logging:**
```yaml
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue

policies:
  db:
    unavoidability: enforce
    log_statements: parameters_redacted
    approval_statement_preview: redacted
    approval_statement_preview_chars: 200

database_connection_rules:
  - name: allow-app-user
    db_service: appdb
    db_user: [app_agent]
    database: app
    decision: allow
  - name: deny-replication
    db_service: appdb
    match_kind: replication
    decision: deny

database_rules:
  - name: allow-public-reads
    db_service: appdb
    operations: [READ]
    relations: ["public.*"]
    match_object_resolution: catalog_resolved
    decision: allow
  - name: deny-dangerous
    db_service: appdb
    operations: [DANGEROUS]
    decision: deny
```
