# AgentSH Policy Skills Design

Two skills for creating and editing AgentSH policy files from any LLM-powered environment (Claude Code, NanoClaw, etc.).

## Problem

AgentSH policies are YAML files with ~15 rule categories, first-match-wins evaluation, variable expansion, and specific field constraints. Writing them correctly requires understanding the schema, valid values, and ordering semantics. Users currently hand-edit YAML or copy-paste from templates — error-prone and slow.

## Decision: Two Skills + Shared Schema

**`policy-create`** — Creates a new policy from a built-in template, customized to the user's use case.

**`policy-edit`** — Makes targeted edits (add/remove/update rules) to an existing policy.

**`schema-reference.md`** — Shared schema reference read by both skills at invocation time. Single source of truth for the YAML-facing surface of the policy model.

### Why Two Skills

The create and edit flows are distinct enough that combining them would make a single skill too branchy. Create needs template selection and use-case questions. Edit needs file reading, intent mapping, and insertion-position logic. Splitting keeps each skill focused and shorter.

### Why Embedded Schema

The skills must work in environments without access to the AgentSH source code (NanoClaw, standalone Claude Code). Embedding the schema reference makes them self-contained. The schema covers only the YAML-author-facing surface — no Go types or engine internals.

## Skill: `policy-create`

### Trigger Patterns

- "create a policy", "new agentsh policy", "make a policy for X"
- "policy for my CI pipeline", "policy for agent sandbox"

### Flow

1. **Locate policy directory** — Look for `config.yml` or `config.yaml` to find `policies.dir`. If not found, look for a `configs/policies/` directory. Fall back to asking the user for the target path.

2. **Understand the use case** — Ask one question: "What will this policy protect?" with options:
   - AI agent doing code tasks → template: `default` or `agent-default`
   - CI/CD pipeline → template: `ci-strict`
   - Local development → template: `dev-safe`
   - Strict agent sandbox → template: `agent-sandbox`
   - Observation/profiling only → template: `agent-observe`
   - Custom / other → start from `default`

3. **Select template** — Read the closest built-in policy pack from the policy directory. If templates are not available locally, use the schema reference to generate a baseline from scratch.

4. **Customize** — Ask focused follow-up questions based on what the template doesn't cover. Only ask what's relevant:
   - "Which domains does your app need to reach?" → network rules
   - "Any paths outside the workspace it needs to access?" → file rules
   - "Any commands that should be blocked or require approval?" → command rules
   - Skip categories the template already handles well for the use case.

5. **Name & write** — Ask for a policy name. Generate the YAML file with descriptive section comments matching the style of built-in policies. Write to the policy directory.

6. **Validate** — Run `agentsh policy validate <name>`. If validation fails, fix the issue and re-validate.

7. **Update config reminder** — If `config.yml` has a `policies.allowed` list, remind the user to add the new policy name to it.

### Guardrails

- Always use `version: 1`.
- Every policy must have `name` and `description`.
- End each rule category with a default-deny catch-all (following built-in policy conventions).
- Use descriptive rule names in `verb-noun` format (e.g., `allow-npm`, `deny-ssh-keys`).
- Include section comment headers matching the style of built-in policies.

## Skill: `policy-edit`

### Trigger Patterns

- "add a network rule", "allow stripe.com", "block file deletes"
- "remove the curl approval rule", "update the memory limit"
- "change the session timeout", "add MCP rules"

### Flow

1. **Locate & read the policy** — Same auto-detect as `policy-create` (check `config.yml`/`config.yaml` for `policies.dir`). If multiple policies exist, list them and ask which one to edit. Read the full YAML into context.

2. **Understand the intent** — Map the user's natural language request to:
   - **Rule category** — file_rules, network_rules, command_rules, unix_socket_rules, registry_rules, signal_rules, dns_redirects, connect_redirects, resource_limits, env_policy, audit, mcp_rules, package_rules, process_contexts, process_identities, env_inject, transparent_commands
   - **Operation** — add a new rule, remove an existing rule, or modify an existing rule
   - **Insertion position** — where in the rule order (for new rules)

3. **Determine insertion position** (for new rules) — First-match-wins means ordering matters:
   - Place deny rules before broader allow rules that would shadow them.
   - Place allow rules before the default-deny catch-all at the end.
   - Place more specific rules before less specific ones.
   - When in doubt, insert immediately before the default-deny rule for that category.

4. **Make the edit** — Use the Edit tool to make the targeted YAML change:
   - **Add**: Insert the new rule at the correct position.
   - **Remove**: Delete the rule block (name through last field).
   - **Update**: Modify only the specific fields that need changing.
   - Preserve existing comments and formatting. Do not reformat or reorganize untouched rules.

5. **Validate** — Run `agentsh policy validate <name>`. If validation fails, fix and re-validate.

6. **Summarize** — Show what changed and explain the effect in terms of what will now be allowed/denied/approved. Example: "Added network rule `allow-stripe` before `approve-unknown-https`. Stripe API traffic on port 443 will now be allowed without approval."

### Guardrails

- **Minimal edits only** — Only touch the specific rules the user asked about.
- **Preserve formatting** — Keep existing comments, blank lines, section headers.
- **Respect ordering** — Never blindly append; consider first-match-wins semantics.
- **Name new rules** consistently — `verb-noun` format matching the existing policy style.
- **Warn about shadowing** — If adding a rule that would be unreachable because an earlier rule matches the same pattern, warn the user.

## Shared Schema Reference (`schema-reference.md`)

Both skills read this file at invocation time. It contains the YAML-author-facing surface of the policy model.

### Contents

#### Top-Level Structure

```yaml
version: 1                    # Required. Always 1.
name: "policy-name"           # Required. Alphanumeric + hyphens.
description: |                # Required. Multi-line description.
  What this policy does.

file_rules: []                # File operation rules
network_rules: []             # Network connection rules
command_rules: []             # Command execution rules
unix_socket_rules: []         # Unix socket rules
registry_rules: []            # Windows registry rules
signal_rules: []              # Signal sending rules
dns_redirects: []             # DNS redirect rules
connect_redirects: []         # TCP connect redirect rules
resource_limits: {}           # Resource limits
env_policy: {}                # Environment variable policy
audit: {}                     # Audit settings
env_inject: {}                # Injected environment variables
mcp_rules: {}                 # MCP tool/server rules
process_contexts: {}          # Parent-conditional policies
process_identities: {}        # Process identity definitions
package_rules: []             # Package install check rules
transparent_commands: {}      # Override transparent command set
```

#### Rule Types

**file_rules[]:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier (verb-noun) |
| description | string | yes | Human-readable description |
| paths | string[] | yes | Glob patterns. Supports `${PROJECT_ROOT}`, `${HOME}`, `${GIT_ROOT}`, `**`, `*` |
| operations | string[] | yes | `read`, `write`, `delete`, `stat`, `list`, `open`, `create`, `mkdir`, `chmod`, `rename`, `rmdir`, `readlink`, `*` |
| decision | string | yes | `allow`, `deny`, `approve`, `soft_delete` |
| message | string | no | Template string for approve decisions. Variables: `{{.Path}}` |
| timeout | duration | no | Approval timeout (e.g., `5m`, `30s`) |
| redirect_to | string | no | Target directory for redirected file operations |
| preserve_tree | bool | no | Preserve directory structure under redirect target |

**network_rules[]:**
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

**command_rules[]:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| description | string | no | Human-readable description |
| commands | string[] | yes | Command names (basename matching, glob supported) |
| args_patterns | string[] | no | Regex patterns matched against the full argument string |
| decision | string | yes | `allow`, `deny`, `approve`, `redirect` |
| message | string | no | Template. Variables: `{{.Args}}` |
| redirect_to | object | no | For redirect decision: `{command, args[], args_append[], environment{}}` |
| context | object | no | Process ancestry context conditions |
| env_allow | string[] | no | Per-command env allowlist (glob) |
| env_deny | string[] | no | Per-command env denylist (glob) |
| env_max_bytes | int | no | Max env size for this command |
| env_max_keys | int | no | Max env keys for this command |
| env_block_iteration | bool | no | Block env enumeration for this command |

**unix_socket_rules[]:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| description | string | yes | Human-readable description |
| paths | string[] | yes | Socket paths. `@name` for abstract namespace. |
| operations | string[] | no | `connect`, `bind`, `listen`, `sendto`. Empty = all. |
| decision | string | yes | `allow`, `deny`, `approve` |
| message | string | no | Approval message |
| timeout | duration | no | Approval timeout |

**registry_rules[] (Windows only):**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| description | string | yes | Human-readable description |
| paths | string[] | yes | Registry key paths (e.g., `HKLM\SOFTWARE\...`) |
| operations | string[] | yes | `read`, `write`, `delete`, `create`, `rename` |
| decision | string | yes | `allow`, `deny`, `approve` |
| priority | int | no | Higher = evaluated first |
| cache_ttl | duration | no | Per-rule cache TTL |
| notify | bool | no | Always emit notification |

**signal_rules[]:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| description | string | yes | Human-readable description |
| signals | string[] | yes | Signal names, numbers, or groups: `@all`, `@fatal`, `@job`, `@reload` |
| target | object | yes | `{type, pattern?, min?, max?}`. Types: `self`, `children`, `parent`, `session`, `external`, `system` |
| decision | string | yes | `allow`, `deny`, `audit`, `approve`, `redirect`, `absorb` |
| fallback | string | no | Fallback decision if platform can't enforce |
| redirect_to | string | no | Target signal name (for redirect decision) |
| message | string | no | Human-readable message |
| timeout | duration | no | Approval timeout |

**dns_redirects[]:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| match | string | yes | Regex pattern for hostname |
| resolve_to | string | yes | IP address to return |
| visibility | string | no | `silent`, `audit_only`, `warn` |
| on_failure | string | no | `fail_closed`, `fail_open`, `retry_original` |

**connect_redirects[]:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | yes | Rule identifier |
| match | string | yes | Regex pattern for `host:port` |
| redirect_to | string | yes | New `host:port` destination |
| tls | object | no | `{mode, sni?}`. Modes: `passthrough`, `rewrite_sni` |
| visibility | string | no | `silent`, `audit_only`, `warn` |
| message | string | no | Human-readable message |
| on_failure | string | no | `fail_closed`, `fail_open`, `retry_original` |

**resource_limits:**
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

**env_policy:**
| Field | Type | Description |
|-------|------|-------------|
| allow | string[] | Glob patterns for allowed env vars |
| deny | string[] | Glob patterns for denied env vars |
| max_bytes | int | Max total env size |
| max_keys | int | Max number of env vars |
| block_iteration | bool | Hide env enumeration |

**audit:**
| Field | Type | Description |
|-------|------|-------------|
| log_allowed | bool | Log allowed operations |
| log_denied | bool | Log denied operations |
| log_approved | bool | Log approved operations |
| include_stdout | bool | Include stdout in logs |
| include_stderr | bool | Include stderr in logs |
| include_file_content | bool | Include file content in logs |
| retention_days | int | Log retention period |

**mcp_rules:**
| Field | Type | Description |
|-------|------|-------------|
| enforce_policy | bool | Enable MCP enforcement |
| tool_policy | string | `allowlist` or `blocklist` |
| allowed_tools | object[] | `[{server, tool, content_hash?}]` |
| allowed_servers | object[] | `[{id}]` |
| server_policy | string | Server list policy |
| version_pinning | object | `{enabled, on_change?, auto_trust_first?}` |
| cross_server | object | `{enabled, read_then_send?: {enabled}}` |

**package_rules[]:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| match | object | yes | `{packages?, name_patterns?, finding_type?, severity?, reasons?, license_spdx?: {allow?, deny?}, ecosystem?}` |
| action | string | yes | `allow`, `warn`, `approve`, `block` |
| reason | string | no | Explanation |

**process_contexts (map[string]ProcessContext):**
| Field | Type | Description |
|-------|------|-------------|
| description | string | Context description |
| identities | string[] | Process identity names that trigger this context |
| chain_rules | object[] | Escape-hatch detection rules |
| command_rules | CommandRule[] | Override command rules |
| file_rules | FileRule[] | Override file rules |
| network_rules | NetworkRule[] | Override network rules |
| unix_socket_rules | UnixSocketRule[] | Override unix socket rules |
| env_policy | EnvPolicy | Override env policy |
| allowed_commands | string[] | Quick allow list |
| denied_commands | string[] | Quick deny list |
| require_approval | string[] | Quick approval list |
| command_overrides | map | Per-command arg filtering |
| default_decision | string | `allow`, `deny`, `approve` (default: `deny`) |
| max_depth | int | Max ancestry depth (0 = unlimited) |
| stop_at | string[] | Stop taint propagation at these process classes |
| pass_through | string[] | Classes that inherit context but don't count toward depth |
| race_policy | object | `{on_missing_parent?, on_pid_mismatch?, on_validation_error?, log_race_conditions?}` |

> **Note:** `stop_at`, `pass_through`, and `race_policy` are advanced ancestry-control fields rarely needed by most policy authors.

**process_identities (map[string]ProcessIdentityConfig):**
| Field | Type | Description |
|-------|------|-------------|
| description | string | Identity description |
| linux | object | `{comm?, exe_path?, cmdline?}` |
| darwin | object | `{comm?, exe_path?, cmdline?, bundle_id?}` |
| windows | object | `{comm?, exe_path?, cmdline?, exe_name?}` |
| all_platforms | object | Same fields, applies everywhere |

**transparent_commands:**
| Field | Type | Description |
|-------|------|-------------|
| add | string[] | Additional transparent commands |
| remove | string[] | Remove from built-in defaults |

#### Evaluation Semantics

- **First match wins**: Rules within each category are evaluated top-to-bottom. The first rule whose pattern matches determines the decision. Order matters.
- **Default deny**: Convention is to end each rule category with a catch-all deny rule (e.g., `paths: ["**"]`, `domains: ["*"]`).
- **Variable expansion**: `${PROJECT_ROOT}`, `${HOME}`, `${GIT_ROOT}` are expanded at load time.
- **Glob syntax**: `*` matches any characters except `/`. `**` matches any characters including `/`. `?` matches one character.
- **Regex syntax**: `args_patterns`, `dns_redirects[].match`, and `connect_redirects[].match` use Go regexp syntax.
- **Duration syntax**: Go duration strings — `5m`, `30s`, `1h`, `4h30m`.

#### Idiomatic Examples

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

## File Layout

```
skills/
  agentsh-policy-create/
    agentsh-policy-create.md     # Skill: trigger, flow, guardrails
  agentsh-policy-edit/
    agentsh-policy-edit.md       # Skill: trigger, flow, guardrails
  agentsh-policy-shared/
    schema-reference.md          # Shared schema (read by both skills)
```

## Validation

Both skills run `agentsh policy validate <name>` after every change. If the binary is not available, the skill warns that it cannot validate and advises the user to run validation manually.

## Built-in Templates

The `policy-create` skill maps use cases to templates:

| Use Case | Template |
|----------|----------|
| AI agent (code tasks) | `default` or `agent-default` |
| CI/CD pipeline | `ci-strict` |
| Local development | `dev-safe` |
| Strict agent sandbox | `agent-sandbox` |
| Observation/profiling | `agent-observe` |
| Custom | Start from `default` |

Templates are read from the local policy directory if available. Otherwise, the schema reference provides enough information to generate a reasonable baseline.
