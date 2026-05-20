---
name: agentsh-policy-edit
description: Use when adding, removing, or updating rules in an existing AgentSH policy, modifying security permissions, HTTP service declarations, Postgres-family database rules, resource limits, or policy YAML files
---

# Edit AgentSH Policy

## Overview
Make targeted edits to existing AgentSH security policies — add, remove, or update rules and declarations. Understands first-match-wins policy categories plus the separate Postgres-family database rule semantics.

## When to Use
- User asks to add/remove/update a policy rule ("allow stripe.com", "block file deletes")
- User asks to change declared HTTP API access (`http_services`, `providers`)
- User asks to change Postgres-family DB access (`db_services`, `database_rules`, `database_connection_rules`, `policies.db`)
- User wants to change resource limits or audit settings
- User mentions modifying an existing policy
- NOT for creating new policies from scratch (use agentsh-policy-create)

## Flow

1. **Locate & read the policy**
   - Check `config.yml`/`config.yaml` for `policies.dir`
   - If not found, look for `configs/policies/` directory
   - Fall back to asking the user
   - If multiple policies exist, list them and ask which one to edit
   - Read the full YAML into context

2. **Understand the intent**
   Map the user's request to:
   - **Rule category** — file_rules, network_rules, command_rules, unix_socket_rules, registry_rules, signal_rules, dns_redirects, connect_redirects, http_services, providers, db_services, database_rules, database_connection_rules, policies.db, resource_limits, env_policy, audit, mcp_rules, package_rules, process_contexts, process_identities, env_inject, transparent_commands
   - **Operation** — add a new rule, remove an existing rule, or modify an existing rule
   - **Insertion position** — where in the rule order (for new rules)

3. **Determine insertion position** (for new rules)
   First-match-wins means ordering matters:
   - Place deny rules before any broader matching rule regardless of its decision — any non-deny rule (`allow`, `approve`, `redirect`, `audit`, `absorb`, `soft_delete`) that matches first will shadow the deny
   - Place allow rules before the default-deny catch-all at the end
   - Place more specific rules before less specific ones
   - When in doubt: deny rules go before the first non-deny rule in that category; allow rules go before the default-deny
   - Do not apply this first-match-wins shortcut to `database_rules` or `database_connection_rules`; see DB rules below.

4. **Make the edit**
   Use the Edit tool:
   - **Add**: Insert the new rule at the correct position
   - **Remove**: Delete the entire rule block (name through last field)
   - **Update**: Modify only the specific fields that need changing
   - Preserve existing comments and formatting. Do not reformat untouched rules.

5. **Validate**
   Run: `agentsh policy validate <name>`
   If validation fails, fix and re-validate.
   If `agentsh` binary is not available, warn the user to validate manually.

6. **Summarize**
   Show what changed and explain the effect:
   "Added network rule `allow-stripe` before `approve-unknown-https`. Stripe API traffic on port 443 will now be allowed without approval."

## Insertion Position Rules

| Scenario | Position |
|----------|----------|
| New deny rule | Before any broader matching non-deny rule in that category |
| New allow rule | Before the default-deny catch-all |
| More specific rule | Before less specific rules matching the same pattern |
| Uncertain (deny) | Before the first non-deny rule in that category |
| Uncertain (allow) | Immediately before the default-deny rule for that category |

## Database Rules

DB policy evaluation is different from file/network/command ordering:

- `database_rules`: any matching deny wins, regardless of order. Non-deny decisions (`allow`, `audit`, `redirect`, `approve`) must cover every object slot in the effect; uncovered objects become implicit deny. Rule order only breaks ties for reporting the primary contributing rule.
- `database_connection_rules`: all matching rules are considered and the most restrictive verb wins (`deny > approve > audit > allow`).
- `passthrough` DB services can use connection rules only; statement rules are unavailable because AgentSH cannot inspect SQL.
- `decision: redirect` is statement-level only. It requires read-only operations, exactly one canonical `relations` source selector, `match_object_resolution: catalog_resolved`, and `redirect.relation` as a canonical `schema.name` target.
- `policies.db.unavoidability: enforce` should be paired with declared `db_services`; it blocks direct DB egress from governed processes and routes through AgentSH-generated DB proxy redirects.
- When editing mutation allow/approve/audit rules, preserve or add `require_where: true` for sensitive Postgres `modify`/`delete` rules when the operator wants no-WHERE mutations to fail closed. Do not add it to `MUTATE`, `*`, `read`, DDL, session, transaction, or procedural rules.

When editing DB rules, prefer adding narrow denies for risky operations and explicit non-deny coverage for intended objects. Avoid broad `allow` rules across all services unless the user explicitly asks for that posture.

## HTTP Services

Use `http_services` when the user needs method/path-level API control or credential substitution for a declared upstream. Keep ordinary `network_rules` for simple host/port access.

- `http_services[].upstream` must be HTTPS in normal policy files.
- If `secret` is present, ensure a matching top-level `providers` entry exists and `inject.header.template` contains `{{secret}}`.
- `expose_as` must be a valid environment variable name and must not collide with LLM proxy env vars.
- `services:` is obsolete; use `http_services:`.

## Guardrails

- **Minimal edits only** — only touch the rules the user asked about
- **Preserve formatting** — keep existing comments, blank lines, section headers
- **Respect ordering** — never blindly append; consider first-match-wins
- **Name new rules** in `verb-noun` format matching the existing policy style
- **Warn about shadowing** — if a new rule would be unreachable because an earlier rule matches the same pattern, warn the user
- **Warn about removal side-effects** — removing a deny rule may expose an allow rule that was previously unreachable; removing an allow rule may expose a deny. Explain the ordering impact when summarizing.
- **Warn about DB coverage gaps** — a DB `allow`, `audit`, `redirect`, or `approve` that covers only one relation/function does not cover other objects touched by the same SQL statement.

## Schema Reference

Read `skills/agentsh-policy-shared/schema-reference.md` for the complete policy YAML schema before making edits. If this file is not accessible, use the existing policy file as your reference for field names and structure. For rule categories not present in the existing file, ask the user for details rather than guessing.
