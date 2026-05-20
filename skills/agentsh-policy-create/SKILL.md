---
name: agentsh-policy-create
description: Use when creating a new AgentSH security policy, including agent sandboxes, CI pipelines, development environments, HTTP service gateways, or Postgres-family database access policies
---

# Create AgentSH Policy

## Overview

Create new AgentSH security policies from built-in templates, customized to the user's use case. Produces valid YAML policy files with correct structure, evaluation semantics, and defensive defaults for file, network, command, HTTP service, and Postgres-family database controls.

## When to Use

- User asks to create/make/generate a new policy
- User describes a use case that needs a policy ("policy for my CI pipeline")
- User wants to set up AgentSH for the first time
- User wants controlled access to a declared HTTP API or Postgres-family database
- NOT for editing existing policies (use agentsh-policy-edit)

## Flow

1. **Locate policy directory**
   - Look for `config.yml` or `config.yaml` in the project root to find `policies.dir`
   - If not found, look for a `configs/policies/` directory
   - Fall back to asking the user with AskUserQuestion

2. **Understand the use case**
   Use AskUserQuestion to ask: "What will this policy protect?"

   | Use Case | Template |
   |----------|----------|
   | AI agent (code tasks) | `default` or `agent-default` |
   | CI/CD pipeline | `ci-strict` |
   | Local development | `dev-safe` |
   | Strict agent sandbox | `agent-sandbox` |
   | Observation/profiling | `agent-observe` |
   | Declared HTTP API gateway | Start from `default` |
   | Postgres-family database access | Start from `default` |
   | Custom / other | Start from `default` |

3. **Select template**
   - Read the matching template from the policy directory (e.g., `configs/policies/default.yaml`)
   - On Windows, prefer the `-windows` variant if available (e.g., `default-windows.yaml`, `ci-strict-windows.yaml`)
   - If templates are not available locally, use the schema reference to generate a baseline

4. **Customize**
   Based on the template read in Step 3, ask only about gaps — skip categories the template already handles well:
   - "Which domains does your app need to reach?" → add network rules
   - "Any paths outside the workspace it needs?" → add file rules
   - "Any commands to block or require approval?" → add command rules
   - "Should any HTTP APIs be exposed through AgentSH?" → add `http_services` plus `providers` when credential substitution is needed
   - "Should any Postgres-family databases be mediated?" → add `db_services`, `database_connection_rules`, `database_rules`, and `policies.db`

   For database policies, ask for:
   - service name, dialect (`postgres`, `aurora_postgres`, `redshift`, `cockroachdb`), upstream `host:port`, and `tls_mode`
   - connection constraints: DB user, database name, application name, replication/cancel handling
   - statement intent: read/write/admin operations, schemas/objects, catalog selectors (`relations`, `functions`) if known
   - redaction preference: `policies.db.log_statements`, `approval_statement_preview`, and `approval_statement_preview_chars`
   - unavoidability posture: `off`, `observe`, or `enforce`

5. **Name & write**
   - Ask for a policy name
   - Generate the YAML with descriptive section comments matching built-in policy style
   - Write to the policy directory

6. **Validate**
   Run: `agentsh policy validate <name>`
   If validation fails, fix and re-validate.
   If `agentsh` binary is not available, warn the user to validate manually.

7. **Update config reminder**
   If `config.yml` has a `policies.allowed` list, remind the user to add the new policy name.

## Guardrails

- Always use `version: 1`
- Every policy must have `name` and `description`
- End rule-list categories (file_rules, network_rules, command_rules) with a default-deny catch-all
- Use descriptive rule names in `verb-noun` format (e.g., `allow-npm`, `deny-ssh-keys`)
- Include section comment headers matching built-in policy style
- First match wins — place specific rules before general ones
- Do not invent runtime support for non-Postgres databases. Current DB enforcement is Postgres-family only.
- For `http_services`, prefer path/method rules over broad network allows when the user needs audited API surface control.
- For `database_rules`, remember DB evaluation is not simple first-match-wins: any matching deny wins, non-deny rules must cover every object slot, and uncovered objects fail closed.
- For Postgres `UPDATE`/`DELETE` access to sensitive relations, ask whether accidental full-table mutation should be blocked. Use `require_where: true` only on rules whose `operations` expand exclusively to `modify` and/or `delete`; explain that it is syntactic, `WHERE true` still satisfies it, and another unguarded non-deny rule can still cover the same effect.
- For DB `redirect`, only author safe read-only Postgres relation replacement: one canonical source in `relations`, `match_object_resolution: catalog_resolved`, and `redirect.relation`.

## Schema Reference

Read `skills/agentsh-policy-shared/schema-reference.md` for the complete policy YAML schema before generating any policy content. If this file is not accessible, proceed using only the guardrails above plus the template file read in Step 3. Do not generate policy YAML without either the schema reference or a template.
