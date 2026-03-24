---
name: agentsh-policy-create
description: Use when creating a new AgentSH security policy, making a policy for an agent sandbox, CI pipeline, or development environment, or asking for a new policy YAML file
---

# Create AgentSH Policy

## Overview

Create new AgentSH security policies from built-in templates, customized to the user's use case. Produces valid YAML policy files with correct structure, evaluation semantics, and defensive defaults.

## When to Use

- User asks to create/make/generate a new policy
- User describes a use case that needs a policy ("policy for my CI pipeline")
- User wants to set up AgentSH for the first time
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

## Schema Reference

Read `skills/agentsh-policy-shared/schema-reference.md` for the complete policy YAML schema before generating any policy content. If this file is not accessible, proceed using only the guardrails above plus the template file read in Step 3. Do not generate policy YAML without either the schema reference or a template.
