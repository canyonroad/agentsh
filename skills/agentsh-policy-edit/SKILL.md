---
name: agentsh-policy-edit
description: Use when adding, removing, or updating rules in an existing AgentSH policy, modifying security permissions, changing resource limits, or editing policy YAML files
---

# Edit AgentSH Policy

## Overview
Make targeted edits to existing AgentSH security policies — add, remove, or update rules. Understands first-match-wins evaluation semantics and correct insertion ordering.

## When to Use
- User asks to add/remove/update a policy rule ("allow stripe.com", "block file deletes")
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
   - **Rule category** — file_rules, network_rules, command_rules, unix_socket_rules, registry_rules, signal_rules, dns_redirects, connect_redirects, resource_limits, env_policy, audit, mcp_rules, package_rules, process_contexts, process_identities, env_inject, transparent_commands
   - **Operation** — add a new rule, remove an existing rule, or modify an existing rule
   - **Insertion position** — where in the rule order (for new rules)

3. **Determine insertion position** (for new rules)
   First-match-wins means ordering matters:
   - Place deny rules before any broader matching rule regardless of its decision — any non-deny rule (`allow`, `approve`, `redirect`, `audit`, `absorb`, `soft_delete`) that matches first will shadow the deny
   - Place allow rules before the default-deny catch-all at the end
   - Place more specific rules before less specific ones
   - When in doubt: deny rules go before the first non-deny rule in that category; allow rules go before the default-deny

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

## Guardrails

- **Minimal edits only** — only touch the rules the user asked about
- **Preserve formatting** — keep existing comments, blank lines, section headers
- **Respect ordering** — never blindly append; consider first-match-wins
- **Name new rules** in `verb-noun` format matching the existing policy style
- **Warn about shadowing** — if a new rule would be unreachable because an earlier rule matches the same pattern, warn the user
- **Warn about removal side-effects** — removing a deny rule may expose an allow rule that was previously unreachable; removing an allow rule may expose a deny. Explain the ordering impact when summarizing.

## Schema Reference

Read `skills/agentsh-policy-shared/schema-reference.md` for the complete policy YAML schema before making edits. If this file is not accessible, use the existing policy file as your reference for field names and structure. For rule categories not present in the existing file, ask the user for details rather than guessing.
