# AgentSH Policy Skills Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create two skills (`policy-create` and `policy-edit`) with a shared schema reference for creating and editing AgentSH policy YAML files from any LLM environment.

**Architecture:** Three markdown files — a shared schema reference read by both skills at invocation time, plus one skill file for each workflow (create vs edit). Skills follow the standard `SKILL.md` format with YAML frontmatter.

**Tech Stack:** Markdown skill files, YAML policy format, `agentsh policy validate` CLI for validation.

**Spec:** `docs/superpowers/specs/2026-03-23-agentsh-policy-skills-design.md`

---

## File Structure

```
skills/
  agentsh-policy-create/
    SKILL.md                     # Create: main skill with flow + guardrails
  agentsh-policy-edit/
    SKILL.md                     # Edit: main skill with flow + guardrails
  agentsh-policy-shared/
    schema-reference.md          # Shared: full YAML schema reference
```

All content comes from the spec's "Shared Schema Reference" and "Skill" sections. No Go code changes.

---

### Task 1: Create shared schema reference

**Files:**
- Create: `skills/agentsh-policy-shared/schema-reference.md`

This is the foundation — both skills read it at invocation time.

- [ ] **Step 1: Create directory**

```bash
mkdir -p skills/agentsh-policy-shared
```

- [ ] **Step 2: Write schema-reference.md**

Content comes directly from the spec's "Shared Schema Reference" section. Include:
- Top-level policy structure (version, name, description + all rule categories)
- All rule type tables (file_rules, network_rules, command_rules, unix_socket_rules, registry_rules, signal_rules, dns_redirects, connect_redirects, resource_limits, env_policy, audit, env_inject, mcp_rules, package_rules, process_contexts, process_identities, transparent_commands)
- Evaluation semantics (first-match-wins, default deny, variable expansion, glob/regex/duration syntax)
- Idiomatic examples (one per common operation: allow domain, block path, approve command, redirect command)

The spec already contains the complete schema tables and examples — transfer them into this file with a brief header explaining the file's purpose.

- [ ] **Step 3: Verify schema against model.go**

Spot-check that the schema reference fields match `internal/policy/model.go` YAML tags. Specifically verify:
- FileRule fields and valid operations
- NetworkRule fields
- CommandRule redirect_to structure
- SignalRule signal groups and target types
- ProcessContext advanced fields (stop_at, pass_through, race_policy)

- [ ] **Step 4: Commit**

```bash
git add skills/agentsh-policy-shared/schema-reference.md
git commit -m "feat: add shared AgentSH policy schema reference"
```

---

### Task 2: Create policy-create skill

**Files:**
- Create: `skills/agentsh-policy-create/SKILL.md`
- Reference: `configs/policies/default.yaml` (template style reference)
- Reference: `skills/agentsh-policy-shared/schema-reference.md`

- [ ] **Step 1: Create directory**

```bash
mkdir -p skills/agentsh-policy-create
```

- [ ] **Step 2: Write SKILL.md**

Structure:

```markdown
---
name: agentsh-policy-create
description: Use when creating a new AgentSH security policy, making a policy for an agent sandbox, CI pipeline, or development environment, or asking for a new policy YAML file
---

# Create AgentSH Policy

## Overview
[1-2 sentences: what this skill does]

## When to Use
[Bullet list of triggers]

## Flow
[Numbered steps from spec section "Skill: policy-create" → Flow]
1. Locate policy directory
2. Understand use case (with template mapping table)
3. Select template
4. Customize
5. Name & write
6. Validate
7. Update config reminder

## Template Mapping
[Table: use case → template name]

## Guardrails
[From spec: version 1, name+description required, default-deny catch-alls, verb-noun names, section comments]

## Schema Reference
Read `skills/agentsh-policy-shared/schema-reference.md` for the complete policy YAML schema.
```

Key details:
- Frontmatter: name and description only, description starts with "Use when..."
- Description must NOT summarize the workflow (CSO rule)
- Flow steps reference `AskUserQuestion` for the use-case question
- Template mapping table directly from spec
- Explicit instruction to read schema-reference.md at invocation
- Include instruction to read the closest template file from the policy directory before customizing

- [ ] **Step 3: Commit**

```bash
git add skills/agentsh-policy-create/SKILL.md
git commit -m "feat: add agentsh-policy-create skill"
```

---

### Task 3: Create policy-edit skill

**Files:**
- Create: `skills/agentsh-policy-edit/SKILL.md`
- Reference: `skills/agentsh-policy-shared/schema-reference.md`

- [ ] **Step 1: Create directory**

```bash
mkdir -p skills/agentsh-policy-edit
```

- [ ] **Step 2: Write SKILL.md**

Structure:

```markdown
---
name: agentsh-policy-edit
description: Use when adding, removing, or updating rules in an existing AgentSH policy, modifying security permissions, changing resource limits, or editing policy YAML files
---

# Edit AgentSH Policy

## Overview
[1-2 sentences: what this skill does]

## When to Use
[Bullet list of triggers, including "When NOT to use" pointing to policy-create]

## Flow
[Numbered steps from spec section "Skill: policy-edit" → Flow]
1. Locate & read the policy
2. Understand the intent (map to rule category + operation + position)
3. Determine insertion position (ordering rules)
4. Make the edit (add/remove/update with Edit tool)
5. Validate
6. Summarize

## Insertion Position Rules
[From spec: deny before allow, allow before default-deny, specific before general]

## Guardrails
[From spec: minimal edits, preserve formatting, respect ordering, verb-noun names, warn about shadowing]

## Schema Reference
Read `skills/agentsh-policy-shared/schema-reference.md` for the complete policy YAML schema.
```

Key details:
- Same frontmatter conventions as policy-create
- Explicit instruction about first-match-wins insertion ordering
- Emphasize minimal edits and formatting preservation
- Include the summarization format ("Added rule X before Y. Effect: ...")
- Explicit instruction to read schema-reference.md at invocation

- [ ] **Step 3: Commit**

```bash
git add skills/agentsh-policy-edit/SKILL.md
git commit -m "feat: add agentsh-policy-edit skill"
```

---

### Task 4: Test skills with subagent scenarios

**Files:**
- Read: `skills/agentsh-policy-create/SKILL.md`
- Read: `skills/agentsh-policy-edit/SKILL.md`
- Read: `skills/agentsh-policy-shared/schema-reference.md`
- Read: `configs/policies/default.yaml` (for edit test)

Test each skill by dispatching a subagent with the skill content loaded, giving it a realistic task, and verifying the output is correct.

- [ ] **Step 1: Test policy-create — basic agent sandbox**

Dispatch subagent with policy-create skill content. Task: "Create a policy for an AI coding agent that needs access to the workspace, npm/pip registries, GitHub, and should block all credential access."

Verify output:
- Valid YAML structure
- Correct template choice (agent-default or default)
- Network rules for npm, pip, GitHub
- File rules blocking credentials
- Default-deny catch-alls present
- verb-noun rule names

- [ ] **Step 2: Test policy-edit — add a network rule**

Dispatch subagent with policy-edit skill content + `configs/policies/default.yaml` loaded. Task: "Allow the agent to connect to api.stripe.com and dashboard.stripe.com on port 443."

Verify output:
- Rule inserted before `approve-unknown-https` (not appended to end)
- Correct YAML structure (name, description, domains, ports, decision)
- Existing rules untouched
- verb-noun name (e.g., `allow-stripe`)

- [ ] **Step 3: Test policy-edit — remove a rule**

Dispatch subagent with policy-edit skill content + `configs/policies/default.yaml` loaded. Task: "Remove the approval requirement for curl and wget downloads."

Verify output:
- `approve-curl-wget` rule removed
- Surrounding rules preserved
- Comments and formatting intact

- [ ] **Step 4: Test policy-edit — modify resource limits**

Dispatch subagent with policy-edit skill content + `configs/policies/default.yaml` loaded. Task: "Increase the session timeout to 8 hours and raise the memory limit to 4096 MB."

Verify output:
- Only `session_timeout` and `max_memory_mb` changed
- Other resource_limits fields untouched

- [ ] **Step 5: Fix any issues found during testing**

If any test reveals gaps (missing schema info, unclear instructions, wrong ordering), update the relevant skill file and re-test.

- [ ] **Step 6: Commit any fixes**

```bash
git add skills/
git commit -m "fix: address issues found during skill testing"
```

---

### Task 5: Final validation and cleanup

- [ ] **Step 1: Word count check**

```bash
wc -w skills/agentsh-policy-create/SKILL.md
wc -w skills/agentsh-policy-edit/SKILL.md
wc -w skills/agentsh-policy-shared/schema-reference.md
```

Skills should be under 500 words each. Schema reference will be larger (it's heavy reference material — that's fine in a separate file per writing-skills conventions).

- [ ] **Step 2: Verify cross-references**

Confirm both skills reference `skills/agentsh-policy-shared/schema-reference.md` correctly.

- [ ] **Step 3: Verify frontmatter**

Check both SKILL.md files:
- Only `name` and `description` in frontmatter
- Name uses only letters, numbers, hyphens
- Description starts with "Use when..."
- Description does NOT summarize the workflow
- Total frontmatter under 1024 characters

- [ ] **Step 4: Final commit if needed**

```bash
git add skills/
git commit -m "chore: final cleanup for policy skills"
```
