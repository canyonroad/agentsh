# AgentSH Policy Skills

AI-assistant skills for creating and editing AgentSH security policies. Works in Claude Code, NanoClaw, and other LLM-powered environments.

## Skills

| Skill | Description |
|-------|-------------|
| **agentsh-policy-create** | Create new policies from built-in templates (default, dev-safe, ci-strict, agent-sandbox) |
| **agentsh-policy-edit** | Add, remove, or update rules in existing policies with first-match-wins ordering awareness |

Both skills reference a shared schema in `agentsh-policy-shared/schema-reference.md` covering all 17 rule categories.

## Installation

### Claude Code

Copy the skill directories into your Claude Code skills folder:

```bash
# Project-level (recommended — other contributors get the skills too)
cp -r skills/agentsh-policy-create .claude/skills/
cp -r skills/agentsh-policy-edit .claude/skills/
cp -r skills/agentsh-policy-shared .claude/skills/

# User-level (available in all your projects)
cp -r skills/agentsh-policy-create ~/.claude/skills/
cp -r skills/agentsh-policy-edit ~/.claude/skills/
cp -r skills/agentsh-policy-shared ~/.claude/skills/
```

### NanoClaw

Copy the skill directories into your NanoClaw skills folder:

```bash
cp -r skills/agentsh-policy-create ~/.nanoclaw/skills/
cp -r skills/agentsh-policy-edit ~/.nanoclaw/skills/
cp -r skills/agentsh-policy-shared ~/.nanoclaw/skills/
```

### Other LLM environments

Copy the three directories (`agentsh-policy-create`, `agentsh-policy-edit`, `agentsh-policy-shared`) into whatever skills/prompts directory your environment uses. The skills are standard markdown files with YAML frontmatter — any system that loads skill files will work.

## Usage

Once installed, the skills activate automatically when you ask your AI assistant to work with policies:

**Creating a new policy:**
> "Create a policy for my CI pipeline that only allows npm registry access and blocks all credential files"

**Editing an existing policy:**
> "Allow my app to connect to api.stripe.com on port 443"
> "Remove the approval requirement for curl downloads"
> "Increase the session timeout to 8 hours"

The skills handle template selection, YAML generation, rule ordering (first-match-wins), and validation via `agentsh policy validate`.
