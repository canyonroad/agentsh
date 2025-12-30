# CI/CD Integration Guide

This guide shows how to integrate agentsh session reports into your CI/CD pipelines.

## Overview

When running AI agents in CI/CD pipelines, agentsh captures all activity for auditing. After the agent completes, generate a report to:

- Verify the agent behaved as expected
- Detect policy violations or anomalies
- Create an audit trail for compliance
- Debug failed runs

## GitHub Actions Example

```yaml
name: AI Agent Task

on:
  workflow_dispatch:
    inputs:
      task:
        description: 'Task for the AI agent'
        required: true

jobs:
  run-agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install agentsh
        run: |
          curl -fsSL https://agentsh.dev/install.sh | bash
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Start agentsh server
        run: |
          agentsh server start --background
          sleep 2

      - name: Create session
        id: session
        run: |
          SESSION=$(agentsh session create --workspace . --policy ci-agent | jq -r '.id')
          echo "id=$SESSION" >> $GITHUB_OUTPUT

      - name: Run AI agent
        env:
          AGENTSH_SESSION: ${{ steps.session.outputs.id }}
        run: |
          # Your AI agent command here
          agentsh exec $AGENTSH_SESSION -- your-agent-cli "${{ inputs.task }}"

      - name: Generate session report
        if: always()
        run: |
          agentsh report ${{ steps.session.outputs.id }} \
            --level=detailed \
            --output=session-report.md

      - name: Upload report as artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agentsh-session-report
          path: session-report.md

      - name: Add report to job summary
        if: always()
        run: |
          echo "## Session Report" >> $GITHUB_STEP_SUMMARY
          cat session-report.md >> $GITHUB_STEP_SUMMARY

      - name: Cleanup session
        if: always()
        run: agentsh session destroy ${{ steps.session.outputs.id }}
```

## GitLab CI Example

```yaml
ai-agent-task:
  stage: build
  image: ubuntu:22.04
  variables:
    AGENTSH_SESSION: ""
  before_script:
    - curl -fsSL https://agentsh.dev/install.sh | bash
    - export PATH="$HOME/.local/bin:$PATH"
    - agentsh server start --background
    - sleep 2
    - export AGENTSH_SESSION=$(agentsh session create --workspace . --policy ci-agent | jq -r '.id')
  script:
    - agentsh exec $AGENTSH_SESSION -- your-agent-cli "do the task"
  after_script:
    - agentsh report $AGENTSH_SESSION --level=detailed --output=session-report.md
    - agentsh session destroy $AGENTSH_SESSION || true
  artifacts:
    when: always
    paths:
      - session-report.md
    reports:
      dotenv: agent.env
```

## Best Practices

### 1. Always Generate Reports

Use `if: always()` or `when: always` to ensure reports are generated even when the agent fails. Failed runs often have the most interesting findings.

### 2. Use Detailed Level for Artifacts

For artifact storage, use `--level=detailed` to capture the full investigation data.

### 3. Add to Job Summary (GitHub Actions)

Append the report to `$GITHUB_STEP_SUMMARY` for inline viewing without downloading artifacts.

### 4. Fail on Critical Findings

Add a step to parse the report and fail the build if critical findings are detected:

```yaml
- name: Check for violations
  run: |
    if grep -q "\[CRITICAL\]" session-report.md; then
      echo "Critical findings detected!"
      exit 1
    fi
```

### 5. Policy Per Environment

Use different policies for different CI contexts:

```yaml
# For PR checks - stricter
agentsh session create --policy pr-check

# For deployment agents - more permissive but audited
agentsh session create --policy deploy-agent
```

## Troubleshooting

### "No sessions found"

The agentsh server may have restarted or the session timed out. Use `--direct-db` for offline access.

### Report is empty or minimal

Check that your agent is actually running through agentsh:

```bash
# Wrong - agent runs outside agentsh
./my-agent

# Right - agent runs through agentsh
agentsh exec $SESSION -- ./my-agent
```
