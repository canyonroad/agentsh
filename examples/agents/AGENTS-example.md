# Command Execution via agentsh

**All shell commands in this project MUST be executed through agentsh.**

When using the Bash tool, wrap every command with `agentsh exec`:

## Required Syntax

```bash
agentsh exec SESSION_ID -- COMMAND [ARGS...]
```

The `--` separator is **required** between the session ID and the command.

## Examples

Instead of:
```bash
ls -la
npm install
go build ./...
```

Use:
```bash
agentsh exec my-session -- ls -la
agentsh exec my-session -- npm install
agentsh exec my-session -- go build ./...
```

## Using Environment Variables (Recommended)

When `AGENTSH_SESSION_ID` is set, pass all command arguments after `exec`:

```bash
export AGENTSH_SESSION_ID=my-session
agentsh exec -- ls -la
agentsh exec -- npm install
```

## Auto-Creating Sessions

Use `--root` to auto-create a session if it doesn't exist:

```bash
agentsh exec my-session --root /path/to/workspace -- ls -la
```

Or set the environment variable:

```bash
export AGENTSH_SESSION_ROOT=/path/to/workspace
agentsh exec my-session -- ls -la
```

## Common Flags

| Flag            | Description                          |
|-----------------|--------------------------------------|
| `--timeout 30s` | Command timeout (e.g., 30s, 5m)      |
| `--output json` | JSON structured output               |
| `--stream`      | Stream output as produced            |
| `--pty`         | Interactive PTY mode                 |

## Environment Variables

| Variable               | Description                                      |
|------------------------|--------------------------------------------------|
| `AGENTSH_SESSION_ID`   | Default session ID (avoids passing as argument)  |
| `AGENTSH_SESSION_ROOT` | Root directory for auto-creating sessions        |
| `AGENTSH_SERVER`       | Server URL (default: `http://127.0.0.1:8080`)    |
