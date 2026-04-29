// Package skillcheck scans AI agent skill installations (Claude Code skill
// directories) for prompt injection, exfiltration, hidden Unicode, scope
// violations, and other supply-chain risks before they become loadable by
// the agent.
//
// Architecture mirrors internal/pkgcheck: a CheckProvider interface,
// an Orchestrator that fans out to providers in parallel, an Evaluator
// that maps findings to a four-state Verdict (allow/warn/approve/block),
// and an action layer that quarantines on block via internal/trash.
//
// Triggers: an fsnotify-based watcher over ~/.claude/skills and
// ~/.claude/plugins/*/skills, plus an `agentsh skillcheck` CLI.
package skillcheck
