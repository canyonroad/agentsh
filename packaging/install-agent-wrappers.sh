#!/bin/sh
# /usr/lib/agentsh/install-agent-wrappers.sh
# Probe /usr/bin for known agent binaries and create /usr/local/bin/<name>
# symlinks pointing at /usr/lib/agentsh/agent-wrap. Skips when:
#   - the agent binary isn't present (nothing to wrap)
#   - /usr/local/bin/<name> already exists (don't fight the agent kit)
#
# Idempotent. Fail-open if the wrap script itself is missing (warns, exits 0,
# leaves /usr/local/bin untouched).
#
# FAKE_ROOT is a TEST-ONLY hook: when set, all paths are relocated under it.
# Production must NOT set FAKE_ROOT.

set -eu

FAKE_ROOT="${FAKE_ROOT:-}"
WRAP="${FAKE_ROOT}/usr/lib/agentsh/agent-wrap"
DEST="${FAKE_ROOT}/usr/local/bin"
BIN="${FAKE_ROOT}/usr/bin"

# Known agent binaries. Extend this list as Docker Sandboxes adds support.
AGENTS="claude opencode gemini codex cursor"

if [ ! -x "$WRAP" ]; then
    echo "install-agent-wrappers: agent-wrap missing at $WRAP; skipping (kit still works without auto-wrap)" >&2
    exit 0
fi

mkdir -p "$DEST"

for agent in $AGENTS; do
    if [ ! -x "$BIN/$agent" ]; then
        continue
    fi
    target="$DEST/$agent"
    if [ -e "$target" ] || [ -L "$target" ]; then
        echo "install-agent-wrappers: $target exists; not overwriting" >&2
        continue
    fi
    ln -s "$WRAP" "$target"
    echo "install-agent-wrappers: wrapped $agent"
done
