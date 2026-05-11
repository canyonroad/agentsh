#!/bin/sh
# Discover known agent binaries via `command -v`, move them aside to a
# `.real` sibling, and put a symlink to /usr/lib/agentsh/agent-wrap in
# the original location.
#
# Idempotent. Fail-open if the wrap script itself is missing.

set -eu

if [ "${AGENTSH_TEST:-}" = "1" ]; then
    FAKE_ROOT="${FAKE_ROOT:-}"
    _AGENT_PATH="${FAKE_TEST_PATH:-$PATH}"
else
    FAKE_ROOT=""
    _AGENT_PATH="$PATH"
fi

WRAP="${FAKE_ROOT}/usr/lib/agentsh/agent-wrap"

AGENTS="claude opencode gemini codex cursor"

if [ ! -x "$WRAP" ]; then
    echo "install-agent-wrappers: agent-wrap missing at $WRAP; skipping (kit still works without auto-wrap)" >&2
    exit 0
fi

for agent in $AGENTS; do
    real=$(PATH="$_AGENT_PATH" command -v "$agent" 2>/dev/null || true)
    if [ -z "$real" ] || [ ! -x "$real" ]; then
        continue
    fi

    # Idempotency: already-wrapped silent skip.
    if [ -L "$real" ] && [ "$(readlink "$real")" = "$WRAP" ] && [ -e "${real}.real" ]; then
        continue
    fi

    # Conflict: .real exists but $real is not our symlink.
    if [ -e "${real}.real" ]; then
        echo "install-agent-wrappers: ${real}.real already exists but $real is not our symlink; not overwriting" >&2
        continue
    fi

    mv "$real" "${real}.real"
    ln -s "$WRAP" "$real"
    echo "install-agent-wrappers: wrapped $agent at $real (real moved to ${real}.real)" >&2
done
