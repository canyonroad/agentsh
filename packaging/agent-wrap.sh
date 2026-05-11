#!/bin/sh
# /usr/lib/agentsh/agent-wrap — invoked via symlinks at /usr/local/bin/<agent>.
# Routes the agent through `agentsh wrap`. Fail-CLOSED: any health-check
# failure refuses the launch with a non-zero exit and a stderr message.
#
# This deviates from the parent kit's "never brick the sandbox" posture
# (parent spec §7) because this kit's purpose IS enforcement; running
# unenforced when the operator asked for enforcement is the worse failure.
#
# FAKE_ROOT is a TEST-ONLY hook: when set, /usr/bin and /run/agentsh paths
# are relocated under that root. Production must NOT set FAKE_ROOT.

set -u

# Test hook. Empty in production.
FAKE_ROOT="${FAKE_ROOT:-}"

name=$(basename "$0")
real="${FAKE_ROOT}/usr/bin/$name"
tier_file="${FAKE_ROOT}/run/agentsh/tier"

if [ ! -x "$real" ]; then
    echo "agentsh-agent-wrap: real binary not found at $real" >&2
    exit 127
fi

if ! command -v agentsh >/dev/null 2>&1; then
    echo "agentsh-agent-wrap: agentsh binary missing; refusing to launch $name without enforcement" >&2
    exit 1
fi

tier=$(cat "$tier_file" 2>/dev/null || echo missing)
if [ "$tier" != "shim" ]; then
    echo "agentsh-agent-wrap: enforcement not active (tier='$tier'); refusing to launch $name" >&2
    exit 1
fi

exec agentsh wrap -- "$real" "$@"
