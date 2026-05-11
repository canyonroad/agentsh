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
# are relocated under that root. It is ONLY honored when AGENTSH_TEST=1 is
# also set, so a sandboxed process that can manipulate environment variables
# cannot use FAKE_ROOT to redirect path resolution. Production must NOT set
# FAKE_ROOT or AGENTSH_TEST.

set -u

# Test hook. Only honored when AGENTSH_TEST=1 is also set, so a sandboxed
# process that can manipulate environment variables cannot use FAKE_ROOT
# to redirect path resolution.
if [ "${AGENTSH_TEST:-}" = "1" ]; then
    FAKE_ROOT="${FAKE_ROOT:-}"
else
    FAKE_ROOT=""
fi

name=$(basename "$0")
real="${FAKE_ROOT}/usr/bin/$name"
tier_file="${FAKE_ROOT}/run/agentsh/tier"

if [ ! -x "$real" ]; then
    echo "agentsh-agent-wrap: real binary not found at $real; refusing to launch $name" >&2
    exit 127
fi

# command -v also reports shell functions; exec below dispatches to binaries
# only, so a function-named agentsh fails non-zero — still fail-closed.
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
