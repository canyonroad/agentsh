#!/bin/sh
# Invoked via symlinks placed by install-agent-wrappers.sh at the original
# location of each agent binary (e.g. /usr/local/share/npm-global/bin/opencode).
# Real binary lives at the same path with a .real suffix (move-aside-and-replace).
#
# Routes the agent through `agentsh wrap`. Fail-CLOSED: any health-check
# failure refuses the launch with a non-zero exit and a stderr message.
#
# This deviates from the parent kit's "never brick the sandbox" posture
# (parent spec §7) because this kit's purpose IS enforcement; running
# unenforced when the operator asked for enforcement is the worse failure.
#
# FAKE_ROOT is a TEST-ONLY hook: when set, /run/agentsh paths are relocated
# under that root. It is ONLY honored when AGENTSH_TEST=1 is also set, so a
# sandboxed process that can manipulate environment variables cannot use
# FAKE_ROOT to redirect path resolution. Production must NOT set FAKE_ROOT or
# AGENTSH_TEST.

set -u

# Gated test hook.
if [ "${AGENTSH_TEST:-}" = "1" ]; then
    FAKE_ROOT="${FAKE_ROOT:-}"
else
    FAKE_ROOT=""
fi

real="${0}.real"
tier_file="${FAKE_ROOT}/run/agentsh/tier"

if [ ! -x "$real" ]; then
    echo "agentsh-agent-wrap: real binary not found at $real; refusing to launch $(basename "$0")" >&2
    exit 127
fi

# command -v also reports shell functions; exec below dispatches to binaries
# only, so a function-named agentsh fails non-zero — still fail-closed.
if ! command -v agentsh >/dev/null 2>&1; then
    echo "agentsh-agent-wrap: agentsh binary missing; refusing to launch $(basename "$0") without enforcement" >&2
    exit 1
fi

tier=$(cat "$tier_file" 2>/dev/null || echo missing)
if [ "$tier" != "shim" ]; then
    echo "agentsh-agent-wrap: enforcement not active (tier='$tier'); refusing to launch $(basename "$0")" >&2
    exit 1
fi

exec agentsh wrap -- "$real" "$@"
