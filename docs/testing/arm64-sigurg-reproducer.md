# arm64 SIGURG preemption reproducer

Manual regression test for the Go SIGURG / seccomp user-notify interaction
fixed in PR #225 and hardened in the libseccomp 2.6 defense-in-depth
change. Run this before cutting any release that touches `internal/netmonitor/unix/`
or `cmd/agentsh-unixwrap/`.

## What this verifies

- Layer 1 (`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`, kernel ≥6.0) is actually
  engaged on arm64 — not just compiled in.
- Under Go async preemption (~10ms SIGURG cadence), seccomp notifications
  are not interrupted by ERESTARTSYS loops.

## Environment

- arm64 Linux VM (bare-metal or qemu-system-aarch64).
- Kernel ≥6.0 (`uname -r` to confirm).
- agentsh binaries built by the release workflow (deb or tar.gz for arm64).

A suitable test host is a stock Ubuntu 24.04 arm64 cloud instance — the
Docker test matrix does not exercise this case because GitHub does not
offer an arm64 runner with FUSE and seccomp user-notify permissions in the
same image.

## Procedure

1. Install the release deb:

   ```bash
   sudo dpkg -i agentsh_<version>_linux_arm64.deb
   ```

2. Install the shell shim:

   ```bash
   sudo agentsh shim install-shell \
     --root / \
     --shim /usr/bin/agentsh-shell-shim \
     --bash \
     --i-understand-this-modifies-the-host
   ```

3. Start a server with seccomp execve enabled:

   ```bash
   sudo agentsh server --config /etc/agentsh/config.yaml &
   ```

4. Create a session and run a Go workload that stresses preemption:

   ```bash
   sid=$(agentsh session create --workspace /tmp --json | jq -r .id)
   agentsh exec "$sid" -- go run -gcflags=all=-N ./cmd/agentsh --help
   ```

   Expected: completes in well under 10 seconds with exit code 0.

5. Repeat step 4 in a tight loop for 100 iterations:

   ```bash
   for i in $(seq 1 100); do
     agentsh exec "$sid" -- /bin/true >/dev/null || { echo "FAIL iter $i"; exit 1; }
   done
   echo "PASS: 100 iterations"
   ```

   Expected: 100 PASS. A hang or high failure rate indicates Layer 1 is
   not engaged and Layer 2 alone is insufficient — investigate which
   layer is broken (check `journalctl` for the
   `WaitKillable unexpectedly unavailable` warning).

## Recording results

Paste the output of `uname -a`, `dpkg -l libseccomp2 | tail -1` (on the
host — note we do not depend on this but it's useful context), and the
PASS line from step 5 into the release PR description under a
`### arm64 SIGURG reproducer` heading.
