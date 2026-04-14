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

3. Start a server with seccomp execve enabled, capturing stderr to a
   file so we can inspect it for warnings:

   ```bash
   sudo agentsh server --config /etc/agentsh/config.yaml \
     >/tmp/agentsh-server.log 2>&1 &
   ```

   (The server is backgrounded from an interactive shell here, not
   managed by systemd, so `journalctl` will not see it — the captured
   log file is the source of truth.)

4. Create a session and run a Go workload that stresses preemption.
   The packaged `agentsh` binary is itself a Go program with async
   preemption enabled, so invoking it inside the sandbox exercises the
   same SIGURG + seccomp-notify interaction as the PR #225 repro. No
   Go toolchain or source checkout is needed:

   ```bash
   sid=$(agentsh session create --workspace /tmp --json | jq -r .id)
   agentsh exec "$sid" -- agentsh --help >/dev/null
   ```

   Expected: completes in well under 10 seconds with exit code 0.

5. Repeat the same stressed invocation in a tight loop for 100
   iterations — this is the release gate, so the loop must run the
   Go-binary workload from step 4, not a C builtin like `/bin/true`:

   ```bash
   for i in $(seq 1 100); do
     agentsh exec "$sid" -- agentsh --help >/dev/null \
       || { echo "FAIL iter $i"; exit 1; }
   done
   echo "PASS: 100 iterations"
   ```

   Expected: 100 PASS. A hang or high failure rate indicates Layer 1
   is not engaged and Layer 2 alone is insufficient.

6. Confirm Layer 1 actually engaged. The fallback path logs a WARN
   line; its absence is the success signal. Check the captured server
   log:

   ```bash
   if grep -q "WaitKillable unexpectedly unavailable" /tmp/agentsh-server.log; then
     echo "FAIL: Layer 1 fell back to SIGURG signal mask (Layer 2) only" >&2
     grep "WaitKillable" /tmp/agentsh-server.log >&2
     exit 1
   fi
   echo "PASS: no Layer 1 fallback warnings"
   ```

   Expected: `PASS: no Layer 1 fallback warnings`. If step 5 PASSed but
   this step FAILs, Layer 2 was silently masking a Layer 1 regression.

## Recording results

Paste the output of `uname -a`, `dpkg -l libseccomp2 | tail -1` (on the
host — note we do not depend on this but it's useful context), the
PASS line from step 5, and the PASS line from step 6 into the release
PR description under a `### arm64 SIGURG reproducer` heading.
