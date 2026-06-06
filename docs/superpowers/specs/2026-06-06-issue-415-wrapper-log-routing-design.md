# Issue #415: Route wrapper diagnostics off the wrapped command's stderr

**Date:** 2026-06-06
**Issue:** [#415](https://github.com/canyonroad/agentsh/issues/415) — Per-exec
"seccomp: filter loaded" line pollutes wrapped command's stderr (corrupts
`agentsh detect --output json`)
**Approach:** Option 3 from the issue — route, don't downgrade — implemented
as a log-fd handoff via env var.

## Problem

`agentsh-unixwrap` execs the real command in place, so the wrapper's stderr
*is* the wrapped command's stderr. Every successful filter install emits
`slog.Info("seccomp: filter loaded", ...)`
(`internal/netmonitor/unix/seccomp_linux.go:515`) via the wrapper's
process-default slog handler → stderr → user-visible stream. Commands with
machine-readable stderr (notably `agentsh detect --output json`) get a noise
prefix consumers must strip.

Downgrading to Debug was rejected in #411/#414: the line is a deliberate #369
diagnostic (`wait_killable` / `wait_killable_source`), asserted on by
`TestInstallFilter_EmitsWaitKillEngagedOnSupportedKernel` and
`TestInstallFilter_HonorsOperatorOverride`, and must stay visible in the
server log at default level.

Beyond the slog line, the wrapper also emits stdlib `log` success-path noise
(`landlock: restrictions applied` on every exec when Landlock is on,
PR_SET_PTRACER warnings, etc.) on the same fd.

## Decision summary

| Question | Decision |
|---|---|
| Which spawn paths | All three: server exec, shim relay, `agentsh wrap` CLI |
| What gets routed | All wrapper diagnostics (slog + stdlib `log`); fatals dual-write to routed dest + stderr |
| Fallback when no destination given | stderr (status quo) |
| Destination in shim/CLI paths | Local state-dir log file |

## Design

### Wrapper side (`cmd/agentsh-unixwrap`)

New env contract: `AGENTSH_WRAPPER_LOG_FD=<n>` — the number of an inherited
fd to receive all wrapper diagnostics.

A `setupLogging()` runs first thing in `main()`, before anything can log:

1. Env var unset → return; stderr remains the destination (manual
   invocation, version skew, tests).
2. Validate the fd with `fstat(2)`. Invalid → one warning to stderr, fall
   back to stderr. Logging must never abort an exec.
3. Valid → wrap in `*os.File` and point both sinks at it:
   - `log.SetOutput(f)` — stdlib `log.Printf` noise (landlock line,
     warnings).
   - `slog.SetDefault(slog.New(slog.NewTextHandler(f, nil)))` — the
     "seccomp: filter loaded" line emitted from `internal/netmonitor/unix`
     through the process-default logger.
4. Set `FD_CLOEXEC` on the fd: the final `syscall.Exec` closes it, the
   wrapped command never sees it, and pipe readers get EOF exactly when
   wrapper logging ends.

`log.Fatalf` call sites (~12) move to a local `fatalf()` helper that writes
to the routed destination **and** stderr, then exits 1 — a user whose
command dies still sees why.

**Env hygiene:** the wrapper execs with `os.Environ()`, so the env var would
leak to the wrapped command. A nested wrapper invocation (wrapped command →
shell → shim → wrapper) would inherit a stale fd number that may have been
reused by the intermediate process — the nested wrapper would write log
lines onto an arbitrary fd. Defenses:

- Wrapper strips `AGENTSH_WRAPPER_LOG_FD` from the environment before
  `syscall.Exec`.
- The shim's `filterShimInternalEnv`
  (`internal/shim/kernelinstall/install_linux.go`) adds the key to its strip
  list, as it already does for `AGENTSH_SIGNAL_SOCK_FD` and the argv0
  override. Each parent always sets its own authoritative value.

### Parent side — three spawn paths

**Server exec path** (`internal/api/core.go`, `buildWrapperSetup`):

- Create `os.Pipe()`; append the write end to `extraCfg.extraFiles`; compute
  the child fd dynamically (`3 + index` — 4 normally, 5 when the signal
  socket is present); set `AGENTSH_WRAPPER_LOG_FD` in both `wrappedReq.Env`
  and `extraCfg.env` (same dual-set pattern as the notify fd).
- New `extraProcConfig` field (`wrapperLogParent *os.File`) carries the read
  end. At spawn (alongside existing `notifyParentSock` handling): close the
  parent's write-end copy, then a drain goroutine `bufio.Scanner`s to EOF,
  emitting each line via server slog at Info:
  `slog.Info("unixwrap", "session_id", sid, "command", origCommand, "line", <raw>)`.
  No parsing or re-leveling — `wait_killable=...` stays greppable in the
  server log at default level. CLOEXEC gives EOF at exec time, so the
  goroutine is short-lived and self-terminating.

**Shim relay path** (`internal/shim/kernelinstall/install_linux.go`,
`runRelay`):

- No pipe, no goroutine: open
  `<config.GetUserStateDir()>/logs/unixwrap.log` with
  `O_CREATE|O_WRONLY|O_APPEND`, mode 0600 (`MkdirAll` the parent dir). Pass
  the file fd as `ExtraFiles[1]` (fd 4 — free in shim mode; the signal
  socket is deliberately not replicated there) and append
  `AGENTSH_WRAPPER_LOG_FD=4` in `assembleWrapperEnv`. `O_APPEND` writes are
  atomic, so concurrent shim execs interleave at line granularity. Parent
  closes its copy after `cmd.Start()`.

**`agentsh wrap` CLI path** (`internal/cli/wrap_linux.go`,
`platformSetupWrap`):

- Same state-dir log file as the shim path. Appended after the conditional
  signal socket; fd number computed (`3 + position` → 4 or 5) and exported
  in the env it already assembles.

### Error handling

All failures fall open to stderr — logging must never break an exec:

| Failure | Behavior |
|---|---|
| Env var unset | stderr, exactly as today |
| Env var set, fd invalid (fstat fails) | one warning to stderr, then stderr fallback |
| Parent can't create pipe / open log file | parent warns in its own log, omits the env var → wrapper falls back |
| Wrapper hard-fails (`fatalf`) | dual-write: routed destination + stderr |
| Pipe write blocks (server stuck) | accepted risk — a few hundred bytes per exec, far under the 64 KiB pipe buffer; cannot deadlock the handshake |

The wrapped command cannot write to the routed fd: CLOEXEC closes it at exec
and the stripped env var means nothing points there.

### Non-goals

- Log rotation for `unixwrap.log` (a handful of lines per exec; follow-up if
  it ever matters).
- Changing the handshake protocol or `wraphandoff` metadata — the fd is just
  another inherited file, like the notify socket.
- Touching `internal/netmonitor/unix` — the slog call site and its level are
  unchanged.

## Testing

1. **Existing regression tests untouched:**
   `TestInstallFilter_EmitsWaitKillEngagedOnSupportedKernel` and
   `TestInstallFilter_HonorsOperatorOverride` re-exec the test binary
   without `AGENTSH_WRAPPER_LOG_FD`; the slog line still lands on their
   combined output. This was the central constraint from the issue.
2. **Wrapper unit tests** (`cmd/agentsh-unixwrap`): `setupLogging` with a
   valid fd routes both `log` and `slog` output there and sets CLOEXEC;
   invalid fd falls back to stderr; the env var is stripped from the exec
   environment.
3. **Server-path integration test** (`internal/integration`): run a wrapped
   command with machine-readable stderr; assert (a) command stderr contains
   no `seccomp: filter loaded` line, (b) the server log does. Remove any
   existing noise-prefix-stripping workarounds so regressions are caught.
4. **Shim-path test** (`internal/shim/kernelinstall`): relay launches the
   wrapper with a temp state dir; assert the line lands in
   `logs/unixwrap.log` and not on inherited stderr.
5. **Cross-compile:** touched parent files are Linux-gated;
   `GOOS=windows go build ./...` must stay green.

## Acceptance mapping

| Acceptance criterion (issue #415) | How satisfied |
|---|---|
| `agentsh detect --output json` produces clean stderr | Routing in all three spawn paths; CLOEXEC + env strip keep the fd away from the command |
| `wait_killable` diagnostic visible in server log at default level | Server drains the pipe and re-emits lines at Info |
| `TestInstallFilter_*` regression tests still pass | They never run wrapper `main()`; `InstallFilterWithConfig` and its slog call are untouched |
