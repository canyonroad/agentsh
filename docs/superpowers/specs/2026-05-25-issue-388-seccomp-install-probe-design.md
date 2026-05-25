# Honest seccomp installability in `detect` Design

Issue: #388

## Summary

`agentsh detect` reports `seccomp-execve ✓` and `seccomp_user_notify ✓` (Command Control 25/25) from **read-only** capability probes (`seccomp(SECCOMP_GET_ACTION_AVAIL)`, `seccomp(SECCOMP_GET_NOTIF_SIZES)`) that never install a filter. In environments where the actual user-notify filter install fails — e.g. Daytona sandboxes, where `SECCOMP_FILTER_FLAG_NEW_LISTENER` returns **EBUSY** — `detect` still reports the capability as available, while runtime `agentsh-unixwrap` dies with `seccomp: filter Load failed`. The verdict means *"the kernel knows this feature"*, not *"agentsh can install its filter here."* So `detect` and the protection score are a **false positive** for the enforcement that actually matters.

This design adds a **behavioral install-probe**: a throwaway re-exec child that attempts the exact `NEW_LISTENER` install the runtime uses (`loadRawFilter`) and reports success or the failing errno. `detect`'s `seccomp-execve` / `seccomp_user_notify` verdicts and the Command Control score derive from **that** ("installable here"), while the existing read-only probe is retained as a distinct "kernel-supported" signal surfaced in the detail text.

## Goals

- `detect` reports `seccomp-execve` / `seccomp-notify` / `seccomp_user_notify` as available only when a real `NEW_LISTENER` filter install succeeds in this environment.
- The Command Control protection score reflects installability, so an environment like Daytona (EBUSY) drops below 25/25 instead of falsely reporting full coverage.
- When the kernel supports user-notify but the install fails here, `detect` surfaces **both** signals and the failing errno, e.g. `seccomp-execve ✗ — kernel supports user-notify, but NEW_LISTENER install failed here: EBUSY (errno 16)`.
- The probe tests **exactly** what the runtime does (`loadRawFilter` → `prctl(NO_NEW_PRIVS)` + `seccomp(SET_MODE_FILTER, NEW_LISTENER)`), so the verdict can't diverge from runtime behavior.
- Regression-safe: on environments where install succeeds (normal kernels), the verdict and score are unchanged (still `✓`, 25/25).

## Non-Goals

- **No change to runtime or server-startup gating.** This fixes the diagnostic's honesty. The runtime already surfaces the real EBUSY at install time (`agentsh-unixwrap` fails loudly). Aligning startup capability gating with the install-probe is a possible separate follow-up.
- The probe reuses the existing `buildProbeFilterBytes()` + `loadRawFilter` rather than hand-rolling a separate filter/install — fidelity to the real runtime install is the point, and reuse avoids divergence.
- No new behavioral KILL-bug logic; that is the separate `wait_killable` probe (#369).
- No change to the read-only probes themselves; they remain as the "kernel-supported" signal.

## Background

- Read-only probes: `probeSeccompBasic()` (`SECCOMP_GET_ACTION_AVAIL`) and `probeSeccompUserNotify()` (`SECCOMP_GET_NOTIF_SIZES`) in `internal/capabilities/check_seccomp_linux.go` (`//go:build linux`, no cgo). `realCheckSeccompUserNotify()` (`check.go:38`) wraps the latter; `checkSeccompUserNotify` is a swappable package var (test seam).
- `internal/capabilities/detect_linux.go` derives `seccomp-execve` (L93), `seccomp-notify` (L86), and the `seccomp_user_notify` map entry (L220) all from `caps.Seccomp` — i.e. from the read-only probe.
- Real install: `loadRawFilter(prog []byte, withWaitKill bool) (int, error)` in `internal/netmonitor/unix/seccomp_load_linux.go` (`//go:build linux && cgo`): `runtime.LockOSThread()` → `prctl(PR_SET_NO_NEW_PRIVS)` → `seccomp(SET_MODE_FILTER, NEW_LISTENER[|WAIT_KILLABLE_RECV])`. The `NEW_LISTENER` flag is what EBUSYs on Daytona.
- Proven re-exec child harness: `internal/netmonitor/unix/wait_killable_probe_runner_linux.go` (#369) already re-execs `os.Executable()` with a two-factor gate (argv sentinel `--agentsh-internal-...-v1` + random env token, validated in `init()`), and its child calls `loadRawFilter`. `internal/api` imports `netmonitor/unix` and `cmd/agentsh` imports `internal/api`, so the child `init()` handler is linked into the `agentsh` binary (and thus runs when `agentsh detect` re-execs itself). `netmonitor/unix` ships non-cgo stubs (`seccomp_stub.go`, `wait_killable_probe_stub.go`), and does **not** import `internal/capabilities` (no cycle).

## Design

### 1. Install-probe in `internal/netmonitor/unix`

A new probe modeled on the wait_killable harness but stripped to a single install attempt.

**Contract constants** (own two-factor gate, distinct from wait_killable):
- argv sentinel `--agentsh-internal-seccomp-install-probe-child-v1`
- env token var `AGENTSH_SECCOMP_INSTALL_PROBE_CHILD` (length ≥ 16)
- exit codes: `0` = installed OK; a small fixed code per errno class (EBUSY, EPERM, EINVAL, ENOSYS, other) so the parent classifies without parsing stderr (stderr still captured, bounded, for the detail string).

**Child (`linux && cgo`):** an `init()` branch (added to the package's probe-child detection) that, when the install-probe sentinel+token are present:
1. builds the filter via the existing `buildProbeFilterBytes()` (the proven probe filter: `ActAllow` default + `ActNotify` on a fixed syscall set) — reused for fidelity to what the runtime installs;
2. calls `loadRawFilter(prog, false)` (plain `NEW_LISTENER`, matching the issue's exact failing case);
3. on success: close the returned fd, `os.Exit(0)`; on error: print the errno to stderr and `os.Exit(<errno-class code>)`.

The child never services notifications and never execs. It is safe from the wait_killable child's "trap-on-exit" hazard precisely because the filter default is `ActAllow` and the child's own post-install syscalls (`close`, `write` to stderr, `exit_group`) are **not** in the notify set — so no notification is ever raised and nothing must service the fd.

It never services notifications and never execs — it only answers "did the install syscall succeed?"

**Parent (`linux && cgo`, paired with the child handler):**
```go
type InstallProbeResult struct {
    Installable bool
    Errno       syscall.Errno // 0 if installable
    Detail      string        // human-readable, e.g. "EBUSY (errno 16)" or child stderr
}
func ProbeSeccompInstall() InstallProbeResult
```
re-execs `os.Executable()` with the sentinel argv + token env, captures exit code + bounded stderr, maps to `InstallProbeResult`. Result cached per-process via `sync.Once` (detect may query repeatedly). A re-exec / spawn failure is treated as `Installable:false` with a descriptive `Detail` (fail-safe: don't claim installable when we couldn't test). It lives in the cgo file because the re-exec is only meaningful when the cgo child handler is compiled into the binary.

**Stub (`!cgo` / non-linux):** `ProbeSeccompInstall()` returns `{Installable:false, Detail:"seccomp install probe unavailable (no cgo / unsupported OS)"}` — no re-exec (there is no child handler to answer it).

### 2. capabilities + detect wiring

- Add a swappable check var `checkSeccompInstall = realCheckSeccompInstall` (test seam, mirroring `checkSeccompUserNotify`) that calls `unix.ProbeSeccompInstall()` and yields a new `caps` field, `SeccompInstallable bool` (+ a detail string for the errno).
- Keep `caps.Seccomp` (read-only) as the **kernel-supported** signal.
- `detect_linux.go`: `seccomp-execve`, `seccomp-notify`, and `seccomp_user_notify` **Available ← `caps.SeccompInstallable`**. The Command Control score weight now counts installability.
- Detail text: when `caps.Seccomp && !caps.SeccompInstallable`, set the entry `Detail` to `kernel supports user-notify, but NEW_LISTENER install failed here: <errno>`; when both true, `✓` with empty/positive detail; when `!caps.Seccomp`, unchanged (kernel doesn't support it).

### Why not other approaches

- **Extend the wait_killable harness:** conflates the KILL-bug behavioral test (5 iterations, notify servicing, syscall storm) with a simple "can we install" check; heavier and entangles two concerns.
- **In-process locked-thread probe:** installing `NEW_LISTENER` + `NO_NEW_PRIVS` on a `runtime.LockOSThread` thread permanently poisons that M (a seccomp'd/no-new-privs thread can't be safely returned to the Go runtime). A throwaway child is the clean isolation boundary.
- **Self-contained probe in capabilities (hand-rolled install):** would duplicate the install syscall/flags and risk diverging from `loadRawFilter` — but fidelity to the real install is the entire point of the fix. Reusing `loadRawFilter` (child-side, in the cgo binary) guarantees the probe tests what runtime does.

## Error handling

The probe is fail-safe: any failure to *run* the probe (re-exec error, child crash, timeout) yields `Installable:false` with a `Detail` explaining why — never a false `✓`. Errno classification (EBUSY/EPERM/EINVAL/ENOSYS/other) drives the detail string; an unrecognized non-zero exit maps to `Installable:false` with the captured child stderr. No new error types surface to callers; `detect` renders the `Detail`.

## Testing

`internal/netmonitor/unix` (`linux && cgo`):
- Child contract: invoking the binary with the install-probe sentinel+token exits `0` and the real `loadRawFilter` install succeeds on a normal CI kernel (skip if the CI kernel itself can't install, to avoid flakiness — gate on a quick precheck).
- Parent classifier: a table mapping injected exit codes + stderr → `InstallProbeResult` (`0`→installable; each errno code→correct `Errno`/`Detail`; spawn failure→not installable). Use an injectable exec seam so the classifier is tested without a real child.

`internal/capabilities`:
- With `checkSeccompInstall` stubbed to `Installable:false` while `checkSeccompUserNotify` reports available (kernel-supported), assert: `seccomp-execve`/`seccomp_user_notify` verdicts are `✗`, the Command Control score drops accordingly, and the detail string names both signals + the errno.
- With both stubbed available, assert verdicts `✓` and score unchanged (regression guard).

Confirm existing `internal/capabilities`, `internal/netmonitor/unix`, and `internal/cli` suites stay green, and `GOOS=windows go build ./...` succeeds (the parent/stub split must compile cgo and non-cgo).

## Affected files

- `internal/netmonitor/unix/seccomp_install_probe_linux.go` (new, `linux && cgo`) — child `init()` handler + parent `ProbeSeccompInstall`.
- `internal/netmonitor/unix/seccomp_install_probe_stub.go` (new, `!cgo` / non-linux) — stub `ProbeSeccompInstall`.
- `internal/netmonitor/unix/*probe*_test.go` (new) — child contract + parent classifier tests.
- `internal/capabilities/check.go` / `check_seccomp_linux.go` — `checkSeccompInstall` seam + `SeccompInstallable` field.
- `internal/capabilities/detect_linux.go` — derive the three verdicts + score from `SeccompInstallable`; dual-signal detail text.
- `internal/capabilities/*_test.go` — detect-level verdict/score/detail tests.
