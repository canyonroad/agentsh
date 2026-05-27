# Ptrace tracee-memory EIO retry + diagnostics — Design

Issue: #369 ("Gap C"), follow-up to #396. rc3 (#396) fixed the return-register
readback but exposed the dominant remaining failure: race-sensitive `EIO` on
ptrace cross-process tracee-memory access.

## Summary

On exe.dev kernel `6.12.90`, agentsh's cross-process tracee-memory access
intermittently fails with `EIO` — both writes (`write BPF to tracee`,
`inject_seccomp.go:182`, ×15 in one rc3 run) and reads (`handleExecve: cannot
read filename`, `tracer.go:1780`). agentsh's access ladder is `process_vm_*` →
`/proc/<pid>/mem` (`memory.go`); **both rungs `EIO`**, and there is no
`PTRACE_PEEK/POKE` fallback.

The decisive clue (erans's strace): the access **succeeds when serialized under
strace** and fails `EIO` un-straced. That is a timing window, not a capability
gap — both `process_vm_*` and `/proc/<pid>/mem` converge on the kernel's
`access_process_vm`/`get_user_pages` path, which transiently `EIO`s right after a
ptrace stop transition (the `mm` appears momentarily inaccessible, notably around
the execve address-space switch). strace's per-syscall latency closes the window.

This design adds a **bounded retry on `EIO`** around the existing access ladder
(replicating strace's latency cheaply) plus **diagnostic logging** that, when a
retry sequence is exhausted, records why the access failed — without strace
masking it. It is both a hypothesis test (does added latency fix it? → confirms
the transient-window theory) and, if confirmed, the fix.

## Goals

- A transient `EIO` on `process_vm_*`/`/proc/<pid>/mem` is retried (bounded) so a
  recoverable race no longer aborts the prefilter inject / execve read → no
  spurious `exit -1` kill.
- Zero behavior/perf change on healthy kernels: `EIO` does not occur there, so
  the retry path is never entered.
- When retries are exhausted, emit enough context to localize the cause
  (is the tracee actually stopped? is the address mapped? which method? errno?),
  observable without strace.
- A `DEBUG` line on retry **success** (attempt count) so a kill-rate drop plus
  "succeeded after N retries" confirms the transient-window hypothesis.

## Non-Goals

- **No `EFAULT` retry.** `EFAULT` is frequently a legitimate bad-pointer result
  (e.g. `readString` crossing a page boundary at end-of-mapping); retrying it
  would add latency to normal operation. `EIO` is the dominant, clearly-transient
  failure (×15 vs no `EFAULT` in the rc3 kill breakdown). Revisit only if rc4
  shows residual `EFAULT`-driven kills.
- **No `PTRACE_PEEK/POKE` fallback.** It shares the same underlying
  `access_process_vm` path, so it would likely `EIO` too; not worth the
  word-at-a-time complexity until evidence says otherwise.
- **No change to the access ladder order** (`process_vm_*` first, then
  `/proc/<pid>/mem`) or to the inject/stop protocol.
- **No backend-degrade / honesty probe.** If retry proves insufficient (EIO is
  persistent, not transient), that becomes the next decision — out of scope here.

## Background

- Reads: `vmReader.read` (`memory.go:35`) tries `process_vm_readv`, falls back to
  `procMemReader.read` (`/proc/<tid>/mem` pread). Used via `getMemReader` by
  `readBytes`/`readString` (and thus `handleExecve`'s filename read, `tracer.go:1780`).
- Writes: `Tracer.writeBytes` (`memory.go:144`) tries `process_vm_writev`, falls
  back to `/proc/<tid>/mem` pwrite. Used by the BPF-program write
  (`inject_seccomp.go:182`), file/exec/net redirects, etc.
- The tracee is ptrace-stopped during all these accesses (inject runs inside the
  tracer's stop handler). `vmReader` already carries `tid`; `writeBytes` has `tid`.

## Design

### 1. Transient-error classification + retry helper (`memory.go`)

```go
// isTransientMemErr reports whether a tracee-memory access error looks like the
// race-sensitive EIO seen on some kernels (exe.dev 6.12.90, #369) where
// process_vm_*/proc-mem transiently fail right after a stop transition. EFAULT
// is intentionally NOT treated as transient (often a legitimate bad pointer).
func isTransientMemErr(err error) bool {
    return errors.Is(err, unix.EIO)
}

// memRetryMaxAttempts and the escalating backoff bound the retry. Injected
// accesses normally complete in microseconds, so the retry cost is paid only on
// the rare transient EIO. Total worst-case sleep ≈ 1+2+4+8 = 15ms.
const memRetryMaxAttempts = 5

// retryTransientMem runs access (the full process_vm_* → /proc-mem ladder),
// retrying on a transient EIO with escalating backoff. On exhaustion it logs
// diagnostic context (tracee stop state, address mapping) and returns the error.
func retryTransientMem(tid int, addr uint64, op string, access func() error) error {
    var err error
    for attempt := 0; attempt < memRetryMaxAttempts; attempt++ {
        if attempt > 0 {
            time.Sleep(time.Duration(1<<(attempt-1)) * time.Millisecond) // 1,2,4,8ms
        }
        err = access()
        if err == nil {
            if attempt > 0 {
                slog.Debug("ptrace mem access recovered after retry",
                    "tid", tid, "addr", fmt.Sprintf("0x%x", addr), "op", op, "attempts", attempt+1)
            }
            return nil
        }
        if !isTransientMemErr(err) {
            return err
        }
    }
    logMemErrContext(tid, addr, op, err)
    return err
}
```

### 2. Diagnostic context on exhaustion (`memory.go`)

```go
// logMemErrContext records, at WARN, why a tracee-memory access kept failing:
// the tracee's scheduler state char from /proc/<tid>/stat (expected 't'/'T' when
// ptrace-stopped) and whether addr falls inside any /proc/<tid>/maps region.
// Best-effort; never fatal. (#369)
func logMemErrContext(tid int, addr uint64, op string, accessErr error) {
    state := procStateChar(tid)            // "" if unreadable
    mapped := addrInMaps(tid, addr)        // bool; false if maps unreadable/absent
    slog.Warn("ptrace mem access failed after retries",
        "tid", tid, "addr", fmt.Sprintf("0x%x", addr), "op", op,
        "error", accessErr, "tracee_state", state, "addr_mapped", mapped,
        "attempts", memRetryMaxAttempts)
}
```

- `procStateChar(tid)` reads `/proc/<tid>/stat`, parses the state char *after the
  last `)`* (comm may contain spaces/parens). Returns "" on any error.
- `addrInMaps(tid, addr)` scans `/proc/<tid>/maps` for a `start-end` range
  containing `addr`. Returns false on any error. Bounded line scan.

### 3. Wire retry into both ladders (`memory.go`)

- `writeBytes`: rename the current body to `writeBytesOnce(tid, addr, buf)` and
  make `writeBytes` call `retryTransientMem(tid, addr, "write", func() error { return t.writeBytesOnce(tid, addr, buf) })`.
- `vmReader.read`: rename the current body to `readOnce`; `read` wraps it with
  `retryTransientMem(r.tid, addr, "read", func() error { return r.readOnce(addr, buf) })`.

The retry wraps the **whole ladder** (so a retry re-tries `process_vm_*` and then
`/proc/<pid>/mem`), matching the observation that both rungs fail together during
the transient window.

## Decisions

- **Retry, not a new access method.** The "works under strace" evidence points at
  a latency-closable timing window; bounded retry is the minimal faithful
  replication. `PEEK/POKE` shares the failing kernel path and is not added.
- **`EIO` only** (see Non-Goals) — surgical, avoids penalizing legitimate `EFAULT`.
- **Retry inside `memory.go`** so every caller (inject writes + `handleExecve`
  read + redirects) is covered uniformly with one change.
- **Diagnostics are best-effort and only on exhaustion** — they cost nothing on
  success and are not masked by strace (internal logging), giving a clean answer
  if retry turns out insufficient.

## Error handling / safety

- On a healthy kernel `EIO` never occurs, so the retry loop runs exactly once and
  returns immediately — no added latency, no new code path exercised.
- Non-`EIO` errors return immediately (including the existing `/proc/mem`
  fallback's error), preserving current semantics.
- `logMemErrContext` helpers swallow their own errors; a diagnostic read failure
  never changes the returned access error.

## Testing

The 6.12.90 `EIO` is not reproducible on CI, but the **retry logic is fully
unit-testable** with a fake access func (deterministic, no kernel):

`internal/ptrace/memory_retry_test.go` (`//go:build linux`):
- `retryTransientMem` returns success when `access` fails `EIO` N(<5) times then
  succeeds; asserts the success-after-retry path (and that it retried, e.g. via a
  call counter).
- `retryTransientMem` returns the error after exhausting attempts when `access`
  always fails `EIO`.
- A **non-transient** error (e.g. `EFAULT`/`EPERM`) returns immediately with no
  retry (call counter == 1).
- `isTransientMemErr`: true for `EIO` (incl. wrapped via `fmt.Errorf("...: %w")`),
  false for `EFAULT`/`nil`/others.
- `procStateChar` parser: feed a sample `/proc/stat`-style line with parens/space
  in comm; assert the correct state char is extracted (parse the helper on a
  string to keep it kernel-independent — factor the parse into a pure function).

Plus: existing `internal/ptrace` suites stay green; `go test ./...`;
`GOOS=windows go build ./...` (changed file is `//go:build linux`).

End-to-end (`EIO` actually recovered → kill rate ~100%) is verified by erans on a
real `6.12.90` VM via v0.20.3-rc4.

## Affected files

- `internal/ptrace/memory.go` — add `isTransientMemErr`, `retryTransientMem`,
  `logMemErrContext` + `procStateChar`/`addrInMaps` (and a pure parse helper);
  split `writeBytes`/`vmReader.read` into `*Once` + retry wrapper. Imports:
  `errors`, `log/slog`, `time`, `strings`/`bufio` for the diag helpers.
- `internal/ptrace/memory_retry_test.go` — new unit tests.
- Inject/stop protocol, access-ladder order, darwin/windows — unchanged.
