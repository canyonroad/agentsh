# Docker test probes

## sigurg_probe.go

Sanity check that the kernel's `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`
flag is functionally engaged when used with `unixwrap`. Invoked once per
docker matrix cell (see `.github/workflows/release.yml docker-test`).

This is a **best-effort sanity probe, not a strict regression catcher**.
The deterministic ERESTARTSYS reproducer from PR #225 requires arm64-VM-
under-load conditions; amd64 docker absence-of-hang is too small a
window to make false negatives impossible. The probe catches the gross
failure class where the kernel accepts the flag but the flag does
nothing. The arm64-VM reproducer remains the manual release gate (see
`docs/testing/arm64-sigurg-reproducer.md` when written).

Build and run:

    go build -o sigurg_probe scripts/docker-test/sigurg_probe.go
    unixwrap -- ./sigurg_probe
