# FUSE Extra Ops Test Policy Path Design

## Context

Issue #328 reports that `TestFUSE_InterceptsExtraOps` grants policy access to
`/workspace` and `/workspace/**`, but FUSE policy evaluation in
`checkWithExist` resolves virtual paths to the real backing workspace path before
calling `CheckFile`. On hosts where the real FUSE mount runs, this can deny the
operation because the resolved tempdir path does not match the virtual
`/workspace` rule. On hosts where FUSE mounting skips, the mismatch is easy to
miss.

`TestFUSE_TruncateUnderSoftDelete` already documents the same path-resolution
behavior and uses a policy shape that avoids testing the wrong failure mode.

## Goal

Make the extra-ops FUSE test validate intercepted operations, not a policy path
mismatch. Also fix any adjacent FUSE test with the same virtual-only allow rule
when that test routes through `checkWithExist`.

## Design

Add a small FUSE-test policy helper that allows the real backing workspace path:

- exact backing tempdir path
- recursive backing tempdir subtree

Use that helper in `TestFUSE_InterceptsExtraOps` so create/stat/list/symlink and
chmod operations are not denied by the resolved path. Use the same helper in the
neighboring cross-mount FUSE test, which has the same `/workspace`-only policy
shape and reaches policy checks through create/rename handling.

Add a non-FUSE regression test for the helper policy. It should construct a
backing tempdir, compile the helper policy, and assert that `CheckFile` allows a
resolved path under that backing directory. This keeps coverage meaningful even
on developer or CI hosts where FUSE mount setup skips because `/dev/fuse` or
`allow_other` is unavailable.

## Non-Goals

- No production behavior changes.
- No change to `checkWithExist` path resolution semantics.
- No broad refactor of all FUSE tests beyond the exact same nearby mismatch.
- No attempt to change host FUSE setup or `allow_other` behavior.

## Testing

Run a focused FUSE test selection that includes the non-FUSE helper regression,
the extra-ops test, the cross-mount test, and the existing truncate regression.
The real mount tests may skip locally when FUSE mounting is unavailable.

Run the full Go suite and the Windows compile gate:

- `go test ./...`
- `GOOS=windows go build ./...`
- `git diff --check`
