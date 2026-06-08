# FUSE per-path soft-delete (#417)

**Date:** 2026-06-07
**Issue:** #417 — FUSE soft-delete not active for shimmed `rm`; `unlink` not captured, `agentsh trash list` empty.
**Status:** Design approved, pending spec review.

## Problem

An operator expresses soft-delete as a per-path policy rule:

```yaml
file_rules:
  - name: soft-delete-workspace
    path: /workspace/**
    decision: soft_delete
```

With `/workspace` FUSE-mounted, `rm /workspace/<file>` deletes the file outright and
`agentsh trash list` stays empty. Reads, writes, and creates through FUSE work
normally — only delete fails to divert.

## Root cause

The FUSE file-operation handlers ignore the per-path `soft_delete` policy decision.
FUSE soft-delete is gated **solely** on the global `sandbox.fuse.audit.mode == "soft_delete"`
setting, never on the policy decision.

Evidence:

1. `node.Unlink` (`internal/fsmonitor/fuse.go:149`) computes `dec := n.check(...)` but only
   branches on `dec.EffectiveDecision == DecisionDeny`. It never inspects
   `dec.PolicyDecision == soft_delete`. Same for `Rmdir` (`:164`) and the cross-mount
   `Rename`-as-delete branch (`:217`).
2. The policy engine maps a `decision: soft_delete` rule to
   `PolicyDecision=soft_delete, EffectiveDecision=allow` (`internal/policy/engine.go:1210`).
   So at the FUSE layer `EffectiveDecision` is `allow`; the handler proceeds to
   `applyAuditPolicy`.
3. `applyAuditPolicy` (`internal/fsmonitor/policy.go:83`) only diverts when
   `Config.Mode == "soft_delete"`. The default mode is `"monitor"`
   (`internal/config/config.go:1629`), so it calls `run()` → a real `unlink` → file gone,
   call succeeds, trash empty.
4. The ptrace path does this correctly: `internal/api/ptrace_handlers.go:210` explicitly
   bridges `decision.PolicyDecision == DecisionSoftDelete` → `"soft-delete"` action, with a
   comment noting that checking `EffectiveDecision` alone would miss it. **FUSE is missing
   this exact bridge**, so in a hybrid deployment the same policy rule behaves differently
   depending on which layer (ptrace vs FUSE) handles the syscall.

Compounding papercut: the reporter configured `fuse.session.mode` / `fuse.session.trash_path`,
which are not real keys (the real keys are `sandbox.fuse.audit.mode` / `.trash_path`). Config
is parsed with non-strict `yaml.Unmarshal` (`internal/config/config.go:1392`), so unknown keys
are silently dropped — the misconfiguration produced no error.

## Approach

Make the FUSE layer honor the per-path `soft_delete` policy decision, mirroring ptrace.

Today FUSE conflates two concepts behind one switch:

- **Trash availability** — is there a trash dir and a divert function?
- **Default audit mode** — `monitor` / `soft_block` / `soft_delete` / `strict`.

Both are currently driven by the single `sandbox.fuse.audit.mode == "soft_delete"` check.
Decouple them: always make trash *available* to FUSE when soft-delete is possible, keep the
global mode as configured (default `monitor`), and let a per-path
`PolicyDecision == soft_delete` upgrade a single operation to a divert.

Per destructive op (`unlink`, `rmdir`, cross-mount rename-as-delete):

```
effectiveMode = (dec.PolicyDecision == soft_delete) ? "soft_delete" : globalAuditMode
```

- global `soft_delete` → all destructive ops divert (unchanged from today)
- per-path rule only → just matching paths divert
- neither → plain `monitor` (unchanged)

Alternatives considered and rejected:

- **Auto-enable the global mode whenever any `soft_delete` rule exists.** Simpler wiring but
  coarse: one rule on a narrow subtree would silently start trashing *every* delete in the
  mount. Loses per-path granularity and keeps FUSE keying off a different mechanism than
  ptrace.
- **Docs/validation only.** Does not make the per-path rule work; the issue is a behavioral
  bug, not just a documentation gap. (The validation half of this is kept as a secondary
  improvement — see below.)

## Detailed design

### 1. Config / trash wiring (`internal/api/core.go`, `internal/platform`)

- Add an explicit global-mode field to `platform.FSConfig` (e.g. `AuditMode string`) so the
  FUSE layer receives the *configured* default instead of `filesystem.go` hardcoding
  `"soft_delete"`.
- In `core.go`, populate `FSConfig.TrashConfig` + `NotifySoftDelete` when trash is usable:
  global mode is `soft_delete` **or** the session's policy contains at least one
  `soft_delete` file rule. Trash dir resolves from the existing
  `Sandbox.FUSE.Audit.TrashPath` (default `.agentsh_trash`), the same source ptrace uses via
  `resolveTrashPath`. Gating on "policy has a soft_delete rule" avoids paying trash setup for
  sessions that can never soft-delete.
  - The engine has no such predicate today. Add `HasSoftDeleteFileRule() bool` on
    `*policy.Engine`, iterating `e.compiledFileRules` for any rule whose decision is
    `types.DecisionSoftDelete`.
- In `internal/platform/linux/filesystem.go` `Mount`, set `hooks.FUSEAudit.Config.Mode` from
  the real configured mode (`FSConfig.AuditMode`), not a hardcoded `"soft_delete"`. Keep
  `TrashPath`/`HashLimitBytes`/`NotifySoftDelete` wiring as today.

### 2. FUSE handlers + `applyAuditPolicy` (`internal/fsmonitor`)

- Change `applyAuditPolicy` to take an explicit resolved `opMode string` argument instead of
  reading `hooks.Config.Mode` internally. Strict-on-failure semantics continue to come from
  `hooks.Config` (`StrictOnAuditFailure` / global `strict`).
- `node.Unlink`, `node.Rmdir`, and the cross-mount `Rename`-as-delete branch compute
  `effectiveMode` from `dec.PolicyDecision` (falling back to the global configured mode) and
  pass it to `applyAuditPolicy`. The `file_delete` / `dir_delete` / `file_rename` events are
  unchanged in shape.
- A small helper resolves the per-op mode:
  `resolveOpMode(dec, globalMode) string` returning `"soft_delete"` when
  `dec.PolicyDecision == types.DecisionSoftDelete`, else `globalMode`.

### 3. Silent-misconfig guard (secondary)

Add a startup warning when the `sandbox.fuse` config subtree contains unknown keys (e.g.
`fuse.session.mode`). Implement by strict-decoding **only** the `sandbox.fuse` subtree
(re-marshal that node and decode with `KnownFields(true)`, or equivalent) and logging unknown
fields. Do **not** flip the whole config loader to strict — too broad and risky for existing
deployments. Warning only; never fails startup.

## Testing

- **fsmonitor unit tests** (no Docker): construct a `node` with global mode `monitor` and a
  stub policy returning `PolicyDecision=soft_delete` for the target path; assert `Unlink`
  moves the file into the trash dir, returns `0`, and fires `NotifySoftDelete`. Same for
  `Rmdir` and the cross-mount rename-as-delete branch. Negative case: `monitor` + `allow`
  decision → real delete (unchanged).
- **applyAuditPolicy unit test**: explicit `opMode == "soft_delete"` diverts even when
  `Config.Mode == "monitor"`; strict-on-failure still sourced from `Config`.
- **Regression**: existing global `audit.mode: soft_delete` integration test
  (`internal/integration/agentsh_soft_delete_test.go`) still passes.
- **New integration test**: mirror the existing soft-delete integration test but drive it with
  a per-path `decision: soft_delete` rule and the global mode left at default — reproduces
  #417 and proves the fix.
- **Config-warning test**: an unknown `sandbox.fuse.*` key produces the warning and does not
  fail load.

## Out of scope

- The ptrace soft-delete path (already correct).
- Cross-device (`EXDEV`) handling for the ptrace `renameat2` divert — separate concern.
- TTL/quota/purge behavior of the trash store.
- macOS / Windows soft-delete parity.

## Cross-compilation

`fsmonitor/fuse.go` is `//go:build !windows`. The config-warning change lives in
`internal/config` (cross-platform). Verify `GOOS=windows go build ./...` still passes.
