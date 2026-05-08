# YAML Mitigation Sets Design

## Problem

The Dirty Frag work adds the right low-level primitive for advisory response: protocol-aware `socket_rules` that can block narrow `socket(2)` and `socketpair(2)` tuples. The current `hardening_profiles` implementation does not scale because each advisory becomes another hardcoded Go `switch` case.

agentsh needs a generic way to ship and load advisory mitigations while still letting users write explicit low-level rules. The mitigation mechanism should avoid parsing every shipped advisory on startup and should not force users to overblock broad resources such as all `AF_NETLINK` when a narrow protocol rule is enough.

## Goals

- Represent advisory mitigations as YAML files that expand into existing generic seccomp config primitives.
- Load only the requested mitigation YAML files.
- Keep low-level `socket_rules` as the enforcement primitive for Dirty Frag and similar socket-family/protocol mitigations.
- Support built-in mitigations shipped with agentsh as embedded YAML files and optional external mitigation directories for emergency or private rules.
- Treat external mitigation files as trusted local admin config with guardrails.
- Fail closed when a requested mitigation cannot be loaded or validated.
- Preserve the conservative Dirty Frag behavior: block `AF_RXRPC` and `AF_NETLINK` protocol `NETLINK_XFRM`, not all `AF_NETLINK`.

## Non-Goals

- No remote mitigation feed or automatic network update mechanism.
- No signature enforcement in the first version.
- No new seccomp enforcement behavior beyond expanding YAML into the same typed rules users can already configure.
- No bulk loading or scanning of every mitigation file to discover available advisories at runtime.

## User Configuration

Replace the advisory-specific `hardening_profiles` field with generic mitigation sets:

```yaml
sandbox:
  seccomp:
    mitigation_sets:
      - dirtyfrag-conservative

    mitigation_dirs:
      - /etc/agentsh/mitigations
```

`mitigation_sets` contains requested mitigation IDs. agentsh resolves each ID to one YAML file and loads only those files.

`mitigation_dirs` is optional. When omitted, only built-in mitigations are available. External files are trusted local admin config, but they must pass permission checks, schema validation, and semantic rule validation.

For compatibility inside the current branch, `hardening_profiles` can remain as a deprecated alias for `mitigation_sets`. Because this branch has not shipped, the preferred implementation is to rename the public docs and examples to `mitigation_sets` before merge.

## Mitigation YAML Format

Each mitigation file describes one mitigation set:

```yaml
version: 1
id: dirtyfrag-conservative
title: Dirty Frag conservative mitigation
references:
  - https://www.openwall.com/lists/oss-security/2026/05/07/8

seccomp:
  socket_rules:
    - name: dirtyfrag-conservative-rxrpc
      family: AF_RXRPC
      action: log_and_kill
    - name: dirtyfrag-conservative-xfrm
      family: AF_NETLINK
      protocol: NETLINK_XFRM
      action: log_and_kill
```

The first version supports:

- `version`: required, currently `1`.
- `id`: required, must match the requested mitigation ID and the filename stem.
- `title`: optional human-readable description.
- `references`: optional list of advisory or vendor URLs.
- `seccomp.socket_rules`: optional list using the same schema as `sandbox.seccomp.socket_rules`.
- `seccomp.blocked_socket_families`: optional list using the same schema as `sandbox.seccomp.blocked_socket_families`.
- `seccomp.syscalls.block` and `seccomp.syscalls.on_block`: optional syscall blocking rules using the existing syscall block schema.

Unknown YAML fields are errors. Empty mitigation files are errors because they create a false sense of protection.

The existing syscall block primitive has one `on_block` action for the whole effective syscall block list. A mitigation that adds `seccomp.syscalls.block` can omit `on_block` to use the effective `sandbox.seccomp.syscalls.on_block`, or can set `on_block` only when it matches that effective action. A mismatch is a config error. Per-syscall actions are out of scope for v1.

## File Resolution

Mitigation IDs must match:

```text
^[a-z0-9][a-z0-9._-]*$
```

This keeps lookup path-safe and avoids directory traversal. A requested ID maps to `<id>.yaml`, with `<id>.yml` accepted only as a fallback for external directories.

Lookup order:

1. Built-in mitigation file embedded in the agentsh binary with `go:embed`.
2. External `mitigation_dirs`, in configured order, only when no built-in with that ID exists.

External files do not override built-ins by default. If a requested ID exists as both a built-in file and an external file, v1 rejects the config as an ambiguous duplicate. A later explicit override option can be added if operators need to replace a built-in mitigation.

The built-in YAML files live in the repo, for example under `internal/config/mitigations/*.yaml`, and are embedded into the binary. The loader does not parse every embedded YAML file during normal config load. It constructs candidate filenames from each requested ID and reads only those requested files from the embedded filesystem and configured external directories. External lookup uses `stat`/read only for the requested candidate filenames; it does not enumerate the full directory.

## Validation

The resolver validates in layers:

1. Validate the requested mitigation ID before constructing paths.
2. Locate exactly one mitigation file.
3. For external files, reject world-writable directories and world-writable files.
4. Decode YAML with strict field checking.
5. Require `version: 1` and matching `id`.
6. Expand the mitigation into existing config structs.
7. Run the same semantic validators used for user-authored `socket_rules`, `blocked_socket_families`, and syscall blocks.
8. Reject duplicate final rule names across user config and all selected mitigations.

If any selected mitigation fails validation, config load fails. agentsh should not silently continue without a requested security mitigation.

## Merge Semantics

User-authored rules and selected mitigations are merged into one effective seccomp configuration:

1. User-authored `socket_rules`, `blocked_socket_families`, and syscall block entries remain supported.
2. Selected mitigation rules are appended in the order listed in `mitigation_sets`.
3. Final duplicate rule names are rejected.
4. For seccomp install ordering, narrow `socket_rules` continue to install before broad socket family rules.

There is no implicit action override in v1. Mitigation files choose their own actions for primitives that already carry per-rule actions, such as `socket_rules` and `blocked_socket_families`. Syscall blocks use the single existing effective `syscalls.on_block` action. Users who need a different mitigation action can copy the YAML into an external directory under a new ID and select that ID.

## Observability

When agentsh loads a mitigation file, it logs:

- mitigation ID
- source: built-in or external path
- SHA-256 checksum of the YAML bytes
- expanded rule counts by rule type

Audit events emitted by enforcement keep the existing rule-level fields such as `rule_name`, `family`, `protocol`, and `action`. For mitigation-derived rules, the rule name should be stable and advisory-specific, such as `dirtyfrag-conservative-xfrm`.

## Security Model

External mitigation YAMLs are trusted local admin config. The first version does not require signatures because operators who can write these files can already change agentsh's local policy. The guardrails are strict schema validation, existing semantic validation, permission checks, explicit opt-in directories, and fail-closed loading.

Signature enforcement can be added later as a separate trust policy:

```yaml
sandbox:
  seccomp:
    mitigation_trust:
      require_signatures: true
      trusted_keys:
        - /etc/agentsh/mitigation-pubkey.pem
```

The v1 schema leaves room for that extension without baking signature logic into mitigation expansion.

## Dirty Frag Built-In

The current hardcoded `dirtyfrag-conservative` profile becomes a built-in YAML mitigation file:

```yaml
version: 1
id: dirtyfrag-conservative
title: Dirty Frag conservative mitigation
references:
  - https://www.openwall.com/lists/oss-security/2026/05/07/8

seccomp:
  socket_rules:
    - name: dirtyfrag-conservative-rxrpc
      family: AF_RXRPC
      action: log_and_kill
    - name: dirtyfrag-conservative-xfrm
      family: AF_NETLINK
      protocol: NETLINK_XFRM
      action: log_and_kill
```

This preserves the existing conservative behavior and avoids blocking all `AF_NETLINK`.

## Testing

Tests should cover:

- Resolving a built-in mitigation by ID without loading unrelated mitigation files.
- Resolving an external mitigation by ID from `mitigation_dirs`.
- Rejecting invalid IDs and traversal attempts.
- Rejecting unknown YAML fields.
- Rejecting mismatched file stem and YAML `id`.
- Rejecting duplicate final rule names.
- Rejecting world-writable external directories and files on Unix.
- Expanding Dirty Frag YAML to the exact two socket rules used by the current implementation.
- Preserving existing seccomp and ptrace Dirty Frag enforcement tests after the resolver changes.
- Windows compilation, with Unix permission checks behind platform-specific files or no-op behavior where not applicable.

## Migration

Because `hardening_profiles` was introduced on the current feature branch and has not shipped, the cleanest path is to rename it to `mitigation_sets` before merge. If compatibility is desired anyway, `hardening_profiles` can remain as a deprecated alias that feeds the same resolver and emits a warning.

Docs and `config.yml` should stop presenting `hardening_profiles` as the preferred interface.
