# Dirty Frag Conservative Socket Rules Design

## Summary

Add a conservative Dirty Frag mitigation to agentsh without broadly blocking common Linux facilities. The design introduces generic seccomp socket tuple rules that can match `socket(2)` by family, optional type, and optional protocol. A new opt-in hardening profile, `dirtyfrag-conservative`, expands to two socket rules:

- block `socket(AF_RXRPC, ...)`
- block `socket(AF_NETLINK, ..., NETLINK_XFRM)`

This avoids the current coarse workaround of blocking all `AF_NETLINK`, which breaks normal netlink users such as `ip`, `ss`, system and network introspection, and related tooling.

## Goals

- Provide a low-breakage agentsh mitigation for the Dirty Frag advisory while kernel patches are unavailable.
- Keep current defaults unchanged.
- Preserve normal `AF_NETLINK` use except `NETLINK_XFRM`.
- Add named constant support for `AF_RXRPC` and `NETLINK_XFRM` so operators do not need numeric values.
- Make the generic mechanism useful for future kernel attack-surface reductions.
- Design ptrace parity explicitly, even if the first implementation lands seccomp support before ptrace support.

## Non-Goals

- Do not implement an aggressive Dirty Frag profile in the first patch.
- Do not block all keyring syscalls, namespace syscalls, or splice-family syscalls in the conservative profile.
- Do not modify host kernel module configuration.
- Do not change existing `blocked_socket_families` behavior or defaults.

## Configuration

Add two fields under `sandbox.seccomp`:

```yaml
sandbox:
  seccomp:
    socket_rules:
      - name: dirtyfrag-rxrpc
        family: AF_RXRPC
        action: log_and_kill

      - name: dirtyfrag-xfrm
        family: AF_NETLINK
        protocol: NETLINK_XFRM
        action: log_and_kill

    hardening_profiles:
      - dirtyfrag-conservative
```

`socket_rules` is the generic primitive. Fields:

- `name`: required stable rule name used in diagnostics and audit.
- `family`: required `AF_*` name or numeric value.
- `type`: optional socket type name or numeric value. If omitted, any type matches.
- `protocol`: optional protocol name or numeric value. If omitted, any protocol matches.
- `action`: one of `errno`, `kill`, `log`, `log_and_kill`; default `errno`.

`hardening_profiles` is a list of named bundles. The first profile is `dirtyfrag-conservative`, which appends generated socket rules equivalent to:

```yaml
socket_rules:
  - name: dirtyfrag-conservative-rxrpc
    family: AF_RXRPC
    action: log_and_kill
  - name: dirtyfrag-conservative-xfrm
    family: AF_NETLINK
    protocol: NETLINK_XFRM
    action: log_and_kill
```

Profile expansion appends rules after explicit `socket_rules`. Duplicate names are rejected after expansion.

## Constant Resolution

Extend the existing family name table to include:

- `AF_RXRPC` = 33

Add protocol name resolution for at least:

- `NETLINK_ROUTE` = 0
- `NETLINK_USERSOCK` = 2
- `NETLINK_FIREWALL` = 3
- `NETLINK_SOCK_DIAG` = 4
- `NETLINK_NFLOG` = 5
- `NETLINK_XFRM` = 6
- `NETLINK_SELINUX` = 7
- `NETLINK_ISCSI` = 8
- `NETLINK_AUDIT` = 9
- `NETLINK_FIB_LOOKUP` = 10
- `NETLINK_CONNECTOR` = 11
- `NETLINK_NETFILTER` = 12
- `NETLINK_KOBJECT_UEVENT` = 15
- `NETLINK_GENERIC` = 16

Numeric protocol values are accepted as a fallback. Unknown names and out-of-range numeric values fail config validation.

Add socket type name resolution for:

- `SOCK_STREAM` = 1
- `SOCK_DGRAM` = 2
- `SOCK_RAW` = 3
- `SOCK_RDM` = 4
- `SOCK_SEQPACKET` = 5

Numeric socket type values are accepted as a fallback. Because Linux callers often OR `SOCK_CLOEXEC` or `SOCK_NONBLOCK` into the type argument, configured type matches compare only the low socket-type bits and ignore those flags. The conservative profile does not set `type`, but implementing type matching correctly now keeps the generic rule primitive coherent.

## Seccomp Enforcement

`agentsh-unixwrap` installs these rules next to existing `blocked_socket_families` rules.

For `socket(2)`, build conditional seccomp rules from the configured tuple:

- arg0 equals family
- arg1 equals type if configured
- arg2 equals protocol if configured

For `socketpair(2)`, build conditional seccomp rules from the same tuple shape where available:

- arg0 equals family
- arg1 equals type if configured
- arg2 equals protocol if configured

The Dirty Frag XFRM rule therefore blocks only:

```text
socket(AF_NETLINK, *, NETLINK_XFRM)
socketpair(AF_NETLINK, *, NETLINK_XFRM, ...)
```

and continues to allow:

```text
socket(AF_NETLINK, *, NETLINK_ROUTE)
socket(AF_NETLINK, *, NETLINK_KOBJECT_UEVENT)
socket(AF_NETLINK, *, NETLINK_GENERIC)
```

Actions reuse existing semantics:

- `errno`: kernel-side deny with `EAFNOSUPPORT`, matching existing socket-family blocking behavior.
- `kill`: kernel-side kill.
- `log`: seccomp notify, emit audit, then deny.
- `log_and_kill`: seccomp notify, emit audit, then kill.

Socket-rule denials consistently use `EAFNOSUPPORT`, including protocol-specific rules. This preserves the existing behavior operators already see from `blocked_socket_families` and makes unsupported attack-surface protocols look unavailable to sandboxed workloads.

## Audit

Add a new event type:

```text
seccomp_socket_rule_blocked
```

Fields:

```json
{
  "rule": "dirtyfrag-conservative-xfrm",
  "family": "AF_NETLINK",
  "family_number": 16,
  "type": "*",
  "type_number": null,
  "protocol": "NETLINK_XFRM",
  "protocol_number": 6,
  "syscall": "socket",
  "action": "log_and_kill",
  "outcome": "killed",
  "engine": "seccomp"
}
```

The event should be emitted for `log` and `log_and_kill`. Kernel-fast-path actions do not need audit, matching existing blocked syscall behavior.

## Ptrace Parity

Add ptrace support after the seccomp path, using the existing `FamilyChecker` pattern as the implementation model.

The matcher should inspect:

- syscall number
- arg0 family
- arg1 type for `socket` and `socketpair`
- arg2 protocol for `socket`

Ptrace audit events should use the same `seccomp_socket_rule_blocked` event shape with `engine: "ptrace"`.

Seccomp and ptrace may both hold the effective rules, but runtime dispatch remains mutually exclusive for a given syscall. This matches the current family-blocking architecture.

## Compatibility

No current default changes. Existing `blocked_socket_families` remains in place and still receives the current recommended defaults when unset.

The conservative Dirty Frag profile is opt-in:

```yaml
sandbox:
  seccomp:
    hardening_profiles:
      - dirtyfrag-conservative
```

Expected compatibility behavior:

- Normal `AF_NETLINK` use remains allowed.
- `NETLINK_ROUTE`, `NETLINK_KOBJECT_UEVENT`, and `NETLINK_GENERIC` remain allowed.
- `AF_RXRPC` is blocked, which should affect very few agent workloads.
- Keyring, namespace, and splice syscalls are not blocked by this conservative profile.

## Diagnostics

Startup logs should report profile expansion:

```text
seccomp hardening profile enabled profile=dirtyfrag-conservative rules=2
```

Config diagnostics should show the effective socket rules after profile expansion and validation.

Validation failures should include field paths, for example:

```text
sandbox.seccomp.socket_rules[0].protocol: "NETLINK_XFRMM" is not valid
sandbox.seccomp.hardening_profiles[0]: unknown profile "dirtyfrag"
```

## Tests

Config tests:

- parse `socket_rules`
- validate `AF_RXRPC`
- validate `NETLINK_XFRM`
- reject unknown family names
- reject unknown protocol names
- reject bad actions
- expand `dirtyfrag-conservative` to two effective rules
- reject duplicate rule names after profile expansion

Seccomp tests:

- allow `socket(AF_NETLINK, ..., NETLINK_ROUTE)`
- block `socket(AF_NETLINK, ..., NETLINK_XFRM)`
- block `socket(AF_RXRPC, ...)`
- verify `log` and `log_and_kill` emit `seccomp_socket_rule_blocked`
- verify existing `blocked_socket_families` tests still pass unchanged

Ptrace tests:

- matcher unit tests for exact tuple, wildcard type/protocol, and socketpair protocol matching
- integration test parity for `AF_RXRPC` and `NETLINK_XFRM` when ptrace support lands

## Rollout

1. Add config schema, validation, constants, and profile expansion.
2. Add seccomp enforcement and audit event support.
3. Document `socket_rules` and `dirtyfrag-conservative`.
4. Add ptrace matcher and audit parity.

The first operator-usable release can ship after step 3 if documentation clearly states that the profile requires the seccomp wrapper path. Ptrace parity should remain tracked as part of the same feature, not a separate long-term gap.
