# Fix file_monitor read-allow policy evaluation — Design Spec

**Date:** 2026-03-27
**Status:** Draft
**Problem:** When `seccomp.file_monitor.enabled: true`, the BPF filter traps ALL openat calls (read + write). Read-only opens are evaluated against the same policy rules designed for write enforcement. Many legitimate read paths (`/proc/self/**`, `/dev/**`, uncovered system paths) either hit explicit deny rules or fall through to `default-deny-files`, returning EACCES. This makes the sandbox unusable — bash can't load shared libraries, commands can't read /proc, /dev/null opens fail.

## Root Cause

Both policy files (`configs/policies/default.yaml` and `configs/policies/agent-default.yaml`) were designed with the assumption that only writes are intercepted (matching ptrace mode's `openatWriteMask` BPF prefilter). Three specific gaps:

1. **`deny-proc-sys`** (agent-default.yaml:522) / **`deny-system-sensitive`** (default.yaml:216) blocks `/proc/**` and `/sys/**` for ALL operations (`*`), including reads. Programs constantly read `/proc/self/status`, `/proc/self/maps`, `/proc/self/fd/*`.

2. **No allow rule for `/dev/**`** in either policy file. Opens of `/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/tty` fall through to `default-deny-files` → EACCES.

3. **`default-deny-files`** catches all paths not matched by any rule with glob `**` and operations `*`. Any path outside `/lib`, `/usr`, `/bin`, `/tmp`, workspace, or the explicit allow list is denied for reads.

Ptrace mode never hits these gaps because its BPF prefilter only traps write-flagged opens — read-only opens pass through at kernel level without policy evaluation.

## Approach

Make the policy read-aware with five changes:

1. **Operation-aware default in `CheckFile()`** — when no rule matches, default to ALLOW for read operations and DENY for write operations. Explicit deny rules for sensitive reads still match first.

2. **Narrow `default-deny-files` to write operations** — in both policy files. The current catch-all (`paths: "**"`, `operations: "*"`) matches ALL reads before the engine fallback is reached, making the engine-level `isReadOperation` check dead code. Change it to only match write operations so reads fall through to the engine's `default-allow-reads`.

3. **Narrow `/proc` and `/sys` deny rules to write operations** — in both policy files. Reads to `/proc/**` and `/sys/**` are no longer blocked by the bulk deny rule.

4. **Add explicit deny for `/proc/self/environ`** — narrowing the /proc deny opens up `/proc/self/environ` which leaks environment variables. Add an explicit deny rule for this path.

5. **Add `/dev/**` allow rules** — add `/dev/**` to `allow-system-read` for reads, add `allow-dev-write` with a narrow list of safe device nodes for writes.

## Detailed Design

### 1. Operation-aware default in CheckFile()

**File:** `internal/policy/engine.go`, lines 615-636

Add a helper function:

```go
// isReadOperation returns true for non-mutating file operations.
// These default to allow when no policy rule matches, because:
//   - Reads cannot modify the filesystem
//   - Sensitive reads are caught by explicit deny rules
//   - The policy was designed for write enforcement; reads hit many uncovered paths
//
// Note: "read" and "list" are included for completeness with policy rule
// operation names but are not currently produced by the Linux seccomp
// syscallToOperation() mapper. The Linux path produces: open, stat,
// readlink, access (read-like) and write, create, delete, rmdir, mkdir,
// rename, link, symlink, chmod, chown, mknod (write-like).
func isReadOperation(op string) bool {
    switch op {
    case "open", "read", "stat", "list", "readlink", "access":
        return true
    default:
        return false
    }
}
```

Change the default fallback in `CheckFile()`:

```go
// No rule matched — use operation-aware default.
// Write operations default to deny (safety net for unrecognized paths).
// Read operations default to allow (reads can't modify files;
// sensitive reads are caught by explicit deny rules above).
if isReadOperation(operation) {
    return e.wrapDecision(string(types.DecisionAllow), "default-allow-reads", "", nil)
}
return e.wrapDecision(string(types.DecisionDeny), "default-deny-files", "", nil)
```

**Security invariant:** Explicit deny rules match BEFORE the default because of first-match-wins evaluation. The default only applies to paths with NO matching rule.

### 2. Narrow default-deny-files to write operations

The `default-deny-files` rule in both YAML policy files is a catch-all with `paths: "**"` and `operations: "*"`. Because it matches ALL operations, it fires before the engine's fallback code in `CheckFile()`, making the `isReadOperation` check unreachable.

**File:** `configs/policies/agent-default.yaml`, rule `default-deny-files` (line 531)
**File:** `configs/policies/default.yaml`, rule `default-deny-files` (line 267)

Change in both files from:
```yaml
- name: default-deny-files
  description: Deny all other file operations
  paths:
    - "**"
  operations:
    - "*"
  decision: deny
```

To:
```yaml
- name: default-deny-files
  description: Deny all other file write operations
  paths:
    - "**"
  operations:
    - write
    - create
    - chmod
    - chown
    - delete
    - rename
    - mkdir
    - link
    - symlink
    - mknod
    - rmdir
  decision: deny
```

With this change, reads to uncovered paths fall through all YAML rules without matching, reach the engine's `CheckFile()` fallback, and get `default-allow-reads`. Writes to uncovered paths match `default-deny-files` and get denied.

### 3. Narrow /proc and /sys deny rules to writes

**File:** `configs/policies/agent-default.yaml`, rule `deny-proc-sys` (line 522)

Change from:
```yaml
- name: deny-proc-sys
  description: Block /proc and /sys
  paths:
    - "/proc/**"
    - "/sys/**"
  operations:
    - "*"
  decision: deny
```

To:
```yaml
- name: deny-proc-sys
  description: Block writes to /proc and /sys
  paths:
    - "/proc/**"
    - "/sys/**"
  operations:
    - write
    - create
    - chmod
    - chown
    - delete
    - rename
    - mkdir
    - link
    - symlink
    - mknod
    - rmdir
  decision: deny
```

**File:** `configs/policies/default.yaml`, rule `deny-system-sensitive` (line 216)

Same change — narrow operations from `*` to write-family operations only. Keep the `/etc/sudoers`, `/etc/sudoers.d/**`, `/etc/security/**` paths (these only appear in default.yaml, not agent-default.yaml).

### 4. Add explicit deny for /proc/self/environ

**File:** `configs/policies/agent-default.yaml` — add before `deny-proc-sys`:

```yaml
- name: deny-proc-environ
  description: Block reading process environment (may contain secrets)
  paths:
    - "/proc/self/environ"
    - "/proc/thread-self/environ"
    - "/proc/*/environ"
  operations:
    - "*"
  decision: deny
```

**File:** `configs/policies/default.yaml` — add before `deny-system-sensitive`:

Same rule.

This ensures `/proc/self/environ` stays blocked even after narrowing the bulk /proc deny to writes. Environment variables may contain secrets (API keys, tokens) that would be leaked via this path.

### 5. Add /dev allow rules

**File:** `configs/policies/agent-default.yaml` — add `/dev/**` to `allow-system-read` (line 446):

```yaml
- name: allow-system-read
  description: Read access to standard system paths
  paths:
    - "/usr/**"
    - "/lib/**"
    - "/lib64/**"
    - "/bin/**"
    - "/sbin/**"
    - "/opt/**"
    - "/dev/**"
  operations: [read, open, stat, list, readlink]
  decision: allow
```

Add a new rule after `allow-system-read` for device writes (narrow allowlist):

```yaml
- name: allow-dev-write
  description: Allow writes to safe device nodes
  paths:
    - "/dev/null"
    - "/dev/zero"
    - "/dev/tty"
    - "/dev/pts/**"
    - "/dev/urandom"
    - "/dev/random"
    - "/dev/shm/**"
  operations: [write, create, open]
  decision: allow
```

Note: `/dev/fuse` is intentionally excluded — opening it for writing enables FUSE mounts, which is the supervisor's responsibility.

**File:** `configs/policies/default.yaml` — same changes to `allow-system-read` and add `allow-dev-write`.

### 6. Testing

**6a. Read-allow default tests** (in `internal/policy/agent_policies_test.go`):
- `CheckFile("/dev/null", "open")` → allow, rule `allow-system-read` (matches `/dev/**`)
- `CheckFile("/some/unknown/path", "open")` → allow, rule `default-allow-reads` (no rule matches, read default)
- `CheckFile("/some/unknown/path", "write")` → deny, rule `default-deny-files` (no rule matches, write default)
- `CheckFile("/proc/self/status", "open")` → allow, rule `default-allow-reads` (`deny-proc-sys` no longer matches reads)
- `CheckFile("/proc/self/status", "write")` → deny, rule `deny-proc-sys`

**6b. Exfiltration deny rules still work:**
- `CheckFile("<HOME>/.ssh/id_rsa", "open")` → approve, rule `approve-ssh-keys` (agent-default uses approve, not deny)
- `CheckFile("/path/to/.env", "open")` → approve, rule `approve-env-files` (agent-default)
- `CheckFile("<HOME>/.aws/credentials", "open")` → approve, rule `approve-cloud-credentials` (agent-default)
- `CheckFile("/proc/self/environ", "open")` → deny, rule `deny-proc-environ` (new rule)
- `CheckFile("/proc/self/environ", "read")` → deny, rule `deny-proc-environ`

**6c. Existing tests that need updated expectations:**
- `agent_policies_test.go:649-653` — `/proc/self/environ` read: rule changes from `deny-proc-sys` to `deny-proc-environ` (decision stays deny)
- `agent_policies_test.go:654-660` — `/sys/class/net/eth0/address` read: changes from deny/`deny-proc-sys` to allow/`default-allow-reads` (`deny-proc-sys` no longer matches reads; no explicit deny rule covers this path for reads)
- `agent_policies_test.go:661-667` — `/home/user/.bashrc` read: changes from deny/`default-deny-files` to allow/`default-allow-reads` (`default-deny-files` no longer matches reads; `.bashrc` is not in any exfiltration deny rule)
- All other `TestAgentDefault_FileDecisions` cases must still pass unchanged.

### 7. Files Changed

| File | Change |
|------|--------|
| `internal/policy/engine.go` | Add `isReadOperation()` helper; change default fallback in `CheckFile()` |
| `configs/policies/agent-default.yaml` | Add `deny-proc-environ` rule; narrow `deny-proc-sys` to write ops; add `/dev/**` to `allow-system-read`; add `allow-dev-write` rule |
| `configs/policies/default.yaml` | Add `deny-proc-environ` rule; narrow `deny-system-sensitive` to write ops; add `/dev/**` to `allow-system-read`; add `allow-dev-write` rule |
| `internal/policy/agent_policies_test.go` | Add tests for read-allow default, /proc reads, /dev access, /proc/self/environ deny; update existing test expectations |
