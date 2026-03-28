# Fix file_monitor read-allow policy evaluation — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the seccomp file_monitor allow read-only file operations by default, so the sandbox doesn't block bash from loading shared libraries, reading /proc, or opening /dev/null.

**Architecture:** The policy engine's `CheckFile()` gets an operation-aware fallback (reads default-allow, writes default-deny). Both YAML policy files (`agent-default.yaml` and `default.yaml`) are narrowed so their catch-all deny rules only match write operations, letting reads fall through to the engine fallback. Explicit deny rules for `/proc/self/environ` maintain security for sensitive read paths.

**Tech Stack:** Go, YAML policy files, gobwas/glob, testify

**Spec:** `docs/superpowers/specs/2026-03-27-fix-filemonitor-reads-design.md`

**Note on `open` operation:** The seccomp `syscallToOperation()` mapper (in `internal/netmonitor/unix/file_syscalls.go`) sends `"open"` only for read-only opens (`O_RDONLY`). Write-flagged opens (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`) are mapped to `"write"` or `"create"`. So `isReadOperation("open") == true` is correct — it only fires for genuinely read-only opens.

**Note on `/etc/sudoers` reads:** Narrowing `deny-system-sensitive` in `default.yaml` opens `/etc/sudoers` and `/etc/security/**` for reads. This is intentional — the policy was designed for write enforcement, and these files are world-readable on most systems. The security concern is writes (privilege escalation), not reads.

---

### Task 1: Add `isReadOperation()` helper and operation-aware default in `CheckFile()`

**Files:**
- Modify: `internal/policy/engine.go:615-636`
- Test: `internal/policy/agent_policies_test.go`

- [ ] **Step 1: Write failing tests for operation-aware default**

Add these test cases to `TestAgentDefault_FileDecisions` in `internal/policy/agent_policies_test.go`. Insert them just before the closing `}` of the `tests` slice (before line 668):

```go
		// Read-allow defaults (new behavior)
		{
			name:     "read unknown path defaults to allow",
			path:     "/some/unknown/path",
			op:       "open",
			wantDec:  types.DecisionAllow,
			wantRule: "default-allow-reads",
		},
		{
			name:     "write unknown path defaults to deny",
			path:     "/some/unknown/path",
			op:       "write",
			wantDec:  types.DecisionDeny,
			wantRule: "default-deny-files",
		},
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/ -run TestAgentDefault_FileDecisions -v -count=1 2>&1 | tail -30`
Expected: FAIL — "read unknown path defaults to allow" fails because currently returns deny/`default-deny-files`.

- [ ] **Step 3: Add `isReadOperation()` helper to `engine.go`**

Add this function right before the `CheckFile` method (before line 615 in `internal/policy/engine.go`):

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

- [ ] **Step 4: Change the default fallback in `CheckFile()`**

In `internal/policy/engine.go`, replace the block at lines 634-635:

```go
	// Default deny (policy files typically include an explicit default deny, but we enforce it here too).
	return e.wrapDecision(string(types.DecisionDeny), "default-deny-files", "", nil)
```

With:

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

- [ ] **Step 5: Run tests — new tests still fail (YAML catch-all blocks reads first)**

Run: `go test ./internal/policy/ -run TestAgentDefault_FileDecisions -v -count=1 2>&1 | tail -30`
Expected: FAIL — "read unknown path defaults to allow" still fails because `default-deny-files` in the YAML has `operations: "*"` which matches reads before the engine fallback is reached. This confirms the spec's Section 2 analysis. The Go code change is correct but the YAML must also be narrowed (Task 2).

- [ ] **Step 6: Commit engine changes**

```bash
git add internal/policy/engine.go internal/policy/agent_policies_test.go
git commit -m "feat: add isReadOperation() helper and operation-aware default in CheckFile()

Read operations now default to allow when no policy rule matches.
Write operations still default to deny. This is the engine-side half
of the fix — YAML policy rules must also be narrowed for reads to
actually fall through to this code path.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 2: Narrow YAML policy rules and add `deny-proc-environ`

This task makes all YAML changes together so there is no transient window where `/proc/self/environ` reads are allowed.

**Files:**
- Modify: `configs/policies/agent-default.yaml` (add deny-proc-environ, narrow deny-proc-sys, narrow default-deny-files)
- Modify: `configs/policies/default.yaml` (add deny-proc-environ, narrow deny-system-sensitive, narrow default-deny-files)
- Modify: `internal/policy/agent_policies_test.go`

- [ ] **Step 1: Add `deny-proc-environ` rule to `agent-default.yaml`**

In `configs/policies/agent-default.yaml`, insert this rule immediately before `deny-proc-sys` (before line 522):

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

- [ ] **Step 2: Narrow `deny-proc-sys` in `agent-default.yaml`**

Replace the `deny-proc-sys` rule (lines 522-529, now shifted down by the insertion):

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

With:

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

- [ ] **Step 3: Narrow `default-deny-files` in `agent-default.yaml`**

Replace the `default-deny-files` rule:

```yaml
  - name: default-deny-files
    description: Deny all other file operations
    paths:
      - "**"
    operations:
      - "*"
    decision: deny
```

With:

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

- [ ] **Step 4: Add `deny-proc-environ` rule to `default.yaml`**

In `configs/policies/default.yaml`, insert this rule immediately before `deny-system-sensitive` (before line 216):

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

- [ ] **Step 5: Narrow `deny-system-sensitive` in `default.yaml`**

Replace the `deny-system-sensitive` rule (lines 216-226, now shifted down):

```yaml
  - name: deny-system-sensitive
    description: Block sensitive system files
    paths:
      - "/etc/sudoers"
      - "/etc/sudoers.d/**"
      - "/etc/security/**"
      - "/proc/**"
      - "/sys/**"
    operations:
      - "*"
    decision: deny
```

With:

```yaml
  - name: deny-system-sensitive
    description: Block writes to sensitive system files
    paths:
      - "/etc/sudoers"
      - "/etc/sudoers.d/**"
      - "/etc/security/**"
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

- [ ] **Step 6: Narrow `default-deny-files` in `default.yaml`**

Replace the `default-deny-files` rule (lines 267-273, now shifted down):

```yaml
  - name: default-deny-files
    description: Deny all other file operations
    paths:
      - "**"
    operations:
      - "*"
    decision: deny
```

With:

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

- [ ] **Step 7: Update `wantFileRules` count in `TestAgentPolicies`**

In `internal/policy/agent_policies_test.go`, line 46, change:

```go
			wantFileRules:    12,
```

To:

```go
			wantFileRules:    13,
```

This accounts for the new `deny-proc-environ` rule added to `agent-default.yaml`. (Task 3 will bump this to 14 when `allow-dev-write` is added.)

- [ ] **Step 8: Update existing test expectations and add new tests**

In `internal/policy/agent_policies_test.go`, make these changes:

**Update line 647-652** — `/proc/self/environ` read: rule changes from `deny-proc-sys` to `deny-proc-environ`:

```go
		{
			name:     "read /proc/self/environ denied (secrets)",
			path:     "/proc/self/environ",
			op:       "read",
			wantDec:  types.DecisionDeny,
			wantRule: "deny-proc-environ",
		},
```

**Update line 654-660** — `/sys/class/net/eth0/address` read: changes from deny to allow:

```go
		{
			name:     "read /sys allowed (reads not blocked)",
			path:     "/sys/class/net/eth0/address",
			op:       "read",
			wantDec:  types.DecisionAllow,
			wantRule: "default-allow-reads",
		},
```

**Update line 661-667** — `/home/user/.bashrc` read: changes from deny to allow:

```go
		{
			name:     "read random home path allowed (reads not blocked)",
			path:     "/home/user/.bashrc",
			op:       "read",
			wantDec:  types.DecisionAllow,
			wantRule: "default-allow-reads",
		},
```

**Add new test cases** (insert before the closing `}` of the tests slice, after the tests added in Task 1):

```go
		// /proc read/write behavior after narrowing
		{
			name:     "open /proc/self/environ denied (secrets)",
			path:     "/proc/self/environ",
			op:       "open",
			wantDec:  types.DecisionDeny,
			wantRule: "deny-proc-environ",
		},
		{
			name:     "read /proc/self/status allowed",
			path:     "/proc/self/status",
			op:       "open",
			wantDec:  types.DecisionAllow,
			wantRule: "default-allow-reads",
		},
		{
			name:     "write /proc/self/status denied",
			path:     "/proc/self/status",
			op:       "write",
			wantDec:  types.DecisionDeny,
			wantRule: "deny-proc-sys",
		},
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `go test ./internal/policy/ -run TestAgentDefault_FileDecisions -v -count=1 2>&1 | tail -50`
Expected: PASS — all tests pass including the new ones from Task 1.

- [ ] **Step 10: Commit YAML and test changes**

```bash
git add configs/policies/agent-default.yaml configs/policies/default.yaml internal/policy/agent_policies_test.go
git commit -m "feat: narrow policy deny rules to writes, add deny-proc-environ

Narrow deny-proc-sys, deny-system-sensitive, and default-deny-files
to only match write-family operations. Reads now fall through to the
engine's operation-aware default (default-allow-reads).

Add deny-proc-environ rule to block reads of /proc/*/environ which
leaks environment variables (API keys, tokens).

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 3: Add `/dev/**` allow rules

**Files:**
- Modify: `configs/policies/agent-default.yaml:446-461` (allow-system-read) + new allow-dev-write rule
- Modify: `configs/policies/default.yaml:75-90` (allow-system-read) + new allow-dev-write rule
- Modify: `internal/policy/agent_policies_test.go`

- [ ] **Step 1: Update `wantFileRules` count for the new rule**

In `internal/policy/agent_policies_test.go`, line 46, change:

```go
			wantFileRules:    13,
```

To:

```go
			wantFileRules:    14,
```

This accounts for the new `allow-dev-write` rule.

- [ ] **Step 2: Write failing tests for /dev access**

Add these test cases to `TestAgentDefault_FileDecisions` in `internal/policy/agent_policies_test.go` (in the test slice, grouped with the system path tests):

```go
		// /dev access
		{
			name:     "read /dev/null via allow-system-read",
			path:     "/dev/null",
			op:       "open",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-system-read",
		},
		{
			name:     "write /dev/null via allow-dev-write",
			path:     "/dev/null",
			op:       "write",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-dev-write",
		},
		{
			name:     "write /dev/tty via allow-dev-write",
			path:     "/dev/tty",
			op:       "write",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-dev-write",
		},
		{
			name:     "write /dev/pts/0 via allow-dev-write",
			path:     "/dev/pts/0",
			op:       "write",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-dev-write",
		},
		{
			name:     "write /dev/fuse denied (not in allow-dev-write)",
			path:     "/dev/fuse",
			op:       "write",
			wantDec:  types.DecisionDeny,
			wantRule: "default-deny-files",
		},
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/policy/ -run TestAgentDefault_FileDecisions -v -count=1 2>&1 | tail -40`
Expected: FAIL — `/dev/null` open returns allow/`default-allow-reads` (no rule matches `/dev/**` yet), not allow/`allow-system-read`. Write tests also fail with deny/`default-deny-files`.

- [ ] **Step 4: Add `/dev/**` to `allow-system-read` in `agent-default.yaml`**

In `configs/policies/agent-default.yaml`, add `- "/dev/**"` to the `allow-system-read` paths list (after `- "/opt/**"`):

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
    operations:
      - read
      - open
      - stat
      - list
      - readlink
    decision: allow
```

- [ ] **Step 5: Add `allow-dev-write` rule in `agent-default.yaml`**

Insert this rule immediately after `allow-system-read` (after the `decision: allow` line):

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
    operations:
      - write
      - create
      - open
    decision: allow
```

- [ ] **Step 6: Add `/dev/**` to `allow-system-read` in `default.yaml`**

In `configs/policies/default.yaml`, add `- "/dev/**"` to the `allow-system-read` paths list (after `- "/opt/**"`):

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
    operations:
      - read
      - open
      - stat
      - list
      - readlink
    decision: allow
```

- [ ] **Step 7: Add `allow-dev-write` rule in `default.yaml`**

Insert this rule immediately after `allow-system-read` in `default.yaml`:

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
    operations:
      - write
      - create
      - open
    decision: allow
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `go test ./internal/policy/ -run TestAgentDefault_FileDecisions -v -count=1 2>&1 | tail -50`
Expected: PASS — all /dev tests pass.

- [ ] **Step 9: Commit**

```bash
git add configs/policies/agent-default.yaml configs/policies/default.yaml internal/policy/agent_policies_test.go
git commit -m "feat: add /dev allow rules for read and safe device writes

Add /dev/** to allow-system-read for read operations. Add
allow-dev-write with a narrow allowlist of safe device nodes
(/dev/null, /dev/zero, /dev/tty, /dev/pts/**, /dev/urandom,
/dev/random, /dev/shm/**). /dev/fuse intentionally excluded.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 4: Full test suite verification

**Files:**
- None modified — verification only

- [ ] **Step 1: Run the full policy test suite**

Run: `go test ./internal/policy/ -v -count=1 2>&1 | tail -50`
Expected: PASS — all tests pass, no regressions.

- [ ] **Step 2: Run the full project test suite**

Run: `go test ./... -count=1 2>&1 | tail -20`
Expected: PASS — no regressions.

- [ ] **Step 3: Verify cross-compilation**

Run: `GOOS=windows go build ./... 2>&1`
Expected: builds successfully (the changes are YAML + engine logic, no platform-specific code).

- [ ] **Step 4: Commit nothing (verification only) — proceed to PR**
