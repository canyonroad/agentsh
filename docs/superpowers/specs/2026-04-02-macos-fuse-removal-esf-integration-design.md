# macOS FUSE-T Removal & ESF Integration Design

## Goal

Replace FUSE-T with ESF as the sole file monitoring mechanism on macOS. Remove the XPC package, establish a secure policy socket between the Go server and the ESF system extension, add NE proxy enforcement for eBPF-parity network defense-in-depth, and verify blocking/redirect works end-to-end.

## Background

FUSE-T was a stopgap for file I/O monitoring on macOS. Now that the ESF system extension is stable (AUTH_OPEN, NOTIFY_CLOSE, NOTIFY_EXEC, etc.), FUSE-T is redundant. The XPC package (`internal/platform/darwin/xpc/`) was the original sysext-server IPC mechanism but the sysext was rewritten to use a Unix socket with newline-delimited JSON (`PolicySocketClient.swift`). The XPC package name is a misnomer — it's already a Unix socket server since Go can't speak Apple's XPC protocol.

On the network side, the Go server's HTTP proxy handles monitoring (working today), but processes that ignore `HTTP_PROXY` can bypass it. Linux uses eBPF enforce mode for defense-in-depth. macOS needs the same via the NetworkExtension content filter.

**Canonical sysext bundle ID:** `ai.canyonroad.agentsh.SysExt` (case-sensitive, matches Info.plist and `systemextensionsctl` output). Note: `internal/platform/darwin/sysext.go` and its tests use lowercase `ai.canyonroad.agentsh.sysext` — these must be updated to match the canonical form.

## Workstreams

### 1. Remove FUSE-T

**Files to change:**

- `internal/platform/fuse/detect_darwin.go` — `checkAvailable()` returns `false`, `detectImplementation()` returns `"none"`. Remove FUSE-T/macFUSE path detection arrays.
- `internal/platform/fuse/detect_darwin_test.go` — Simplify to verify functions return `false`/`"none"`.
- `internal/platform/darwin/permissions.go`:
  - Remove fields: `HasFuseT`, `FuseTVersion`, `HasMacFUSE`.
  - Remove functions: `checkFuseT()`, `checkMacFUSE()`.
  - Add field: `HasSystemExtension` — detected via `systemextensionsctl list` checking for activated `ai.canyonroad.agentsh.SysExt`.
  - Collapse tier system from 5 to 3 tiers:
    - **Enterprise** (sysext installed, ESF + NE) — score 95
    - **Standard** (root + pf, no sysext) — score 50
    - **Minimal** (no root) — score 10
  - Users currently at TierFull (had FUSE-T + root + pf, score 75) will fall to Standard (score 50) unless they install the sysext (which promotes them to Enterprise at 95). The `computeMissingPermissions()` output should include a tip: "Install the agentsh system extension to enable ESF-based file monitoring (replaces FUSE-T)."
  - Update `AvailableFeatures()`: remove FUSE references, ESF-based features for Enterprise tier.
  - Update `LogStatus()`: remove FUSE section, add sysext status section.
- `internal/platform/darwin/platform.go`:
  - Update doc comment (remove FUSE-T reference).
  - Map 3 tiers to capabilities: Enterprise gets `HasFUSE=true, FUSEImplementation="endpoint-security"`. Standard and Minimal get `HasFUSE=false`.
- `internal/platform/darwin/sysext.go` and `internal/platform/darwin/sysext_test.go`:
  - Update bundle ID from lowercase `ai.canyonroad.agentsh.sysext` to canonical `ai.canyonroad.agentsh.SysExt`.
- `internal/capabilities/detect_darwin.go`:
  - Remove `fuse_t` from caps map and `checkFuseT()` function.
  - Replace `checkESF()` with `checkSysExtInstalled()` — checks `systemextensionsctl list` for activated sysext. This is distinct from the old `checkESF()` which checked the running binary's entitlements (the CLI never has ESF entitlements; the sysext does).
  - Remove `fuse-t` backend from File Protection domain, keep `esf` only.
  - Update `selectDarwinMode()` to remove fuse-t modes (`"dynamic-seatbelt-fuse"`, `"fuse-t"`).
- `internal/capabilities/detect_darwin_test.go` — Update test cases for new tier/mode structure.
- `internal/capabilities/tips.go`:
  - Remove `fuse_t` entry from `darwinTips`.
  - Remove `"fuse-t"` entry from `tipsByBackend`.

**What stays:** Linux native FUSE, Windows WinFsp, cgofuse dependency (used by Linux/Windows), `nofuse` build tag (less important but still available).

**Graceful degradation:** Without the sysext installed, users land at Standard tier with no file interception. This is the same as the current TierNetworkOnly behavior. FSEvents observation is not preserved as a fallback — it was never enforcing, only observing, so it provides no security value for agentsh's use case. The tip system will guide users to install the sysext.

### 2. Rename XPC to policysock

**Mechanical rename:**

- Move all files in `internal/platform/darwin/xpc/` → `internal/platform/darwin/policysock/`
- Full file list (14 files): `server.go`, `server_test.go`, `protocol.go`, `protocol_test.go`, `handler.go`, `handler_test.go`, `sessions.go`, `sessions_test.go`, `snapshot.go`, `snapshot_test.go`, `version.go`, `version_test.go`, `event_handler_test.go`, `integration_test.go`
- Rename package declaration from `xpc` to `policysock`
- Strip XPC-specific naming in comments and strings:
  - `PolicyAdapter` slog prefix: `"xpc:"` → `"policysock:"`
  - `PolicyHandler` comment: `"XPC bridge"` → `"policy socket bridge"`
  - Panic message: `"xpc: handler must not be nil"` → `"policysock: handler must not be nil"`
  - Note: the `Server` type is already named `Server` (not `XPCServer`), so no type rename needed.
- Update import paths in files that import the package:
  - `internal/platform/darwin/es_exec.go`
  - `internal/platform/darwin/es_exec_test.go`
  - `internal/platform/darwin/es_exec_integration_test.go`
  - `internal/platform/darwin/xpc/sessions.go` (self-reference, moves with package)
  - `internal/platform/darwin/xpc/sessions_test.go` (self-reference, moves with package)
- **Do NOT rename** references to Apple's XPC services in other files (e.g., `internal/api/xpc_darwin.go` references macOS XPC service allow/block lists — these are unrelated to the policy socket and must stay as-is).

**What stays unchanged:** The wire protocol (newline-delimited JSON), the session snapshot structure, the message types. The sysext's `PolicySocketClient.swift` already speaks this protocol.

**Approval dialog compatibility:**

The current server sets the socket to mode `0666` so the `ApprovalDialog.app` (which runs as the logged-in user) can connect to fetch/submit approvals. With the new `0600` root-only socket, the approval dialog cannot connect directly.

Solution: split into two sockets:
- **Policy socket** (`/var/run/agentsh/policy.sock`, root:wheel 0600) — sysext ↔ server communication, secured with code signing validation.
- **Approval socket** (user-accessible path, e.g., `~/Library/Application Support/agentsh/approval.sock` or the existing `data/agentsh.sock`) — approval dialog ↔ server communication. Only exposes approval-related operations (get pending, submit decision). No state-changing operations (register/unregister session).

This addresses the existing TODO in server.go about separating approval operations.

**Wire into server startup:**

- The server's main startup creates a `policysock.Server` listening on the configured socket path
- Socket path is fixed at `/var/run/agentsh/policy.sock` (not configurable — the sysext hardcodes this path in `PolicySocketClient.swift` line 9, and sysext bundles cannot read server config files). If the path needs to change in the future, both sides must be updated together.
- Config in `config.yml`:
  ```yaml
  policy_socket:
    path: "/var/run/agentsh/policy.sock"
    team_id: "WCKWMMKJ35"
  ```
- Server pushes session snapshots when sessions are created/updated/destroyed
- Server receives events from the sysext and routes them to the session's event store

### 3. Secure Policy Socket

Three layers of trust validation, applied on every accepted connection:

**Layer 1 — File permissions:**
- Socket file created as `root:wheel` mode `0600`
- Install script creates `/var/run/agentsh/` with matching ownership
- Only root can connect

**Layer 2 — Peer UID check:**
- On `Accept()`, call `getpeereid()` on the connection
- Reject any peer with UID != 0 (sysext runs as root)

**Layer 3 — Code signing validation:**
- Get peer PID via `LOCAL_PEERPID` socket option
- Resolve binary path from PID via `proc_pidpath()`
- Validate code signing against the configured team ID
- Reject connections from incorrectly signed processes

**Implementation approach:** Initial implementation shells out to `codesign --verify -R="anchor apple generic and certificate leaf[subject.OU] = \"<team_id>\"" <binary_path>`. This has known tradeoffs:
- Process spawn on each connection (acceptable — connections are infrequent, not per-event)
- TOCTOU risk between PID resolution and codesign check (mitigated by UID check in layer 2 — only root processes reach layer 3)
- `codesign` output format dependency (stable across macOS versions for `--verify`)

Future improvement: replace shell-out with `Security.framework` C API (`SecCodeCopyGuestWithAttributes` + `SecCodeCheckValidityWithErrors`) via CGO for direct in-process validation.

**Bidirectional validation:**
- `PolicySocketClient.swift` must be updated to validate the server process after connecting:
  - Get peer PID via `LOCAL_PEERPID` socket option on the connected fd
  - Resolve binary path via `proc_pidpath()`
  - Validate code signing using `SecCodeCopyGuestWithAttributes` + `SecCodeCheckValidityWithErrors` (native Swift, no shell-out needed)
  - Disconnect if validation fails
- Prevents a rogue process from squatting on the socket path

**Implementation files:**
- New: `policysock/auth.go` — `ValidatePeer(conn *net.UnixConn) error`, called after `Accept()`
- Modify: `macos/AgentSH/PolicySocketClient.swift` — add `validateServer()` method called after `connect()`

### 4. NE Proxy Enforcement (eBPF Parity)

**Goal:** The NetworkExtension content filter enforces that session PIDs can only make network connections through the proxy, matching Linux eBPF enforce behavior.

**Data flow:**

1. Server creates a session, proxy starts on `127.0.0.1:<port>`
2. Server pushes session snapshot to sysext via policy socket, including `proxy_addr` and direct-connect allowlist
3. `SessionPolicyCache` stores proxy address per session
4. NE filter evaluates connections:
   - PID not in any session → `.allow()` (pass through, no session scope)
   - PID in session, destination is the session's proxy address → `.allow()`
   - PID in session, destination is localhost (`127.0.0.1`, `::1`) → `.allow()`
   - PID in session, destination is on the direct-connect allowlist → `.allow()`
   - PID in session, destination is external and not through proxy → `.drop()` + report `proxy_bypass_blocked` event

**Wire format additions:**

Go side — add to `PolicyResponse` (or its successor in `policysock/protocol.go`):
```go
type SessionSnapshot struct {
    // ... existing fields ...
    ProxyAddr    string          `json:"proxy_addr,omitempty"`    // e.g. "127.0.0.1:50382"
    DirectAllow  []DirectAllow   `json:"direct_allow,omitempty"`
}

type DirectAllow struct {
    Host string `json:"host"`  // IP, hostname, or "*" for any
    Port int    `json:"port"`  // 0 means any port
}
```

Swift side — add to `SessionCache` in `SessionPolicyCache.swift`:
```swift
struct DirectAllowEntry {
    let host: String  // IP, hostname, or "*"
    let port: Int     // 0 = any port
}

// In SessionCache:
var proxyAddr: String?
var directAllow: [DirectAllowEntry] = []
```

Parse in `SessionCache.from(json:sessionID:rootPID:)` from the `proxy_addr` and `direct_allow` JSON fields.

**`proxy_bypass_blocked` event format:**
```json
{
    "type": "proxy_bypass_blocked",
    "session_id": "session-xxx",
    "pid": 12345,
    "destination_ip": "93.184.216.34",
    "destination_port": 443,
    "destination_host": "example.com",
    "process_name": "malicious-tool",
    "bundle_id": "",
    "timestamp": "2026-04-02T18:42:56.590129Z"
}
```

**Mode toggle:** The existing `blockingEnabled` flag on the NE filter remains the master switch. When blocking is off, the filter audits but doesn't enforce proxy usage (same as eBPF `enforce: false`).

**Swift file changes:**

- `SessionPolicyCache.swift`: add `proxyAddr` and `directAllow` per session, parse from snapshot JSON
- `FilterDataProvider.swift`: add proxy enforcement logic in `handleNewFlow()` before existing policy evaluation
- `PolicySocketClient.swift`: add `proxy_bypass_blocked` event sending

### 5. Manual E2E Testing

Test sequence after implementation:

**Setup:**
1. Build Go binary + sysext, sign, notarize, install
2. Enable Full Disk Access for the sysext
3. Start server: `sudo ./agentsh server --config ./config.yml`
4. Verify policy socket: confirm `/var/run/agentsh/policy.sock` exists, sysext connects (check server logs)

**File I/O via ESF:**
5. Create session: `./agentsh session create --policy agent-observe --workspace /tmp/test`
6. Run file commands: `./agentsh exec $SID -- bash -c 'echo test > /tmp/test/file.txt'`
7. Query events: `./agentsh events query $SID` — verify `fs_open`, `fs_close` events appear from ESF
8. Switch to a policy with file deny rules, re-run — verify AUTH_OPEN blocks file access

**Network via proxy + NE enforcement:**
9. Run: `./agentsh exec $SID -- curl https://example.com` — verify `net_connect` event via proxy
10. Test proxy bypass detection: `./agentsh exec $SID -- python3 -c "import urllib.request; urllib.request.urlopen('https://example.com')"` (Python's `urlopen` can bypass `HTTP_PROXY` depending on configuration). Verify NE filter blocks it and `proxy_bypass_blocked` event appears.

**Exec redirect:**
11. Configure a policy with exec redirect rules
12. Run the redirected command — verify ESF denies original exec, server gets redirect notification

**Success criteria:**
- Events appear in `events query` for file, network, and exec categories
- Deny policies result in actual blocking (file access denied, connection dropped)
- Proxy bypass is caught and blocked by the NE filter

## Out of Scope

- Automated integration test harness (separate spec)
- Linux/Windows changes (unaffected by this work)
- FUSE removal from Linux/Windows builds (they keep their native FUSE)
- Changes to the sysext's ESF event handling (already working from prior implementation)
- Security.framework CGO integration for code signing validation (future improvement over codesign shell-out)

## Dependencies

- ESF system extension must be installed and activated (completed in prior work)
- macOS with Full Disk Access granted to the sysext
- Server runs as root (or with appropriate permissions for the policy socket)
