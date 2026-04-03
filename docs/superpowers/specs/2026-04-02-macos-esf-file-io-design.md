# macOS ESF File I/O Event Capture & Enforcement

## Goal

Complete end-to-end file I/O tracking on macOS via ESF, achieving parity with Linux's seccomp/FUSE file event capture. All file operations from session-scoped processes (open, create, delete, rename, write, chmod, chown) flow from the sysext to the Go server and are stored in the event store with full session and command attribution.

## Context

The previous implementation plan (2026-04-02-macos-fuse-removal-esf-integration) removed FUSE-T, renamed xpc→policysock, added socket authentication, wired up the policy socket server, and added NE proxy enforcement. The infrastructure is in place:

- ESF AUTH handlers evaluate locally via `SessionPolicyCache` (no IPC on critical path)
- `PolicySocketClient` communicates with the Go server via Unix socket at `/tmp/agentsh-policy.sock` (note: earlier specs reference `/var/run/agentsh/policy.sock` — this was migrated to `/tmp/` to avoid requiring root; see FUSE removal plan)
- `policysock.Server` accepts connections, routes requests, and has an `EventHandler` interface

What's missing: the sysext sends file events but the Go server silently drops them (no `EventHandler` wired up). File approve/redirect/soft_delete actions are defined in Go policy but hardcoded to deny in Swift with no follow-through.

## Architecture

### Two Connection Types

The policy socket serves two connection types:

1. **Request-response** (existing) — short-lived connections for policy checks, snapshots, session registration, mute requests. Client sends one JSON request, server responds, connection closes.

2. **Event stream** (new) — a single persistent connection for file event observation. The sysext opens this connection at startup (or on first session registration) and keeps it alive. Events are written as newline-delimited JSON, fire-and-forget (no response from server). Reconnects with exponential backoff on failure.

The server distinguishes connection types by the first message: if `"type": "event_stream_init"`, it switches to stream mode and reads events in a loop. Otherwise, it handles the message as a normal request-response.

### Event Flow

```
Process calls open("/workspace/file.txt")
    ↓
ESF delivers AUTH_OPEN to sysext
    ↓
Sysext evaluates locally via SessionPolicyCache.evaluateFile() → allow/deny
    ↓
Sysext responds to ESF immediately (AUTH response — never blocked by IPC)
    ↓
Sysext writes event JSON to persistent event stream connection (fire-and-forget)
    ↓
Go policysock server reads event from stream connection
    ↓
Go resolves command_id via PID→command lookup
    ↓
Go stores as types.Event in SQLite (via existing async batch writer)
```

### ESF Limitations vs FUSE

ESF AUTH events are binary: allow or deny. Unlike FUSE, ESF cannot transparently rewrite file paths or fake successful operations. This affects three policy actions:

| Action | FUSE behavior | ESF behavior |
|--------|--------------|--------------|
| **redirect** | Transparent path rewrite — process sees redirected file | Deny at ESF + Go server updates session guidance with redirect target path |
| **soft_delete** | Fake successful unlink — file preserved invisibly | Deny at ESF + file stays, event logged, guidance updated |
| **approve** | Block until user approves, then allow | Deny at ESF + trigger approval flow. Original operation fails; exec layer can re-execute after approval |

This works well for AI agent sandboxes because commands run through the Go exec layer which provides guidance and retry capability. The agent adapts its behavior based on guidance rather than needing transparent filesystem tricks.

## Component Design

### 1. Swift: Persistent Event Stream Connection

**PolicySocketClient.swift** — add a dedicated persistent connection for event streaming:

- `connectEventStream()` — opens a persistent connection, sends `{"type": "event_stream_init"}` as the first message. The server responds with `{"status": "ok"}` to acknowledge. After this handshake, the connection becomes one-directional: client writes events, server reads. No further responses are sent by the server.
- `sendEvent(_ event: [String: Any])` — writes newline-delimited JSON to the persistent connection. No response expected. If the connection is dead, events are queued in a fixed-size ring buffer (1024 events). If the buffer overflows, the oldest events are dropped and a warning is logged with the drop count. Reconnect runs in the background.
- Reconnect with exponential backoff: 1s, 2s, 4s, capped at 30s. On successful reconnect, flush the buffer.
- Separate from the existing `sendSync` request-response path — event stream never blocks policy checks.
- Remove the existing NOTIFY_CLOSE event-via-request-response path in `ESFClient.handleNotifyClose`. All file events use the persistent stream exclusively.

### 2. Swift: ESF AUTH Handler Event Forwarding

All AUTH handlers follow the same pattern:

1. Evaluate locally via `SessionPolicyCache.evaluateFile()`
2. Respond to ESF immediately (allow/deny)
3. Fire event to stream connection (fire-and-forget, never blocks step 2)

**Events forwarded per handler:**

| Handler | Event type | Key fields |
|---------|-----------|------------|
| `handleAuthOpen()` | `file_open` | path, operation (read/write/readwrite — check `event.open.fflag` for `FFLAGS_READ`/`FFLAGS_WRITE`), decision, rule. Note: AUTH_OPEN uses `es_respond_flags_result`, not `es_respond_auth_result` |
| `handleAuthCreate()` | `file_create` | path, decision, rule |
| `handleAuthUnlink()` | `file_delete` | path, decision, rule, action (soft_delete if applicable) |
| `handleAuthRename()` | `file_rename` | path (source), path2 (destination), decision, rule |
| `handleNotifyClose()` | `file_write` | path, operation=close_modified. NOTIFY events have no decision/rule (use `"observed"` as decision) |

**Note:** Events may arrive at the Go server before the authorized operation completes. This is expected — events record the authorization decision, not the operation's completion.

**Event JSON format:**

```json
{
  "type": "file_event",
  "event_type": "file_open",
  "path": "/workspace/file.txt",
  "operation": "read",
  "pid": 1234,
  "session_id": "session-abc",
  "decision": "allow",
  "rule": "allow-workspace-read",
  "action": "",
  "timestamp": "2026-04-02T16:34:08Z"
}
```

For rename events, add `"path2": "/workspace/newname.txt"`.

For redirect/soft_delete, add `"action": "redirect"` or `"action": "soft_delete"`.

### 3. Swift: NOTIFY_SETATTR Support (macOS 26+)

Add `ES_EVENT_TYPE_NOTIFY_SETATTR` to the ESF subscription list, guarded for backward compatibility. On older macOS versions, SETATTR tracking is silently skipped.

**Compilation guard:** Use `#if canImport(EndpointSecurity)` combined with `if #available(macOS 26.0, *)` runtime check. The subscription call and handler are both gated so the code compiles on older SDKs that don't define the `ES_EVENT_TYPE_NOTIFY_SETATTR` symbol. If the minimum SDK is bumped to macOS 26, the `#if` guard can be removed.

Emits two event types based on the setattr fields:
- `file_chmod` — when mode bits change
- `file_chown` — when ownership changes

### 4. Swift: Redirect/Soft_Delete/Approve Actions

In `SessionPolicyCache.evaluateFile()`, the actions `redirect`, `soft_delete`, and `approve` continue to return `.deny` at the ESF level. The change is that the AUTH handler now includes the `action` field in the event sent to the Go server, enabling server-side follow-through:

- **redirect**: event carries `action: "redirect"`. Go server looks up the redirect target from the file rule and updates session guidance.
- **soft_delete**: event carries `action: "soft_delete"`. Go server logs the preservation and updates guidance.
- **approve**: event carries `action: "approve"`. Go server triggers approval flow (future scope — for now, just logged).

### 5. Go: Event Stream Handler in policysock Server

**server.go** — extend `handleConn`:

When the first message on a connection is `{"type": "event_stream_init"}`, the server:

1. Sends a single `{"status": "ok"}` response to acknowledge the init handshake
2. Enters stream mode: reads events in a loop via `json.NewDecoder(conn)` until EOF or error
3. Each decoded event is passed to the `EventHandler`
4. No further responses are written after the init ack
5. EOF triggers cleanup (log disconnection, no error)

The existing `json.NewDecoder` handles buffering correctly across the mode switch — no special handling needed.

### 6. Go: EventHandler Implementation

**New file: `internal/platform/darwin/policysock/event_handler.go`** (with `//go:build darwin` tag)

Concrete implementation of the existing `policysock.EventHandler` interface. Uses `store.EventStore.AppendEvent()` to persist events.

```go
type ESFEventHandler struct {
    store       store.EventStore  // AppendEvent(ctx, ev) — existing interface
    cmdResolver CommandResolver   // PID → command_id lookup (new, see component 7)
    tracker     *SessionTracker   // PID → session_id (existing, same instance from policysock_darwin.go)
}
```

`HandleESFEvent(ctx, payload)`:
1. Parse JSON payload into `esfEvent` struct
2. Map `event_type` to `types.Event.Type` (file_open, file_write, etc. — direct string copy, types already defined in `internal/events/types.go`)
3. Resolve `command_id` via `cmdResolver.CommandForPID(pid)`
4. Resolve `session_id` (from payload, or fallback via `tracker.SessionForPID(pid)`)
5. Process `action` field if present (redirect → update guidance, soft_delete → update guidance)
6. Build `types.Event` and call `store.AppendEvent(ctx, ev)`

**Field mapping (ESF JSON → types.Event):**

| ESF JSON field | types.Event field |
|---------------|-------------------|
| `event_type` | `Type` |
| `path` | `Path` |
| `operation` | `Operation` |
| `pid` | `PID` |
| `session_id` | `SessionID` |
| `decision` | `Policy.Decision` |
| `rule` | `Policy.Rule` |
| `action` | `Fields["action"]` |
| `path2` | `Fields["path2"]` |
| `timestamp` | `Timestamp` |

**Fork/exit events** are also handled here — when `event_type` is `process_fork` or `process_exit`, the handler updates the `CommandResolver` mapping (see component 7) rather than storing a file event.

### 7. Go: PID→Command_ID Resolution

Extend command tracking to support reverse PID lookup:

- **Registration from exec handler:** when the Go exec handler spawns a process, register `PID → command_id` in a `sync.Map`. This is the only source of truth for the root PID→command_id mapping.
- **Registration from fork events:** the sysext forwards `process_fork` events over the event stream (NOTIFY_FORK already handled in ESFClient — add stream forwarding). The Go-side `CommandResolver` looks up the parent PID's command_id and assigns it to the child PID.
- **Cleanup from exit events:** the sysext forwards `process_exit` events (NOTIFY_EXIT). The `CommandResolver` removes the PID entry.
- **Interface:** `CommandResolver` with `RegisterCommand(pid int32, commandID string)`, `RegisterFork(parentPID, childPID int32)`, `UnregisterPID(pid int32)`, `CommandForPID(pid int32) string`.
- **Fallback:** If PID has no command association (e.g., the exec handler registration was missed, or the process predates the session), `command_id` is empty — event is still stored with session-level attribution only.

**Swift side:** `handleNotifyFork` and `handleNotifyExit` in `ESFClient.swift` already handle these events for session PID tracking. Add `sendEvent` calls to forward `process_fork` and `process_exit` events over the stream connection. These are lightweight — just `{type, event_type, pid, parent_pid, session_id, timestamp}`.

### 8. Go: Wiring in policysock_darwin.go

In `startPolicySocket()`, after creating the `SessionTracker` and `PolicyAdapter`, create the `ESFEventHandler` and wire it in:

```go
cmdResolver := policysock.NewCommandResolver()
eventHandler := policysock.NewESFEventHandler(s.eventStore, cmdResolver, tracker)
psrv.SetEventHandler(eventHandler)
```

The `CommandResolver` must also be accessible from the exec handler so it can call `RegisterCommand(pid, cmdID)` when spawning processes. Pass it via the server struct or a shared registry.

### 9. Documentation

- **Policy documentation**: document file rule actions on macOS — `allow`, `deny`, `redirect` (deny + guidance), `soft_delete` (deny + preserve), `approve` (deny + approval flow). Explain how these differ from Linux where FUSE/seccomp can intercept transparently.
- **Architecture docs**: update existing design docs to reflect the two-connection model (request-response + event stream) and the end-to-end file event flow.
- **README**: add section on macOS file I/O model and ESF limitations.

### 10. Testing

- **Go unit tests**: EventHandler parsing, PID→command_id resolution, event store integration, stream connection handling
- **Go integration test**: (a) connect to server, (b) send `event_stream_init` as first message, (c) verify `{"status":"ok"}` ack, (d) send N file events as newline-delimited JSON, (e) close connection, (f) verify all N events are in SQLite with correct session_id, command_id, decision, path
- **E2E test**: build + install + start server → create session → run commands that trigger file ops → query events → verify file_open, file_write, file_create, file_delete, file_rename events appear
- **Cross-compilation**: all new Go code needs `//go:build darwin` tags, verify `GOOS=windows go build ./...` passes
- **Backward compatibility**: verify SETATTR code compiles on pre-macOS 26 SDKs (gated by `@available`)

## Out of Scope

- Byte-level `file_read` tracking (Linux FUSE tracks individual read() calls; ESF only provides AUTH_OPEN which tells us a file was opened for reading, not individual read operations)
- Approval dialog UI for file operations (the `approve` action is logged but no UI is triggered in this scope)
- File event filtering/throttling (capture everything, filter at query time — matches Linux)
