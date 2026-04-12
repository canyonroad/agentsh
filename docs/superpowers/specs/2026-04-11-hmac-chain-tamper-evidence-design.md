# HMAC Audit Chain Tamper-Evidence Design

**Date:** 2026-04-11
**Status:** Draft (pending implementation plan)
**Related:** `docs/superpowers/specs/2026-03-30-wire-hmac-integrity-chain-design.md` (the original chain wiring)

## Goal

Make the audit log HMAC integrity chain unbroken across server processes and CLI invocations, so that any deletion of audit entries — whether mid-file, at the tail, or whole-file — is detectable. Close the latent silent-skip hole in the verify CLI. Provide a clean recovery path when chain state is legitimately lost.

## Problem statement

The current chain (wired in `2026-03-30-wire-hmac-integrity-chain-design.md` and shipped in v0.18.0) keeps chain state in memory only. Each server process starts at `sequence=0, prev_hash=""` and appends to the existing audit log file. Because v0.18.0's auto-start behavior (#204) spawns a fresh server process per CLI invocation when none is running, chain resets show up in audit logs at every `session_created` event — but the resets are actually one per server process, not one per session.

This produces three concrete problems:

1. **False positives in `agentsh audit verify`.** The verify CLI walks the file linearly and reports "chain broken" at every reset, even though the resets are not tampering.
2. **Real tamper-evidence weakness.** An attacker who deletes a whole process-segment from the file leaves a log that verifies cleanly segment-by-segment. The chain fails to detect deletion of a segment that aligns with a process boundary.
3. **Latent silent-skip hole.** `internal/cli/audit.go:165-168` silently skips lines whose `entry_hash` is empty. An attacker who appends an unsigned line is invisible to verify in default mode.

There's also a latent bug in the interaction between chain wrapping and audit log file rotation: `rotateIfNeededLocked` runs inside `WriteRaw`, which is called by `IntegrityStore.AppendEvent` after the chain has already wrapped the event. The wrapped event's `prev_hash` points to a hash in the *old* file but lands in the *new* file. With the current single-file verify, this manifests as a chain break at every rotation boundary.

## Decisions

These were settled during brainstorming (2026-04-11 session). They drive everything in this spec:

| Decision | Choice | Rationale |
|---|---|---|
| **Threat model** | Strong: chain unbroken across processes; deletions detectable | The user explicitly chose the strongest guarantee |
| **Sidecar loss handling** | Auto-rotate with loud `integrity_chain_rotated{reason: sidecar_missing}` event | Refusing to start would lock dev users out; auto-rotate preserves operability while making the discontinuity conspicuous in the log |
| **Chain unit** | Spans audit log file rotations (one logical chain per installation) | Strong threat model requires detecting whole-file deletion. Per-file chains can't do that. Spanning is also simpler — chain doesn't need to know files exist. |
| **Backwards compatibility with v0.18.0 logs** | None. Refuse to start; operator runs `agentsh audit chain reset --legacy-archive` | Cleanest implementation; no legacy code in the verify hot path |
| **Sidecar mismatch on startup** | Refuse to start (NOT auto-rotate) | A sidecar/log mismatch is unambiguous tampering evidence, not benign disk loss |
| **Default verify strict mode** | ON. Unsigned lines are errors. | Closes the latent silent-skip hole |

## Architecture

The HMAC integrity chain becomes a logical layer above storage that maintains continuity across server processes via a sidecar state file. The audit log is treated as one continuous stream regardless of how it's split across rotated files. The chain only resets at explicit, conspicuous boundaries — fresh install, sidecar loss (auto-rotate), and operator-driven reset.

### Components

1. **`IntegrityChain`** (`internal/audit/integrity.go`, mostly unchanged) — in-memory `{sequence, prev_hash, key}`. Wraps each event with sequence + hash.
2. **Chain sidecar** (new) — a file at `<audit log path>.chain` holding `{format_version, sequence, prev_hash, key_fingerprint, updated_at}`. Atomically rewritten after each successful audit append. Acts as the external truth for chain state across process restarts.
3. **Format version field** (new) — each integrity entry gets `format_version: 2` in its integrity envelope. Distinguishes new-format entries from legacy v0.18.0 entries during startup detection.
4. **Startup detection logic** (new, in `IntegrityStore` constructor) — decides between resume / fresh-install / auto-rotate / refuse-to-start based on sidecar presence and last-line format version.
5. **`agentsh audit chain reset`** (new CLI subcommand under a new `chain` group) — operator escape hatch for legacy archives, post-tamper recovery, and key rotation acknowledgment.
6. **Verify CLI rewrite** (`internal/cli/audit.go:135-208`) — discovers all files in the rotation set, walks them oldest-first as one continuous stream, allows chain resets only at rotation events.
7. **Strict mode in verify** (default ON) — rejects unsigned lines (closes the latent skip hole at `audit.go:165-168`).

### Key insight

Option A (chain spans rotations) means the `IntegrityStore` needs **zero awareness** of file rotation. The chain just keeps wrapping events with `seq++` and the underlying JSONL store rotates independently. The chain and storage are decoupled. This silently fixes the existing latent rotation bug.

## Data structures and on-disk formats

### Chain sidecar file

Path: `<audit log path>.chain` (e.g., `/var/lib/agentsh/audit.jsonl.chain`).

Permissions: `0o600` (matches the threat model — sidecar contents must not be world-readable because key fingerprint and chain state could aid an attacker who already has read access).

Format: single-line JSON, atomically replaced via write-temp-then-rename + fsync of both file and parent directory.

```json
{
  "format_version": 2,
  "sequence": 18934,
  "prev_hash": "a1b2c3d4...",
  "key_fingerprint": "sha256:9f8e7d6c...",
  "updated_at": "2026-04-11T14:32:18.443Z"
}
```

Field meanings:
- `format_version` — schema version of the sidecar itself; lets us evolve later without ambiguity
- `sequence` — last successfully written entry's sequence number
- `prev_hash` — last successfully written entry's `entry_hash` (the value the next entry will chain back to)
- `key_fingerprint` — `sha256:` prefix + first 16 bytes (32 hex chars) of `SHA-256(key)`; lets startup detect "wrong key for this chain"
- `updated_at` — informational; not load-bearing for security

### Format version field on each integrity entry

Existing v0.18.0 integrity envelope:
```json
{ "sequence": 5, "prev_hash": "...", "entry_hash": "..." }
```

New v2 envelope:
```json
{ "format_version": 2, "sequence": 5, "prev_hash": "...", "entry_hash": "..." }
```

`format_version` is part of the canonical payload that gets HMAC'd, so tampering with it produces a hash mismatch. Cost: ~20 bytes per entry.

### Rotation event schema

When the chain rotates (sidecar lost, manual reset, fresh install), the IntegrityStore writes a special event into the audit log as the *first* entry of the new chain:

```json
{
  "type": "integrity_chain_rotated",
  "timestamp": "2026-04-11T14:32:18.443Z",
  "reason": "sidecar lost during disk full incident",
  "reason_code": "sidecar_missing",
  "prior_chain_summary": {
    "last_sequence_seen_in_log": 18934,
    "last_entry_hash_seen_in_log": "a1b2c3d4...",
    "audit_log_size_bytes": 87421056,
    "format_version_seen": 2
  },
  "new_chain": {
    "format_version": 2,
    "sequence": 0,
    "key_fingerprint": "sha256:9f8e7d6c..."
  },
  "integrity": {
    "format_version": 2,
    "sequence": 0,
    "prev_hash": "",
    "entry_hash": "<hash of this event under the current key>"
  }
}
```

`reason_code` is a closed enum: `initial`, `sidecar_missing`, `sidecar_corrupt`, `key_rotated`, `manual_reset`, `legacy_archived`, `post_tamper_recovery`.

`reason` is free-form text (operator-supplied for manual resets, system-generated for auto-rotates).

`prior_chain_summary` is forensic — captures whatever could be read from the existing log (if any) at rotation time. It's data, not chain-load-bearing. If an attacker tampered with the log between rotations, the summary captures the tampered state, which is itself useful for incident response.

The rotation event itself is the FIRST entry of the new chain, so `integrity.sequence = 0` and `integrity.prev_hash = ""`. Verify recognizes this pattern: a `prev_hash = ""` entry is only valid if it's the very first line of the entire walk OR it's an `integrity_chain_rotated` event.

## Startup decision tree

When `IntegrityStore` is constructed at server startup, it walks this decision tree before accepting any writes. This is the only place where chain reset / refuse-to-start / fresh-install decisions get made.

```
START

├─ Read sidecar at <audit log path>.chain
│
├─ Sidecar exists & parses cleanly?
│   │
│   ├─ YES:
│   │   │
│   │   ├─ Validate key_fingerprint matches current key
│   │   │   │
│   │   │   ├─ MATCH:
│   │   │   │   │
│   │   │   │   ├─ Walk rotation set in age order (active file first,
│   │   │   │   │  then .1, .2, .3, ...) and read the last line of the
│   │   │   │   │  first file with content. The active file may be empty
│   │   │   │   │  for a brief window after a rotation but before the
│   │   │   │   │  next write — in that case the chain state lives in
│   │   │   │   │  the most recent backup.
│   │   │   │   │
│   │   │   │   ├─ Any file in the rotation set has content?
│   │   │   │   │   │
│   │   │   │   │   ├─ NO: Sidecar says seq=N but the entire rotation set
│   │   │   │   │   │        is empty/missing.
│   │   │   │   │   │        → Tampering (whole rotation set deleted or
│   │   │   │   │   │          truncated).
│   │   │   │   │   │        → REFUSE TO START with clear error pointing
│   │   │   │   │   │          at `agentsh audit chain reset`.
│   │   │   │   │   │
│   │   │   │   │   └─ YES: Compare sidecar to that last line:
│   │   │   │   │            │
│   │   │   │   │            ├─ sidecar.seq == last.seq
│   │   │   │   │            │  AND sidecar.prev_hash == last.entry_hash
│   │   │   │   │            │  → ✅ RESUME normally. (If the match was
│   │   │   │   │            │    against a backup because the active file
│   │   │   │   │            │    is empty post-rotation, the next write
│   │   │   │   │            │    goes into the active file with seq=N+1
│   │   │   │   │            │    — the chain spans the rotation.)
│   │   │   │   │            │
│   │   │   │   │            ├─ sidecar.seq + 1 == last.seq
│   │   │   │   │            │  AND last.prev_hash == sidecar.prev_hash
│   │   │   │   │            │  AND last verifies under current key
│   │   │   │   │            │  → ✅ RECOVERABLE CRASH: advance sidecar to
│   │   │   │   │            │    last, log warning, resume
│   │   │   │   │            │
│   │   │   │   │            └─ Anything else
│   │   │   │   │               → Tampering. REFUSE TO START with clear
│   │   │   │   │                 error pointing at
│   │   │   │   │                 `agentsh audit chain reset`.
│   │   │   │
│   │   │   └─ MISMATCH: Sidecar was written with a different key.
│   │   │       → REFUSE TO START with "key fingerprint mismatch" error
│   │   │         pointing at `agentsh audit chain reset --reason-code key_rotated`
│
│   └─ NO (sidecar missing or unparseable):
│       │
│       ├─ Walk rotation set in age order (active file first, then
│       │  .1, .2, .3, ...) and read the last line of the first file
│       │  with content.
│       │
│       ├─ Any file in the rotation set has content?
│       │   │
│       │   ├─ NO: Fresh install (or both sidecar and rotation set absent)
│       │   │     → Write integrity_chain_rotated{reason_code: initial} as the
│       │   │       very first entry. Create sidecar. ✅ START.
│       │   │
│       │   └─ YES: Pre-existing chain content but no sidecar.
│       │           Inspect that last line:
│       │           │
│       │           ├─ Last line malformed JSON
│       │           │   → REFUSE TO START with "audit log corrupted at last line"
│       │           │     error pointing at chain reset.
│       │           │
│       │           ├─ Last line has integrity.format_version >= 2 AND HMAC verifies
│       │           │   → New-format log whose sidecar got lost mid-operation.
│       │           │   → AUTO-ROTATE with reason_code=sidecar_missing
│       │           │
│       │           ├─ Last line has integrity.format_version >= 2 AND HMAC FAILS
│       │           │   → Tampering: format claims v2 but signature doesn't verify.
│       │           │   → REFUSE TO START with clear error.
│       │           │
│       │           └─ Last line has format_version < 2 OR no format_version field
│       │               → Legacy v0.18.0 log detected.
│       │               → REFUSE TO START with "legacy audit log detected" error
│       │                 pointing at `agentsh audit chain reset --legacy-archive`
END
```

### What "auto-rotate" means concretely

Only one scenario fires it at startup: `sidecar_missing` (the audit log has new-format content but no sidecar exists alongside it, so we can't pick up where the previous chain left off). All other "something looks wrong" cases refuse to start instead, since under the strong threat model an unexplained discrepancy is treated as evidence of tampering. (Operators can also fire a rotation manually via `agentsh audit chain reset` — that path uses other reason codes like `key_rotated` or `manual_reset`.)

The rotate flow:
1. Construct a `prior_chain_summary` from whatever can be read (last-line hash if file non-empty, else null; current file size; etc.)
2. Construct an `integrity_chain_rotated` event with the appropriate `reason_code` and a system-generated `reason` text
3. Wrap it under a fresh chain (`sequence=0, prev_hash=""`) — this is the first entry of the new chain
4. Append it to the audit log via the underlying JSONL store
5. Atomically write a fresh sidecar with `{seq=0, prev_hash=<that event's entry_hash>, key_fingerprint, format_version=2}`
6. Continue startup normally — subsequent events get `sequence=1, 2, 3, ...`

### What "refuse to start" means concretely

The `IntegrityStore` constructor returns an error. The server startup path catches this and refuses to accept any sandbox sessions, printing a multi-line message to stderr. Example for sidecar/log mismatch:

```
agentsh: refusing to start — audit chain integrity check failed

Reason: Last entry in audit.jsonl does not match sidecar
        (sidecar says sequence=18934, prev_hash=a1b2...,
         but last line has sequence=18901, prev_hash=ff03...)

This means either:
  - The audit log was tampered with (entries were modified or deleted), OR
  - The audit log was rolled back to an older state from a backup

To investigate: examine /var/lib/agentsh/audit.jsonl

To recover (this preserves the existing log for forensic review):
  agentsh audit chain reset --reason "<your explanation>"

For more information: agentsh audit chain --help
```

## Write path

### Per-event sequence

Each call to `IntegrityStore.AppendEvent`:

```
1. Acquire chain mutex
2. chain.Wrap(payload) → produces wrapped bytes + new state {seq=N, prev_hash=H}
                         (if write fails, chain.Restore() rolls back)
3. underlying.WriteRaw(wrapped)
   ├─ may trigger rotateIfNeededLocked() — chain doesn't care
   ├─ on success: line is durably on disk
   └─ on failure (non-PartialWriteError):
       a. chain.Restore(prev state)
       b. return error (no sidecar update)
4. Atomically write sidecar to <audit log>.chain.tmp
   a. Marshal {format_version: 2, seq: N, prev_hash: H, key_fingerprint, updated_at}
   b. os.WriteFile(<sidecar>.tmp, ..., 0o600)
   c. file.Sync() — fsync the temp file
   d. os.Rename(.tmp, sidecar)
   e. dir.Sync() — fsync the parent directory so the rename is durable
5. Release chain mutex
```

### Order matters: log line first, then sidecar

Reasoning: if a crash happens between steps 3 and 4, on next startup the log is one entry ahead of the sidecar. That's a *recoverable* state (see "recoverable crash" branch in the startup decision tree). The opposite ordering (sidecar then log) would leave the sidecar ahead of reality, which is harder to reconcile because we'd need to roll the sidecar back without knowing what the previous state was.

### Sidecar write failure is fatal to the current process

If step 4 fails after step 3 succeeds, we have a line on disk that the sidecar doesn't yet know about. The current process cannot write any more events (it would compound the gap). The IntegrityStore returns an error from `AppendEvent`, the server logs a critical error, and the server shuts down. The next process restart goes through the startup decision tree, which accepts a one-entry gap as a recoverable crash.

### Audit log file rotation handling

Already handled by being decoupled. The chain writes to whatever file the JSONL store currently points at; rotation inside `rotateIfNeededLocked` is invisible to the chain. The sidecar references sequence/hash, not a file path, so it stays valid across rotations.

When `WriteRaw` rotates the file mid-call, the wrapped event whose chain hash was already computed against the previous line's hash gets written into the new file. Verify handles this by walking the rotation set in age order, treating the chain as continuous across file boundaries.

### Crash recovery — the "+1 ahead" rule

```
sidecar.seq == log.last.seq AND sidecar.prev_hash == log.last.entry_hash
  → ✅ Clean state. Resume.

sidecar.seq + 1 == log.last.seq
  AND log.last.prev_hash == sidecar.prev_hash
  AND log.last verifies under current key (recompute HMAC, compare)
  → ✅ Recoverable crash mid-write. Advance sidecar to
     {seq: log.last.seq, prev_hash: log.last.entry_hash}, log a warning
     "recovered from crash mid-append at seq=N", continue.

Anything else
  → ❌ Tampering. Refuse to start.
```

The "+1 recovery" rule has one constraint: the new line must HMAC-verify against the current key, AND its `prev_hash` must equal the sidecar's `prev_hash`. An attacker can't fabricate a recoverable-crash state without forging an HMAC, which they can't do without the key.

### Performance cost

Sidecar update is 2 fsyncs per audit event (file + parent dir). On commodity SSDs that's ~100µs each, so ~200µs per event. Audit events are not high-frequency in agentsh (sandbox sessions emit events on file/network/exec activity, not in tight loops), so a 200µs overhead is acceptable.

If a future hot path makes this matter, we can add an opt-in `audit.integrity.sidecar_sync: false` config that fsyncs only periodically, with the obvious tamper-evidence weakening at the recovery boundary. Not in v1.

## Verify CLI rules

This is the rewrite of `verifyIntegrityChain` at `internal/cli/audit.go:135-208`.

### File discovery

Given a path argument (e.g., `agentsh audit verify /var/lib/agentsh/audit.jsonl`):

1. Discover rotation siblings: glob `<path>`, `<path>.1`, `<path>.2`, ..., `<path>.<N>` for any N that exists. Stop at the first missing N.
2. Order them oldest-first by suffix number descending (`.3`, `.2`, `.1`, then the bare path).
3. Treat the resulting ordered list as one logical stream.

If only the bare path exists (no rotation has happened yet), the list is just `[<path>]`.

### Per-line validation

Walk the stream line by line, maintaining state `{expected_seq, expected_prev_hash, key, format_seen, oldest_file_first_line}`. Initial state: `{expected_seq: 0, expected_prev_hash: "", key: <from config>, format_seen: false, oldest_file_first_line: true}`.

For each line:

1. **Parse JSON.** Malformed → error and stop. No "skip and continue."
2. **Extract integrity envelope.** If missing entirely:
   - In `--strict` mode (default): error "unsigned line at <file>:<lineno>", stop.
   - In `--tolerate-unsigned` mode: warn, skip the line, do NOT advance state.
3. **Check format_version.** If missing or `< 2`: error "legacy-format entry at <file>:<lineno> — use v0.18.0 verify or archive and reset". Stop.
4. **Check sequence.** Must equal `expected_seq` UNLESS this is `oldest_file_first_line` AND the file is a backup (`.1`, `.2`, etc., not the bare current file). In that case, accept any sequence as the rolled-off-origin start point. After this line, set `oldest_file_first_line = false`.
5. **Check prev_hash.** Two valid cases:
   - **Normal case:** `prev_hash == expected_prev_hash`. Continue.
   - **Chain origin / rotation case:** `prev_hash == ""` AND `seq == 0` AND **either**:
     - This is the very first line of the very first file in the rotation set (true chain origin), **OR**
     - This line is an `integrity_chain_rotated` event (post-rotation reset)
   - Anything else: error "chain broken at <file>:<lineno> (expected prev=<X>, got <Y>)". Stop.
6. **Recompute HMAC** of the canonical payload using the configured key. Compare to `entry_hash`. If not equal: error "hash mismatch at <file>:<lineno> — entry was modified after writing". Stop.
7. **Update state:** `expected_seq = seq + 1`, `expected_prev_hash = entry_hash`, `format_seen = true`.

### Special handling for the rolled-off origin

If the rotation set's oldest file is a backup (`.1`–`.3`) and does NOT start at `seq=0`, that means the original chain origin has rolled off the back of the rotation window. This is normal data retention, not tampering.

In that case, the very first line of the oldest file is allowed to start at any sequence with any `prev_hash`, as long as it parses and HMAC-verifies. The output explicitly notes the gap:

```
verified entries 12048..18934 (6,887 entries across 4 files)
note: chain origin (entries 0..12047) has rolled off the rotation
window and cannot be verified
```

This behavior only triggers when the oldest file is a backup. If the bare current file starts at non-zero with no rotation event, that's still tampering.

### Output

Success:
```
✅ verified 6,887 entries across 4 files
   first: seq=12048 (audit.jsonl.3, line 1)
   last:  seq=18934 (audit.jsonl, line 4382)
   chain rotations encountered: 2
     - seq=12048 reason="initial" (rolled-off origin assumed)
     - seq=15103 reason="sidecar_missing" at audit.jsonl.2:847
```

Failure:
```
❌ chain broken at audit.jsonl:1832
   expected prev_hash: 9f8e7d6c...
   got prev_hash:      00000000...
   sequence:           17221
   verified up to:     seq=17220 (1822 lines into audit.jsonl)
```

Exit code 0 on success, non-zero on any failure.

### Flags

- `--strict` (default) — explicit, no behavior change
- `--tolerate-unsigned` — accept lines without integrity envelope (warn, skip, do not advance state)
- `--from-sequence N` — start verification from sequence N instead of the chain origin (debugging large logs)
- `--tolerate-truncation` — accept a truncated last line as the end of the chain (off by default; default is to error on truncated last line)
- `--legacy` — **not added.** No backwards compat for v0.18.0 logs.

The latent skip-unsigned hole at the current `audit.go:165-168` gets closed: silent skipping is no longer a thing in default mode.

### Edge cases

- **Truncated last line** (file ends mid-JSON): default mode errors. With `--tolerate-truncation`, accept and treat the chain as ending at the last fully-parsed line.
- **Multiple consecutive rotation events**: allowed.
- **Empty file**: nothing to verify. Exit 0 with "no entries to verify".
- **Missing intermediate rotation siblings** (`.3` exists, `.2` doesn't): error "missing audit log file <path>.2 — rotation set is incomplete". Catches the "attacker deleted a whole backup file" case.

## Reset CLI command

New subcommand under a new `agentsh audit chain` group.

### Subcommand structure

```
agentsh audit chain reset --reason <text> [flags]

Required:
  --reason <text>      Free-form text explaining why the reset is happening.
                       Stored in the integrity_chain_rotated event for the
                       audit trail. Required — no default. Cannot be empty.

Optional:
  --legacy-archive     Archive the existing audit log to
                       audit.jsonl.legacy.<timestamp> before starting fresh.
                       Use this when upgrading from v0.18.0 or any pre-v2 log.
                       Without this flag, the existing log is preserved in
                       place and the new chain appends to it (rotation event
                       in the middle).

  --force              Skip the confirmation prompt. For scripting.

  --reason-code <enum> Optional structured reason code from a closed set:
                       sidecar_missing, sidecar_corrupt, key_rotated,
                       legacy_archived, manual_reset, post_tamper_recovery.
                       Stored alongside the free-form reason.
```

### Default flow

1. **Acquire exclusive lock** (flock) on the audit log file. If a server is running and holds the lock, refuse with "agentsh server is running; stop it before resetting the chain".
2. **Confirmation prompt** (skipped with `--force`):
   ```
   This will reset the audit integrity chain.

   Existing audit log:
     /var/lib/agentsh/audit.jsonl  (87 MB, 18,934 entries)

   The existing log will be PRESERVED. A new integrity_chain_rotated event
   will be appended marking the boundary, and the chain will continue from
   that point with a fresh sequence starting at 0.

   Reason given: "sidecar lost during disk full incident, recovered from backup"

   Continue? [y/N]
   ```
3. **Capture prior chain summary** by reading the last line of the audit log (if any). Extract `last_sequence`, `last_entry_hash`, `format_version`. Empty log → null summary.
4. **Construct the rotation event** with the operator's reason, the prior summary, and the new chain's first state (`seq=0, prev_hash=""`).
5. **Wrap and append** the rotation event via the same JSONL store the server uses. The event becomes the first entry of the new chain.
6. **Atomically write a fresh sidecar** with `{format_version: 2, seq: 0, prev_hash: <rotation event's entry_hash>, key_fingerprint, updated_at: now}`.
7. **Release the lock.** Print confirmation.

### `--legacy-archive` flow

Used when upgrading from v0.18.0:

1. Acquire lock as above.
2. Confirmation prompt explicitly mentions archiving:
   ```
   This will RENAME the existing audit log to a legacy archive and
   start a fresh log. The renamed file will NOT be appended to.

   Existing audit log:
     /var/lib/agentsh/audit.jsonl  (45 MB, 9,213 entries)

   Will be archived to:
     /var/lib/agentsh/audit.jsonl.legacy.20260411T143218Z

   Reason given: "upgrading from v0.18.0"

   Continue? [y/N]
   ```
3. `os.Rename(audit.jsonl, audit.jsonl.legacy.<RFC3339>)` — atomic, preserves the old data exactly.
4. Construct the rotation event with `reason_code: legacy_archived` and a `prior_log_archived_to: <path>` field in addition to whatever summary we could extract.
5. Append the rotation event to the (now empty) `audit.jsonl`.
6. Write fresh sidecar.
7. Release lock. Confirmation includes the archive path.

### Companion subcommands

While we're adding the `chain` group, two read-only subcommands round it out:

- `agentsh audit chain status` — read sidecar, print `{format_version, seq, prev_hash, key_fingerprint, updated_at}`. Read-only, no lock.
- `agentsh audit chain verify` — alias for `agentsh audit verify` that defaults to walking the rotation set.

### Out of scope

- Does not delete or truncate the existing log
- Does not start the server
- Does not validate the existing log (verify's job)
- Does not rotate the HMAC key (separate config change; reset just acknowledges that the key has changed)

## Error handling

### Cross-cutting cases

- **Integrity disabled in config:** None of this code runs. The IntegrityStore is not constructed; the JSONL store is used directly. Verify CLI prints "integrity not enabled in this log; nothing to verify" and exits 0.
- **KMS provider failure during construction:** The server refuses to start with a clear error pointing at the key provider config. No fallback to "no integrity" — that would be a silent downgrade.
- **Disk full during sidecar write:** Step 4 of the write path fails. IntegrityStore returns a fatal error; server logs critical and shuts down. Next startup recovers via the +1 branch.
- **Disk full during audit log write:** `WriteRaw` returns an error. Chain rollback fires (existing behavior in `integrity_wrapper.go:53-59`). Sidecar untouched. State consistent.
- **NFS or non-atomic filesystems:** Documented as unsupported. The audit log directory must be on a POSIX-compliant local filesystem. If a real NFS use case appears, add a flock-based fallback later.
- **Concurrent server processes:** Existing server already enforces single-instance via flock. The chain relies on this — it does NOT add its own locking on the sidecar.
- **Permission errors on sidecar:** Sidecar created at `0o600`. External permission tampering is filesystem-level, out of scope.
- **Key fingerprint computation:** `sha256:` prefix + first 16 bytes (32 hex chars) of `SHA-256(key bytes)`. Deterministic. Computed once at chain construction.

## Test plan

### Chain core (unit tests on `IntegrityChain`)

- Happy path: 100 sequential `Wrap` calls produce correct sequences and prev_hash chains
- Single-entry chain: `Wrap` once, verify state
- `Wrap` with empty payload (must still produce a valid hash)
- `Wrap` with very large payload (1 MB+) — confirms canonicalization has no size limit
- `Wrap` with payload containing NUL bytes
- `Wrap` with payload containing every Unicode codepoint we can serialize
- `Restore` rolls back state correctly
- `Restore` to an earlier state, then re-`Wrap`, produces a different chain than the original
- Concurrent `Wrap` calls under mutex serialize correctly
- Sequence overflow at `int64 max` — explicit error, not silent wrap
- `key_fingerprint` is deterministic for the same key bytes
- `key_fingerprint` changes if any byte of the key changes
- HMAC verification: correct key passes, wrong key fails
- HMAC verification: a single bit-flip in the entry produces a hash mismatch

### Sidecar serialization (unit tests on the new sidecar reader/writer)

- Round-trip: write → read → struct equal
- Atomic write succeeds: temp file gone, target file present, content correct
- Atomic write under simulated rename failure: temp file cleaned up, error returned
- Atomic write under simulated fsync failure: error returned, no half-written state
- Parse rejection: malformed JSON
- Parse rejection: missing `format_version`
- Parse rejection: missing `sequence`
- Parse rejection: missing `prev_hash`
- Parse rejection: missing `key_fingerprint`
- Parse rejection: `format_version` is a string instead of a number
- Parse rejection: `sequence` is negative
- Parse rejection: `prev_hash` is not a hex string
- Forward compat: `format_version` higher than current → clear error, not silent acceptance
- Forward compat: unknown additional fields → preserved on read but ignored
- Sidecar with permissions other than `0o600` is still readable
- Sidecar at zero bytes (truncated) → parse error
- Sidecar partially zeroed (filesystem corruption) → parse error
- Read sidecar from a path that doesn't exist → returns "not found" sentinel, not generic error

### Startup decision tree (one test per leaf)

State setup helpers create the (sidecar, audit.jsonl) pair, then construct the IntegrityStore and assert the outcome.

- **Sidecar present, key matches, active file empty, no backups** → tampering (whole rotation set deleted), refuse
- **Sidecar present, key matches, active file empty, most recent backup last line matches sidecar** → resume cleanly (post-rotation startup window — next write goes to active file with seq=N+1)
- **Sidecar present, key matches, active file empty, most recent backup last line does NOT match sidecar** → tampering, refuse
- **Sidecar present, key matches, active file non-empty, last line matches sidecar** → resume cleanly
- **Sidecar present, key matches, active file last line +1 ahead, valid HMAC, prev chains correctly** → recoverable crash, sidecar advances, resume
- **Sidecar present, key matches, active file last line +1 ahead, valid HMAC, but prev_hash doesn't chain** → tampering, refuse
- **Sidecar present, key matches, active file last line +1 ahead, invalid HMAC** → tampering, refuse
- **Sidecar present, key matches, active file last line two or more ahead** → tampering, refuse
- **Sidecar present, key matches, active file last line one BEHIND sidecar** → tampering, refuse
- **Sidecar present, key matches, active file last line equal sequence but different hash** → tampering, refuse
- **Sidecar present, key fingerprint mismatch** → refuse with "key rotated" error
- **Sidecar present but malformed JSON** → treated as sidecar missing → fall through
- **Sidecar missing, entire rotation set empty/missing** → fresh install, write `integrity_chain_rotated{reason_code: initial}`
- **Sidecar missing, active file non-empty, last line v2 format with valid HMAC** → auto-rotate `sidecar_missing`
- **Sidecar missing, active file empty, most recent backup non-empty with valid v2 HMAC** → auto-rotate `sidecar_missing` (post-rotation startup with no sidecar)
- **Sidecar missing, log non-empty, last line v2 format with INVALID HMAC** → refuse (don't auto-rotate over a corrupted log)
- **Sidecar missing, log non-empty, last line v1/legacy format** → refuse with "legacy log detected"
- **Sidecar missing, log non-empty, last line malformed JSON** → refuse with "audit log corrupted at last line"
- **Sidecar present, active file does not exist and no backups** → tampering (whole rotation set deleted), refuse

### Write path (integration tests on `IntegrityStore.AppendEvent`)

- 1000 sequential events, sidecar matches log last line at every step
- Concurrent calls under mutex produce strictly increasing sequences with no gaps
- WriteRaw fails (disk full simulated) → chain rolled back, sidecar untouched, error returned
- Sidecar write fails (disk full simulated) → fatal error returned, log line still durable
- After fatal sidecar failure, fresh process recovers via "+1 ahead" branch
- Audit log rotation fires mid-stream → chain unaffected, sidecar still matches
- Audit log rotation fires exactly at the line being written → line lands in new file, chain still correct, sidecar correct

### Chain spans rotations

- Write enough events to trigger 1 rotation, verify chain hashes link from `audit.jsonl.1` to `audit.jsonl`
- Write enough events to trigger 3 rotations, verify chain links across all 4 files
- Write enough events to trigger 4+ rotations (oldest backup dropped), verify the chain still verifies from whatever the oldest available file's start is
- **Post-rotation startup window:** Trigger a rotation so the active file is newly empty, then close the store WITHOUT writing the next event (simulating a crash in the rotation window). Reopen the store. The decision tree should walk past the empty active file, find the matching last entry in `.1`, and resume cleanly. Then write a new event and assert it lands in the active file with `seq = N+1`, chaining correctly to the entry in `.1`.
- **Post-rotation startup window with sidecar one behind:** Same as above but with the sidecar lagging one entry behind the last line of `.1` (simulating a crash mid-write before rotation). Should trigger the recoverable-crash branch, advance the sidecar, and resume.
- Verify CLI walks `.3, .2, .1, audit.jsonl` in correct order
- Verify CLI handles a missing intermediate backup → reports "rotation set incomplete"
- Verify CLI handles `.3` starting at non-zero sequence (rolled-off origin) → accepts and reports the gap

### Verify CLI — chain attack scenarios

These directly test that the verifier catches the tampering patterns the threat model promises:

- **Mid-file deletion:** Delete a single line. Verify reports "chain broken" at the line after the deletion.
- **Last-line deletion:** Delete the last line. Sidecar mismatch on next startup catches it. Standalone verify (no sidecar) reports "verified up to N" but cannot detect.
- **Range deletion (10 contiguous lines):** Verify reports "chain broken" at the line after the gap.
- **Whole backup file deletion:** Delete `audit.jsonl.2`. Verify reports "rotation set incomplete." Sidecar/log mismatch on next startup also catches it.
- **In-place mutation of a JSON value field:** Verify reports "hash mismatch."
- **In-place mutation of integrity.entry_hash:** Verify reports "hash mismatch" (recomputed hash doesn't match stored).
- **In-place mutation of integrity.sequence:** Verify reports "sequence mismatch."
- **In-place mutation of integrity.prev_hash:** Verify reports "chain broken."
- **Line swap:** Swap two adjacent lines. Verify reports "chain broken" at the second.
- **Duplicate line:** Verify reports "sequence mismatch" at the duplicate.
- **Inserted line with no integrity envelope:** Strict mode → error. Tolerate mode → warn, chain still verifies.
- **Inserted line with forged integrity envelope (random hash):** Verify reports "hash mismatch."
- **Inserted line with copied integrity envelope from elsewhere:** Verify reports "sequence mismatch" or "chain broken."
- **Whole file replaced with a smaller, valid-looking file (truncation to a previous backup):** Sidecar/log mismatch catches on startup. Standalone verify cannot. Test confirms the sidecar comparison is the load-bearing check.
- **Sidecar replaced with an older sidecar from a backup:** If exactly one behind, recovery applies (false positive); otherwise refuse. Known limitation of the +1 recovery rule. Test confirms behavior matches spec.
- **Both sidecar AND log replaced with consistent older versions (rollback attack):** Cannot be detected without external state. Documented limitation. Test confirms verifier doesn't crash.

### Verify CLI — degenerate inputs

- Empty rotation set → exit 0 with "no entries"
- Single empty file → exit 0 with "no entries"
- Single file with one entry → verifies
- Single file with one entry that's a rotation event → verifies
- Multi-file with rotation event as the very last line of one file and the chain continuing in the next file → verifies
- Multi-file with two consecutive rotation events (end of one file, start of next) → verifies
- Line with `integrity` set to `null` → "unsigned line" in strict mode
- Line with `integrity` set to `{}` → "missing integrity fields" error
- Line with `integrity.entry_hash = ""` → "missing entry_hash" error in strict mode
- File ending in `\n` vs file ending without `\n` → both verify identically
- File with CRLF line endings → verify (or explicit error if we don't support them)
- File with a line longer than `bufio.Scanner` default buffer → verify with custom larger buffer

### Reset CLI

- `agentsh audit chain reset --reason "x"` on a clean log → appends rotation event, creates sidecar, exits 0
- `agentsh audit chain reset` (no `--reason`) → exits non-zero with "reason required"
- `agentsh audit chain reset --reason ""` → exits non-zero with "reason cannot be empty"
- `agentsh audit chain reset --reason "x"` while server is running → exits non-zero with "stop server first"
- `agentsh audit chain reset --reason "x"` with no existing log → creates fresh log with rotation event
- `agentsh audit chain reset --reason "x"` with existing v2 log → preserves log, appends rotation event in place
- `agentsh audit chain reset --reason "x" --legacy-archive` with existing log → renames log to `.legacy.<ts>`, starts fresh
- `agentsh audit chain reset --reason "x" --legacy-archive --force` → skips prompt
- `agentsh audit chain reset --reason "x"` interactive prompt → answering "n" leaves state unchanged
- `agentsh audit chain reset --reason "x"` interactive prompt → answering "y" proceeds
- After reset, `verify` runs against the new chain and succeeds
- After reset, the rotation event captures the prior chain summary correctly

### Property-based / fuzz tests

- **Random mutation fuzz:** Take a known-good chain of N entries. For each iteration, mutate the file randomly (delete a byte, flip a bit, delete a line, swap lines, insert a line, truncate). Verify must EITHER report a clear error OR the mutation was a no-op (e.g., removing trailing newline). No silent acceptance.
- **Random valid input fuzz:** Generate random `(payload, key)` pairs, write a chain, read it back, verify. No false negatives.

### Concurrency tests

- Two goroutines call `AppendEvent` 1000 times each → all 2000 entries present, sequences strictly monotonic, no duplicates
- One goroutine appends while another reads the sidecar → sidecar reads always return a self-consistent state (not torn)
- One goroutine appends while another runs `verify` against the same files → verify either succeeds (read all entries written before it started) or fails with a clean error (race detected); never crashes

### End-to-end integration

- Start server, write 100 events, kill server, restart server, verify all 200 events are continuous (no chain reset between server processes)
- Start server, write event, kill -9 between line write and sidecar write (fault injection hook), restart, verify recovery applied and state is consistent
- Run `agentsh audit chain reset` and verify the rotation event is present and the new chain starts at seq=0
- Start with a v0.18.0-format audit log, verify server refuses to start with the legacy error
- Run `agentsh audit chain reset --legacy-archive` and verify the archive file exists and the new log starts cleanly
- Force a file rotation (write enough events to exceed `maxBytes`), verify the chain spans the rotation correctly and the verify CLI walks both files

### Performance regression

- Benchmark `IntegrityStore.AppendEvent` p50 and p99 over 10,000 events → fail CI if p50 > 500µs or p99 > 2ms
- Benchmark verify over a 100 MB log set → fail CI if > 5 seconds

### Coverage target

`go test ./internal/audit/... ./internal/store/... ./internal/cli/... -cover` should report ≥ 90% line coverage on the new sidecar code, the IntegrityStore startup path, the IntegrityStore write path, the verify CLI walk, and the reset CLI command. Coverage gaps must be either explicitly justified (e.g., unreachable error returns from stdlib) or filled.

### Non-goals (explicitly NOT tested)

- Cross-machine clock skew (timestamps are informational)
- KMS provider availability (mocked at the chain layer)
- Concurrent access from multiple machines (single-machine assumption)
- Recovery from corrupted blocks in the middle of the audit log (the chain detects it; recovery is "use the reset command")

## Migration and rollout

v0.18.0 → next-version transition:

1. User upgrades the agentsh binary
2. First `agentsh exec` (or any command that starts the server) attempts to construct the IntegrityStore
3. The startup decision tree finds the existing v0.18.0 audit log (no sidecar, last line is v1 format)
4. Server refuses to start with the "legacy log detected" message and points at `agentsh audit chain reset --legacy-archive`
5. User runs `agentsh audit chain reset --legacy-archive --reason "upgrading from v0.18.0"`
6. Old log is renamed to `audit.jsonl.legacy.<ts>`; fresh log is created with a rotation event; sidecar is created
7. User retries `agentsh exec`; server starts normally

The legacy archive file is preserved indefinitely. Operators who care about long-term audit history can verify it offline using a v0.18.0 binary kept around for that purpose. There's no migration utility — the data formats are too different to translate automatically without losing tamper-evidence semantics.

## Out-of-scope for this design

The following are deliberately deferred:

- **Off-machine chain anchoring** (shipping hashes to an external service for true rollback resistance). The current design's tamper-evidence is bounded by what can be stored locally; rollback attacks on both files simultaneously are undetectable. Off-machine anchoring would close that gap but adds significant operational complexity.
- **Automatic key rotation.** v1 expects key rotation to be a manual operator-initiated event acknowledged via `agentsh audit chain reset --reason-code key_rotated`. Automatic rotation tied to KMS key versioning is a future enhancement.
- **Multi-writer support.** The chain assumes a single writer at a time (enforced by the existing server flock). Two concurrent writers would race on the sidecar and produce inconsistent state. Multi-writer chains require a different model (e.g., distributed ordering).
- **NFS / non-POSIX filesystems.** Documented as unsupported. Future enhancement if a real use case appears.
- **Sidecar encryption.** The sidecar contains chain state but not the key itself; the key fingerprint is a one-way hash. Encryption would add complexity without a clear threat model justification.

## Open questions

None — all design decisions were settled during the brainstorming session.
