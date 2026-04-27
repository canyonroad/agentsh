# WTP Monitoring Migration

## `audit.watchtower.log_goaway_message`

**Default:** unset (resolves to `false`).

**What it does.** When `true`, the WARN log emitted on GOAWAY receipt includes the server-supplied `goaway_message` text after client-side sanitization via `sanitizeForLog` (transport implementation). The sanitizer applies these rules **in order**:

1. Replace any invalid UTF-8 sequence with U+FFFD.
2. Replace any control or non-printable rune (including `\t`, `\n`, all C0 controls) with U+FFFD. Only the literal space character and printable Unicode pass through.
3. Truncate the **sanitized** output to at most 512 bytes at a UTF-8 rune boundary, appending `...[truncated]` **within** that 512-byte budget. When truncation fires, operators see the prefix of the message followed by the `...[truncated]` marker; the total length including the marker is at most 512 bytes.

When `false` or unset, only `goaway_message_present: bool` is emitted.

**Three-state semantics.** YAML omitted, explicit `false`, and explicit `true` are distinct on the wire so a future major-version-bump default flip is auditable in startup logs.

**Server-side contract.** The Watchtower server contract at `proto/canyonroad/wtp/v1/wtp.proto` (`Goaway.message`) REQUIRES that the message field MUST NOT contain credentials, secrets, or PII. Setting `log_goaway_message: true` opts your operator log aggregator into receiving that text under the trust assumption that the server contract is enforced.

**Threat model.** Server is trusted not to leak secrets in `Goaway.message`. If the server side ever violates the contract, those values land in your log aggregator. The conservative default (`false`/unset) is recommended for any deployment where the server side is not under unified operational control.

**Reload model.** Read at transport-construction time. Changes take effect ONLY after a daemon restart.

**Verification after a flip.** Restart the daemon. Look for the startup INFO line `watchtower: log_goaway_message omitted; using default` (when unset) or the WARN line `watchtower: log_goaway_message=true; …` (when explicitly true). The transport will then honor the value.

**Default-flip migration policy.** Changing the in-code default from `false` to `true` is forbidden without a major schema version bump in the daemon config — silent flips would expose the goaway_message field to log aggregators on upgrade for any fleet that omitted the field. See spec §"`goaway_message` redaction policy" for the binding policy.

## `audit.watchtower.emit_extended_loss_reasons`

**Default:** `false`.

**What it does.** Controls whether the WTP client emits `TransportLoss` ClientMessages on the wire for the six reason values added in the 2026-04-27 spec:

- `MAPPER_FAILURE`
- `INVALID_MAPPER`
- `INVALID_TIMESTAMP`
- `INVALID_UTF8`
- `SEQUENCE_OVERFLOW`
- `ACK_REGRESSION_AFTER_GC`

When `false`, in-flight drops increment the matching `wtp_dropped_*` counter on the client and emit a structured WARN, but no marker reaches the wire — the gap appears server-side only as a missing sequence number.

When `true`, each in-flight drop also persists a `wal.LossRecord` via `wal.AppendLoss`; the carrier walks the WAL Reader and emits a `TransportLoss` ClientMessage with the matching wire reason. The receiving Watchtower can correlate gaps in the sequence stream with their cause.

**OVERFLOW and CRC_CORRUPTION are unaffected** — those values predate this spec, are part of the original wire schema, and emit unconditionally regardless of this flag.

**Migration order.** Three phases:

1. **Client lands the carrier change.** Today's fail-closed behavior on overflow / CRC becomes fail-open: `TransportLoss` frames replace session restarts. No operator action.
2. **Watchtower server ships support for the six new reason values.** Confirm with your server operator that the receiving instance has been upgraded.
3. **Operator flips `audit.watchtower.emit_extended_loss_reasons: true`** in the agent's YAML config. Restart the agent. Verify `wtp_loss_unknown_reason_total` stays at zero (non-zero indicates a client-side programming bug — file an issue).

**Rollback.** If the server-side upgrade misbehaves and the agent enters a Goaway loop, set the flag back to `false` and restart the agent. The agent reverts to counter-only drops for the six extended reasons; OVERFLOW and CRC_CORRUPTION continue to emit on the wire.

**Threat model.** The reason values carry no PII or secrets — they are bounded enum values plus the `(from_sequence, to_sequence, generation)` triple of the dropped event. The agent does not include the original event contents in the `TransportLoss` frame.

**Reload model.** Read at transport-construction time. Changes take effect ONLY after a daemon restart.

**Wire-incompatibility risk.** Strict-enum receivers reject unknown enum values per the `TRANSPORT_LOSS_REASON_UNSPECIFIED` contract (`receivers MUST reject`). Enabling this flag against a Watchtower server that has not been upgraded will trigger a Goaway → reconnect loop. Always verify server support BEFORE flipping the flag.

**Verification after a flip.** Restart the agent. Trigger a known in-flight drop (e.g., write a synthetic event with invalid UTF-8) and confirm:

1. The `wtp_dropped_invalid_utf8_total` counter increments on the client.
2. The receiving Watchtower logs a `TransportLoss` with `reason=INVALID_UTF8`.
3. The session does NOT restart (no extra `SessionInit` handshakes).

If any of these fail, set `emit_extended_loss_reasons: false`, restart, and check the daemon logs for the WARN/ERROR explaining the failure.
