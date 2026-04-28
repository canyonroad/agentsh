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

## `audit.watchtower.batch.compression`

**Default:** `none`.

**What it does.** Selects the per-batch compression algorithm the WTP transport applies to `EventBatch` payloads. Valid values:

- `none` — every `EventBatch` is sent uncompressed (`Compression: COMPRESSION_NONE`, `body: UncompressedEvents`). This is the legacy behavior and the conservative default.
- `zstd` — the marshaled `UncompressedEvents` is compressed via zstandard at the level set by `audit.watchtower.batch.zstd_level` (default 3). Wire frame is `Compression: COMPRESSION_ZSTD` + `compressed_payload`.
- `gzip` — same shape with stdlib gzip at the level set by `audit.watchtower.batch.gzip_level` (default 6).

The proto schema (`Compression` enum + `compressed_payload` oneof field) has supported `zstd` and `gzip` since the original WTP wire spec, but the transport implementation only began emitting compressed batches in this release. Receivers must understand the `compressed_payload` oneof variant to decode anything other than `none`.

**Per-batch wire contract.** `EventBatch.compression` is a per-batch field, not per-stream. A client configured for `zstd` MAY emit individual batches with `compression: COMPRESSION_NONE` if the codec returns an error for a specific batch (the client's fail-open path; see "Failure modes" below). Receivers MUST handle a stream that mixes compressed and uncompressed batches.

**Failure modes.**

- **Encoder error (rare).** If `zstd.Encode` or `gzip.Write` returns an error for a single batch, the client emits THAT batch as `Compression: COMPRESSION_NONE` + `UncompressedEvents` and increments `wtp_compress_error_total{algo}` by one. Subsequent batches still attempt compression with the same encoder; the encoder is not reset. Events are NOT lost.
- **Configured but unknown algo (programmer error).** Rejected by config validation; the daemon refuses to start.
- **Receiver-side decode failure.** A receiver's responsibility — outside the scope of this knob. The proto reserves `decompress_error` as a metrics-only `WTPInvalidFrameReason` for that path.

**Recommended setting.** Once your Watchtower receiver is confirmed to support `compressed_payload` (verify the deployed server version actually decodes it), set `compression: zstd` for the bandwidth win. zstd at level 3 is the recommended starting point.

**Wire-incompatibility risk.** Receivers that pre-date the proto's `compressed_payload` oneof field, or that have not been upgraded to decode it, will reject batches with `Compression: COMPRESSION_ZSTD` or `COMPRESSION_GZIP`. The exact failure mode depends on the receiver's strict-enum behavior — typically a Goaway with an "unrecognized compression" diagnostic, followed by an agent reconnect loop. Verify your Watchtower server version supports compressed batches BEFORE setting `compression: zstd` (or `gzip`). If you observe a reconnect loop after flipping this knob, revert to `compression: none` and restart the agent.

**Reload model.** Read at transport-construction time. Changes take effect ONLY after a daemon restart.

**Default-flip migration policy.** The default may flip from `none` to `zstd` in a future release once metrics across the fleet show clean encode behavior and server-side parity is confirmed. Such a flip would land via the major-schema-version-bump process used for other operator-visible defaults — silent flips are forbidden.

**Verification after a flip.** Restart the daemon. Confirm:

1. `wtp_batch_compression_ratio{algo}_count` is non-zero on the next scrape — the encoder ran.
2. `wtp_compress_error_total{algo}` is zero — no fail-open fallbacks.
3. The receiver decodes the batches without raising `wtp_decompress_error_total{algo, reason}` (a receiver-side metric; check your Watchtower server dashboards).

If any of (1) or (2) fail, the agent log will indicate the reason; revert to `compression: none` and restart while debugging.

## `audit.watchtower.batch.zstd_level`

**Default:** `3`.

**What it does.** Selects the zstandard compression level applied when `audit.watchtower.batch.compression: zstd`. Valid range is `1`..`22` inclusive (the canonical zstd CLI's range). The agent uses `klauspost/compress`, which internally collapses these into four speed/compression tradeoffs (fastest → best). Most operators should leave the default. Higher levels trade CPU for marginally smaller output; for OCSF event streams the diminishing returns above level 3 are typically not worth the CPU cost.

**Reload model.** Read at transport-construction time. Changes take effect ONLY after a daemon restart.

**Validation.** Out-of-range values are rejected at config validation; the daemon refuses to start. The validator's range mirrors the canonical zstd CLI's `[1,22]` bounds rather than klauspost/compress's looser internal acceptance, so operator-facing nonsense values fail loudly.

**Ignored when** `compression` is not `zstd`. The field is parsed and validated but has no runtime effect.

## `audit.watchtower.batch.gzip_level`

**Default:** `6`.

**What it does.** Selects the gzip compression level applied when `audit.watchtower.batch.compression: gzip`. Valid range is `1`..`9` inclusive (stdlib `compress/gzip` levels). The default 6 matches stdlib's `DefaultCompression` for typical balanced output.

**Reload model.** Read at transport-construction time. Changes take effect ONLY after a daemon restart.

**Validation.** Out-of-range values are rejected at config validation; the daemon refuses to start. The validator does NOT accept `-1` (stdlib's `DefaultCompression` sentinel) — operators should use the explicit numeric value the sentinel resolves to (`6`) instead.

**Ignored when** `compression` is not `gzip`.

## Compression metrics

Five new metric families surface compression behavior. All are emitted at zero on the first scrape after daemon start (always-emit contract) so dashboards have a stable schema regardless of runtime activity.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `wtp_batch_compression_ratio` | Histogram | `algo` ∈ {`zstd`, `gzip`} | Distribution of `compressed_bytes / uncompressed_bytes` per successfully-compressed batch. Buckets: 0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1.0, +Inf. Smaller is better. |
| `wtp_batch_compressed_bytes_total` | Counter | `algo` ∈ {`zstd`, `gzip`} | Total bytes emitted as `EventBatch.compressed_payload`. |
| `wtp_batch_uncompressed_bytes_total` | Counter | `algo` ∈ {`zstd`, `gzip`} | Total marshaled `UncompressedEvents` bytes pre-compression. Pairs with the row above for an aggregate ratio. |
| `wtp_compress_error_total` | Counter | `algo` ∈ {`zstd`, `gzip`} | Number of fail-open fallbacks (encoder returned an error and the batch was sent as `Compression: COMPRESSION_NONE` for that batch only). A non-zero counter is a debug signal, NOT a data-loss event. |
| `wtp_decompress_error_total` | Counter | `algo` ∈ {`zstd`, `gzip`}, `reason` ∈ {`decode_error`, `oversize`, `proto_unmarshal`} | Receiver-side decode failures by algorithm and reason. Currently name-reserved: the proto package documents `decompress_error` as a metrics-only `WTPInvalidFrameReason`, and the agent emits this family at zero (always-emit contract) for receiver compatibility. The agent itself does not currently increment this metric — production receivers in another repo are responsible for the actual counts. |

**Operator alerts.** Recommended starting points:

- Recommended threshold for `wtp_compress_error_total`: monitor the rate, not the absolute. A single transient encoder error fires the metric and emits the batch as `Compression: NONE` — that is by design and is not a data-loss event. Use a rate threshold matched to your batch volume; e.g., `rate(wtp_compress_error_total{algo=...}[10m]) > 0.01` for fleets emitting many batches per second. Sustained non-zero rates indicate a real regression worth investigating.
- Alert on `histogram_quantile(0.5, sum by (le, algo) (rate(wtp_batch_compression_ratio_bucket[5m]))) > 0.75` — if the median ratio drifts above 0.75 the codec is barely compressing; verify input shape or downgrade level.
- Track `sum(rate(wtp_batch_compressed_bytes_total[1m])) / sum(rate(wtp_batch_uncompressed_bytes_total[1m]))` for the aggregate fleet ratio.

## `wtp_session_init_failures_total{reason}`

**Status:** Live as of PR (this branch). Previously emitted at zero with no producers wired.

The agent increments this counter at every SessionInit handshake failure path in `state_connecting.go`. The reason enum is shared with `wtp_session_rotation_failures_total` (Project C — currently has no producer), so all 6 reason labels emit at zero on every scrape regardless of which producer is active.

| Reason | Fires when (SessionInit producer) |
|---|---|
| `invalid_utf8` | Reserved for chain-rotation invalid-UTF-8 (Project C). The SessionInit producer does not currently emit this reason. |
| `send_failed` | `conn.Send(SessionInit)` returns an error. Indicates network egress problems or server unreachability. |
| `recv_failed` | `conn.Recv()` returns an error before SessionAck arrives. Indicates server liveness or network return-path problems. |
| `unexpected_message` | The first inbound `ServerMessage` after SessionInit is not a `SessionAck`. Typically a server protocol bug or version mismatch. |
| `rejected` | Server returned `SessionAck.accepted=false`. The structured WARN log carries the server-supplied `reject_reason` text; the counter only carries the count. Operator response: check server-side authorization / agent identity configuration. |
| `unknown` | Validator (`ValidateSessionInit`) returned an error. Today this is `ReasonSessionInitAlgorithmUnspecified`; future validator surface gains add `errors.Is` branches at the emit site. Operator response: check Options misconfiguration (typically `Algorithm` left zero); structured ERR log carries the field-level cause. |

**Operator alert recommendations.**

- Notify-only on `rate(wtp_session_init_failures_total[10m]) > 0` — a single transient handshake failure during a normal reconnect cycle is not a problem.
- Page on sustained `rejected` rate: `rate(wtp_session_init_failures_total{reason="rejected"}[5m]) > 0.01` indicates persistent server-side authorization failure.
- Page on sustained `unknown` rate: indicates a misconfigured agent that cannot construct a valid SessionInit.

**Reload model.** Read at handshake time on every reconnect; changes to `Options.Algorithm` etc. take effect on the next reconnect (no daemon restart needed for metric-side observation).

## `wtp_dropped_invalid_frame_total{reason=goaway_code_unspecified|session_update_generation_invalid}`

**Status:** Live as of PR (this branch). Two new reason labels added; the existing reasons (`event_batch_*`, `session_init_algorithm_unspecified`, `payload_too_large`, `decompress_error`, `classifier_bypass`, `unknown`) are unchanged.

These two reasons fire on inbound frames that fail the new structural validators in `recv_multiplexer.go`:

- `goaway_code_unspecified`: Server sent a `Goaway` with `code: GOAWAY_CODE_UNSPECIFIED`. Wire-incompatible per the proto's UNSPECIFIED contract — receivers MUST reject. Operator response: investigate server protocol-version mismatch.
- `session_update_generation_invalid`: Server sent a `SessionUpdate` with `new_generation: 0`. Rotation MUST monotonically advance to a positive generation. Operator response: investigate server bug.

In both cases the agent ALSO ticks `wtp_reconnects_total{reason="recv_unknown_frame"}` because the validator failure causes the recv goroutine to fail-close and the run loop reconnects. The two metrics answer different questions:
- `wtp_dropped_invalid_frame_total{reason}` — frame-level diagnostic ("why was the frame rejected").
- `wtp_reconnects_total{reason="recv_unknown_frame"}` — connection-level event ("why did we reconnect").

A single malformed frame legitimately fires both.

**Operator alert recommendations.**

- Notify-only on any non-zero rate for these two new labels — server-side protocol drift is rare and worth investigation when it appears.
- Page on `rate(...) > 0.01/s` sustained: server is consistently misbehaving and the agent is reconnect-looping.

`wtp_decompress_error_total` is receiver-side; alert thresholds should live with the receiving Watchtower server's dashboards, not the agent's.
