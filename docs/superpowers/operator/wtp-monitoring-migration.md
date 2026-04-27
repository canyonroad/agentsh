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
