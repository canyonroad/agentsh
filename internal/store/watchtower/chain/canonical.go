package chain

import (
	"bytes"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// EncodeCanonical produces the byte-exact canonical JSON encoding of an
// IntegrityRecord per spec §6.4: keys sorted lexicographically, no insignificant
// whitespace, ASCII-escaped non-ASCII (lowercase hex), decimal integers (no
// scientific notation), strict JSON string escapes.
//
// This is the cross-implementation contract surface — a single byte difference
// breaks every other implementation. Vectors live in chain/testdata/vectors.json
// and are also published as the conformance suite at docs/spec/wtp/conformance/.
func EncodeCanonical(rec IntegrityRecord) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	// Keys sorted lexicographically: context_digest, event_hash, format_version,
	// generation, key_fingerprint, prev_hash, sequence.
	writeKey(&buf, "context_digest", true)
	writeStringValue(&buf, rec.ContextDigest)

	writeKey(&buf, "event_hash", false)
	writeStringValue(&buf, rec.EventHash)

	writeKey(&buf, "format_version", false)
	writeUint(&buf, uint64(rec.FormatVersion))

	writeKey(&buf, "generation", false)
	writeUint(&buf, uint64(rec.Generation))

	writeKey(&buf, "key_fingerprint", false)
	writeStringValue(&buf, rec.KeyFingerprint)

	writeKey(&buf, "prev_hash", false)
	writeStringValue(&buf, rec.PrevHash)

	writeKey(&buf, "sequence", false)
	writeUint(&buf, rec.Sequence)

	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// encodeContextCanonical does the same for SessionContext. Internal: only used
// by ComputeContextDigest. Keys sorted: agent_id, agent_version, algorithm,
// format_version, key_fingerprint, ocsf_version, session_id.
func encodeContextCanonical(ctx SessionContext) []byte {
	var buf bytes.Buffer
	buf.WriteByte('{')
	writeKey(&buf, "agent_id", true)
	writeStringValue(&buf, ctx.AgentID)
	writeKey(&buf, "agent_version", false)
	writeStringValue(&buf, ctx.AgentVersion)
	writeKey(&buf, "algorithm", false)
	writeStringValue(&buf, ctx.Algorithm)
	writeKey(&buf, "format_version", false)
	writeUint(&buf, uint64(ctx.FormatVersion))
	writeKey(&buf, "key_fingerprint", false)
	writeStringValue(&buf, ctx.KeyFingerprint)
	writeKey(&buf, "ocsf_version", false)
	writeStringValue(&buf, ctx.OCSFVersion)
	writeKey(&buf, "session_id", false)
	writeStringValue(&buf, ctx.SessionID)
	buf.WriteByte('}')
	return buf.Bytes()
}

func writeKey(buf *bytes.Buffer, k string, first bool) {
	if !first {
		buf.WriteByte(',')
	}
	buf.WriteByte('"')
	writeStringEscapedBody(buf, k)
	buf.WriteByte('"')
	buf.WriteByte(':')
}

func writeStringValue(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	writeStringEscapedBody(buf, s)
	buf.WriteByte('"')
}

func writeUint(buf *bytes.Buffer, n uint64) {
	buf.WriteString(strconv.FormatUint(n, 10))
}

// writeStringEscapedBody writes s into buf with the canonical-JSON escape
// rules: \", \\, \b/\f/\n/\r/\t, \uXXXX for everything below 0x20 and for
// every non-ASCII rune (lowercase hex). Surrogate pairs encode as two \uXXXX
// escapes per RFC 8259 §7.
func writeStringEscapedBody(buf *bytes.Buffer, s string) {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// Invalid UTF-8 — emit the replacement character escape.
			fmt.Fprintf(buf, `\u%04x`, 0xFFFD)
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(buf, `\u%04x`, r)
		case r < 0x80:
			buf.WriteByte(byte(r))
		case r <= 0xFFFF:
			fmt.Fprintf(buf, `\u%04x`, r)
		default:
			// Outside BMP — surrogate pair, lowercase hex.
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(buf, `\u%04x\u%04x`, hi, lo)
		}
		i += size
	}
}
