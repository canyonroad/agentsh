package chain

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type vectorEntry struct {
	Name          string          `json:"name"`
	Kind          string          `json:"kind"`           // "integrity_record" | "context_digest"
	Input         json.RawMessage `json:"input,omitempty"` // for valid inputs, an object with canonical wire snake_case keys (e.g. format_version, sequence, session_id) — NOT Go field names. Each implementation maps the keys to its local struct fields inside its harness.
	InputB64      string          `json:"input_b64,omitempty"` // base64-encoded raw struct field bytes for negative cases (non-UTF-8)
	InputField    string          `json:"input_field,omitempty"` // canonical wire field name receiving InputB64 (e.g., "prev_hash", "session_id")
	Expected      string          `json:"expected,omitempty"` // for valid: canonical bytes (integrity_record) or hex digest (context_digest)
	ExpectedError string          `json:"expected_error,omitempty"` // for negative: sentinel name (e.g., "ErrInvalidUTF8")
}

func TestVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := loadVectors(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("vectors.json has no entries")
	}
	for _, v := range entries {
		t.Run(v.Name, func(t *testing.T) {
			switch v.Kind {
			case "integrity_record":
				rec, err := buildIntegrityRecord(v)
				if err != nil {
					t.Fatalf("build input: %v", err)
				}
				got, err := EncodeCanonical(rec)
				if v.ExpectedError != "" {
					assertExpectedError(t, err, v.ExpectedError)
					return
				}
				if err != nil {
					t.Fatalf("EncodeCanonical: %v", err)
				}
				if string(got) != v.Expected {
					t.Errorf("canonical mismatch\ngot:  %s\nwant: %s", got, v.Expected)
				}
			case "context_digest":
				ctx, err := buildSessionContext(v)
				if err != nil {
					t.Fatalf("build input: %v", err)
				}
				got, err := ComputeContextDigest(ctx)
				if v.ExpectedError != "" {
					assertExpectedError(t, err, v.ExpectedError)
					return
				}
				if err != nil {
					t.Fatalf("ComputeContextDigest: %v", err)
				}
				if got != v.Expected {
					t.Errorf("digest mismatch\ngot:  %s\nwant: %s", got, v.Expected)
				}
			default:
				t.Fatalf("unknown vector kind %q", v.Kind)
			}
		})
	}
}

// buildIntegrityRecord decodes v.Input — an object with canonical wire
// snake_case keys, NOT Go field names — into a Go IntegrityRecord. Then
// applies v.InputB64 (raw bytes including invalid UTF-8) to v.InputField
// for negative cases. Each implementation maps the snake_case keys to
// its local struct fields here, keeping the published vectors language-
// neutral.
//
// Numeric fields are decoded via decodeUint32 / decodeUint64 helpers
// that range-check before casting. Silently truncating uint64 → uint32
// would weaken the cross-implementation conformance story; explicit
// rejection at the harness boundary is the contract.
func buildIntegrityRecord(v vectorEntry) (IntegrityRecord, error) {
	var rec IntegrityRecord
	if len(v.Input) > 0 {
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal(v.Input, &fields); err != nil {
			return rec, fmt.Errorf("decode input: %w", err)
		}
		for key, raw := range fields {
			switch key {
			case "format_version":
				n, err := decodeUint32(key, raw)
				if err != nil {
					return rec, err
				}
				rec.FormatVersion = n
			case "sequence":
				n, err := decodeUint64(key, raw)
				if err != nil {
					return rec, err
				}
				rec.Sequence = n
			case "generation":
				n, err := decodeUint32(key, raw)
				if err != nil {
					return rec, err
				}
				rec.Generation = n
			case "prev_hash":
				s, err := decodeString(key, raw)
				if err != nil {
					return rec, err
				}
				rec.PrevHash = s
			case "event_hash":
				s, err := decodeString(key, raw)
				if err != nil {
					return rec, err
				}
				rec.EventHash = s
			case "context_digest":
				s, err := decodeString(key, raw)
				if err != nil {
					return rec, err
				}
				rec.ContextDigest = s
			case "key_fingerprint":
				s, err := decodeString(key, raw)
				if err != nil {
					return rec, err
				}
				rec.KeyFingerprint = s
			default:
				return rec, fmt.Errorf("unknown input key %q (expected wire snake_case name for integrity_record)", key)
			}
		}
	}
	if v.InputB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(v.InputB64)
		if err != nil {
			return rec, fmt.Errorf("decode input_b64: %w", err)
		}
		switch v.InputField {
		case "prev_hash":
			rec.PrevHash = string(raw)
		case "event_hash":
			rec.EventHash = string(raw)
		case "context_digest":
			rec.ContextDigest = string(raw)
		case "key_fingerprint":
			rec.KeyFingerprint = string(raw)
		default:
			return rec, fmt.Errorf("unknown input_field %q (expected wire snake_case name)", v.InputField)
		}
	}
	return rec, nil
}

// decodeUint32 parses raw as a JSON number and rejects values outside
// the uint32 range. Uses json.Number to preserve full uint64 precision
// before the range check.
func decodeUint32(name string, raw json.RawMessage) (uint32, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var num json.Number
	if err := dec.Decode(&num); err != nil {
		return 0, fmt.Errorf("decode %s: %w", name, err)
	}
	u, err := strconv.ParseUint(num.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	if u > math.MaxUint32 {
		return 0, fmt.Errorf("vector field %q value %d exceeds uint32 range", name, u)
	}
	return uint32(u), nil
}

// decodeUint64 parses raw as a JSON number into a real uint64 (no range
// reduction). Uses json.Number so values up to math.MaxUint64 round-trip
// without precision loss.
func decodeUint64(name string, raw json.RawMessage) (uint64, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var num json.Number
	if err := dec.Decode(&num); err != nil {
		return 0, fmt.Errorf("decode %s: %w", name, err)
	}
	u, err := strconv.ParseUint(num.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	return u, nil
}

// decodeString parses raw as a JSON string. Provided for API symmetry
// with decodeUint32 / decodeUint64 so every switch case calls a helper.
func decodeString(name string, raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("decode %s: %w", name, err)
	}
	return s, nil
}

// buildSessionContext mirrors buildIntegrityRecord for SessionContext.
// v.Input uses canonical wire snake_case keys, NOT Go field names.
// Numeric fields use the same decode helpers as buildIntegrityRecord
// (range-checked uint32, full-precision uint64) so out-of-range values
// fail explicitly rather than truncating silently.
func buildSessionContext(v vectorEntry) (SessionContext, error) {
	var ctx SessionContext
	if len(v.Input) > 0 {
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal(v.Input, &fields); err != nil {
			return ctx, fmt.Errorf("decode input: %w", err)
		}
		for key, raw := range fields {
			switch key {
			case "session_id":
				s, err := decodeString(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.SessionID = s
			case "agent_id":
				s, err := decodeString(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.AgentID = s
			case "agent_version":
				s, err := decodeString(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.AgentVersion = s
			case "ocsf_version":
				s, err := decodeString(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.OCSFVersion = s
			case "format_version":
				n, err := decodeUint32(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.FormatVersion = n
			case "algorithm":
				s, err := decodeString(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.Algorithm = s
			case "key_fingerprint":
				s, err := decodeString(key, raw)
				if err != nil {
					return ctx, err
				}
				ctx.KeyFingerprint = s
			default:
				return ctx, fmt.Errorf("unknown input key %q (expected wire snake_case name for context_digest)", key)
			}
		}
	}
	if v.InputB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(v.InputB64)
		if err != nil {
			return ctx, fmt.Errorf("decode input_b64: %w", err)
		}
		switch v.InputField {
		case "session_id":
			ctx.SessionID = string(raw)
		case "agent_id":
			ctx.AgentID = string(raw)
		case "agent_version":
			ctx.AgentVersion = string(raw)
		case "ocsf_version":
			ctx.OCSFVersion = string(raw)
		case "algorithm":
			ctx.Algorithm = string(raw)
		case "key_fingerprint":
			ctx.KeyFingerprint = string(raw)
		default:
			return ctx, fmt.Errorf("unknown input_field %q (expected wire snake_case name)", v.InputField)
		}
	}
	return ctx, nil
}

// assertExpectedError checks that err matches the named sentinel.
func assertExpectedError(t *testing.T, err error, sentinelName string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", sentinelName)
	}
	switch sentinelName {
	case "ErrInvalidUTF8":
		if !errors.Is(err, ErrInvalidUTF8) {
			t.Fatalf("expected ErrInvalidUTF8, got %v", err)
		}
	default:
		t.Fatalf("vectors.json names unknown sentinel %q", sentinelName)
	}
}

// supportedVectorSchemaVersions is the set of envelope schema_version values
// the harness will accept. Bump when shipping a new envelope shape; the
// loader fails closed on any value not listed here so a future incompatible
// vector set cannot be silently treated as conformant. v1 (bare array) is
// detected by the leading '[' byte, not by this set.
var supportedVectorSchemaVersions = map[int]struct{}{
	2: {}, // current published envelope; see spec §"Vector schema versioning"
}

// loadVectors decodes a conformance-vector file in either v1 (bare JSON
// array) or v2+ (envelope `{"schema_version": N, "vectors": [...]}`) form.
//
// Detection rule (per spec §"Vector schema versioning"): peek the first
// non-whitespace byte. '[' → v1 array. '{' → v2+ envelope; the envelope
// MUST carry a recognized schema_version or the load fails. Anything else
// is an error. This is fail-closed: an unknown envelope value is never
// accepted as a "best-effort" v1 fallback.
//
// Both paths reject unknown fields (DisallowUnknownFields) and trailing
// content after the top-level value, per spec §"Unknown-field policy"
// and §"Trailing content". Typos and accidentally-concatenated payloads
// fail loudly rather than being silently dropped.
func loadVectors(data []byte) ([]vectorEntry, error) {
	first, err := firstNonWhitespaceByte(data)
	if err != nil {
		return nil, err
	}
	switch first {
	case '[':
		// v1 path: a bare array. json.Decoder + DisallowUnknownFields gives
		// us per-entry strict decoding plus a follow-up EOF check that
		// rejects trailing junk after the closing ']'.
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		var entries []vectorEntry
		if err := dec.Decode(&entries); err != nil {
			return nil, fmt.Errorf("decode v1 vectors array: %w", err)
		}
		if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("decode v1 vectors array: trailing content after array: %v", err)
		}
		return entries, nil
	case '{':
		// Decode the envelope into a struct that uses *int for schema_version
		// so we can tell "field absent" from "field present and zero".
		var env struct {
			SchemaVersion *int            `json:"schema_version"`
			Vectors       []vectorEntry   `json:"vectors"`
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&env); err != nil {
			return nil, fmt.Errorf("decode vectors envelope: %w", err)
		}
		if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("decode vectors envelope: trailing content after envelope: %v", err)
		}
		if env.SchemaVersion == nil {
			return nil, errors.New("vectors envelope missing required field schema_version")
		}
		if _, ok := supportedVectorSchemaVersions[*env.SchemaVersion]; !ok {
			return nil, fmt.Errorf("unsupported vectors schema_version %d (harness accepts %v)", *env.SchemaVersion, supportedSchemaVersionList())
		}
		return env.Vectors, nil
	default:
		return nil, fmt.Errorf("vectors file must start with '[' (v1) or '{' (v2+ envelope); got %q", first)
	}
}

func firstNonWhitespaceByte(data []byte) (byte, error) {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return b, nil
		}
	}
	return 0, errors.New("vectors file is empty or whitespace-only")
}

func supportedSchemaVersionList() []int {
	out := make([]int, 0, len(supportedVectorSchemaVersions))
	for v := range supportedVectorSchemaVersions {
		out = append(out, v)
	}
	return out
}

func TestBuildIntegrityRecord_RejectsUint32Overflow(t *testing.T) {
	raw := json.RawMessage(`{"format_version": 4294967296, "sequence": 0, "generation": 0, "prev_hash": "", "event_hash": "", "context_digest": "", "key_fingerprint": ""}`)
	v := vectorEntry{Input: raw, Kind: "integrity_record"}
	_, err := buildIntegrityRecord(v)
	if err == nil {
		t.Fatal("expected range error for format_version > MaxUint32, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds uint32 range") {
		t.Errorf("error must mention range overflow: %v", err)
	}
}

func TestBuildIntegrityRecord_AcceptsUint32Max(t *testing.T) {
	raw := json.RawMessage(`{"format_version": 4294967295, "sequence": 0, "generation": 4294967295, "prev_hash": "", "event_hash": "", "context_digest": "", "key_fingerprint": ""}`)
	v := vectorEntry{Input: raw, Kind: "integrity_record"}
	rec, err := buildIntegrityRecord(v)
	if err != nil {
		t.Fatalf("uint32 max should be accepted: %v", err)
	}
	if rec.FormatVersion != math.MaxUint32 {
		t.Errorf("FormatVersion: got %d, want %d", rec.FormatVersion, uint32(math.MaxUint32))
	}
	if rec.Generation != math.MaxUint32 {
		t.Errorf("Generation: got %d, want %d", rec.Generation, uint32(math.MaxUint32))
	}
}

func TestDecodeUint32_RejectsOverflow(t *testing.T) {
	// Shared contract for buildIntegrityRecord AND buildSessionContext —
	// both consume decodeUint32 for format_version (and integrity records
	// also for generation). Exercising the helper covers both call sites.
	_, err := decodeUint32("format_version", json.RawMessage(`4294967296`))
	if err == nil {
		t.Fatal("expected range error for value > MaxUint32, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds uint32 range") {
		t.Errorf("error must mention range overflow: %v", err)
	}
}

func TestDecodeUint32_AcceptsMax(t *testing.T) {
	got, err := decodeUint32("format_version", json.RawMessage(`4294967295`))
	if err != nil {
		t.Fatalf("uint32 max should be accepted: %v", err)
	}
	if got != math.MaxUint32 {
		t.Errorf("decodeUint32 returned %d, want %d", got, uint32(math.MaxUint32))
	}
}

func TestLoadVectors_V1Array(t *testing.T) {
	data := []byte(`[{"name":"x","kind":"integrity_record","input":{"format_version":2,"sequence":0,"generation":0,"prev_hash":"","event_hash":"","context_digest":"","key_fingerprint":""},"expected":"{\"context_digest\":\"\",\"event_hash\":\"\",\"format_version\":2,\"generation\":0,\"key_fingerprint\":\"\",\"prev_hash\":\"\",\"sequence\":0}"}]`)
	entries, err := loadVectors(data)
	if err != nil {
		t.Fatalf("loadVectors(v1): %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "x" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestLoadVectors_V2Envelope(t *testing.T) {
	data := []byte(`{"schema_version":2,"vectors":[{"name":"y","kind":"context_digest"}]}`)
	entries, err := loadVectors(data)
	if err != nil {
		t.Fatalf("loadVectors(v2): %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "y" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestLoadVectors_RejectsEnvelopeMissingSchemaVersion(t *testing.T) {
	data := []byte(`{"vectors":[]}`)
	_, err := loadVectors(data)
	if err == nil {
		t.Fatal("expected error for envelope without schema_version, got nil")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error must mention schema_version: %v", err)
	}
}

func TestLoadVectors_RejectsUnknownSchemaVersion(t *testing.T) {
	data := []byte(`{"schema_version":99,"vectors":[]}`)
	_, err := loadVectors(data)
	if err == nil {
		t.Fatal("expected error for unknown schema_version, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error must mention unsupported: %v", err)
	}
}

func TestLoadVectors_RejectsMalformedJSON(t *testing.T) {
	data := []byte(`{not valid json`)
	if _, err := loadVectors(data); err == nil {
		t.Fatal("expected decode error, got nil")
	}
}

func TestLoadVectors_RejectsEmpty(t *testing.T) {
	if _, err := loadVectors([]byte("   \n\t")); err == nil {
		t.Fatal("expected error for whitespace-only input, got nil")
	}
}

func TestLoadVectors_RejectsBareScalar(t *testing.T) {
	if _, err := loadVectors([]byte(`42`)); err == nil {
		t.Fatal("expected error for non-array/non-object top-level value, got nil")
	}
}

func TestLoadVectors_RejectsTrailingContent(t *testing.T) {
	// Both v1 (bare-array) and v2 (envelope) paths must reject anything
	// after the top-level JSON value. Catches accidental concatenation and
	// forward-incompatible streaming formats. Spec §"Trailing content".
	v1WithJunk := []byte(`[{"name":"x","kind":"integrity_record","input":{"format_version":2,"sequence":0,"generation":0,"prev_hash":"","event_hash":"","context_digest":"","key_fingerprint":""},"expected":"{}"}]  garbage`)
	if _, err := loadVectors(v1WithJunk); err == nil {
		t.Fatal("expected v1 trailing-content rejection, got nil")
	} else if !strings.Contains(err.Error(), "trailing content") {
		t.Errorf("v1 error must mention trailing content: %v", err)
	}
	v2WithJunk := []byte(`{"schema_version":2,"vectors":[]}  {"another":"object"}`)
	if _, err := loadVectors(v2WithJunk); err == nil {
		t.Fatal("expected v2 trailing-content rejection, got nil")
	} else if !strings.Contains(err.Error(), "trailing content") {
		t.Errorf("v2 error must mention trailing content: %v", err)
	}
}

func TestLoadVectors_RejectsUnknownFields(t *testing.T) {
	// Both v1 and v2 paths must reject unknown fields per spec
	// §"Unknown-field policy". Typos and forward-incompatible vectors
	// fail loudly rather than silently being dropped.
	v1WithUnknown := []byte(`[{"name":"x","kind":"integrity_record","input":{},"expected":"","UNKNOWN_FIELD":1}]`)
	if _, err := loadVectors(v1WithUnknown); err == nil {
		t.Fatal("expected v1 unknown-field rejection, got nil")
	} else if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("v1 error must mention unknown field: %v", err)
	}
	v2WithUnknown := []byte(`{"schema_version":2,"vectors":[],"UNKNOWN_ENVELOPE_FIELD":true}`)
	if _, err := loadVectors(v2WithUnknown); err == nil {
		t.Fatal("expected v2 unknown-field rejection at envelope level, got nil")
	} else if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("v2 envelope error must mention unknown field: %v", err)
	}
	v2EntryUnknown := []byte(`{"schema_version":2,"vectors":[{"name":"y","kind":"context_digest","UNKNOWN_ENTRY_FIELD":"x"}]}`)
	if _, err := loadVectors(v2EntryUnknown); err == nil {
		t.Fatal("expected v2 unknown-field rejection at entry level, got nil")
	} else if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("v2 entry error must mention unknown field: %v", err)
	}
}
