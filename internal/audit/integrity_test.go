package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// testKey is a valid 32-byte key for tests that require a valid key.
var testKey = []byte("test-secret-key-32-bytes-long!!!")

func TestIntegrityChain_Wrap(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	payload := []byte(`{"event":"command_executed","command":"ls -la"}`)
	wrapped, err := chain.Wrap(payload)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	// Parse the wrapped payload
	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("unmarshal wrapped payload: %v", err)
	}

	// Verify original fields are preserved
	if result["event"] != "command_executed" {
		t.Errorf("event field = %v, want %v", result["event"], "command_executed")
	}
	if result["command"] != "ls -la" {
		t.Errorf("command field = %v, want %v", result["command"], "ls -la")
	}

	// Verify integrity field exists with correct structure
	integrity, ok := result["integrity"].(map[string]any)
	if !ok {
		t.Fatalf("integrity field missing or not an object, got %T", result["integrity"])
	}

	// Check sequence
	seq, ok := integrity["sequence"].(float64) // JSON numbers are float64
	if !ok || seq != 0 {
		t.Errorf("integrity.sequence = %v, want 0", integrity["sequence"])
	}

	formatVersion, ok := integrity["format_version"].(float64)
	if !ok || int(formatVersion) != IntegrityFormatVersion {
		t.Errorf("integrity.format_version = %v, want %d", integrity["format_version"], IntegrityFormatVersion)
	}

	// Check prev_hash (should be empty for first entry)
	prevHash, ok := integrity["prev_hash"].(string)
	if !ok || prevHash != "" {
		t.Errorf("integrity.prev_hash = %q, want empty string", prevHash)
	}

	// Check entry_hash exists and is non-empty
	entryHash, ok := integrity["entry_hash"].(string)
	if !ok || entryHash == "" {
		t.Errorf("integrity.entry_hash is missing or empty")
	}
}

func TestIntegrityChain_Wrap_StartsAtSequenceZeroAndAddsFormatVersion(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	wrapped, err := chain.Wrap([]byte(`{"event":"first"}`))
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	integrity := result["integrity"].(map[string]any)
	if got := int64(integrity["sequence"].(float64)); got != 0 {
		t.Fatalf("sequence = %d, want 0", got)
	}
	if got := int(integrity["format_version"].(float64)); got != IntegrityFormatVersion {
		t.Fatalf("format_version = %d, want %d", got, IntegrityFormatVersion)
	}
	if got := integrity["prev_hash"].(string); got != "" {
		t.Fatalf("prev_hash = %q, want empty", got)
	}
}

func TestIntegrityChain_Restore_ContinuesFromLastWrittenSequence(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}
	if err := chain.Restore(41, "0000000000000000000000000000000000000000000000000000000000000000"); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}

	wrapped, err := chain.Wrap([]byte(`{"event":"after_restore"}`))
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	integrity := result["integrity"].(map[string]any)
	if got := int64(integrity["sequence"].(float64)); got != 42 {
		t.Fatalf("sequence = %d, want 42", got)
	}
	if got := integrity["prev_hash"].(string); got != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("prev_hash = %q, want zero hex", got)
	}
}

func TestKeyFingerprint_IsDeterministic(t *testing.T) {
	got := KeyFingerprint(testKey)
	if got == "" {
		t.Fatal("KeyFingerprint() returned empty string")
	}
	if !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("KeyFingerprint() = %q, want sha256: prefix", got)
	}
	if len(got) != len("sha256:")+32 {
		t.Fatalf("KeyFingerprint() length = %d, want %d", len(got), len("sha256:")+32)
	}
	sum := sha256.Sum256(testKey)
	want := "sha256:" + hex.EncodeToString(sum[:16])
	if got != want {
		t.Fatalf("KeyFingerprint() = %q, want %q", got, want)
	}
	if got != KeyFingerprint(testKey) {
		t.Fatalf("KeyFingerprint() should be deterministic, got %q then %q", got, KeyFingerprint(testKey))
	}

	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}
	if chain.KeyFingerprint() != got {
		t.Fatalf("chain.KeyFingerprint() = %q, want %q", chain.KeyFingerprint(), got)
	}
}

func TestIntegrityChain_Wrap_ReturnsSequenceOverflowAtMaxInt64(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := chain.Restore(math.MaxInt64, zeroHash); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}

	_, err = chain.Wrap([]byte(`{"event":"overflow"}`))
	if !errors.Is(err, ErrSequenceOverflow) {
		t.Fatalf("Wrap() error = %v, want %v", err, ErrSequenceOverflow)
	}

	state := chain.State()
	if state.Sequence != math.MaxInt64 {
		t.Fatalf("State().Sequence = %d, want %d", state.Sequence, int64(math.MaxInt64))
	}
	if state.PrevHash != zeroHash {
		t.Fatalf("State().PrevHash = %q, want %q", state.PrevHash, zeroHash)
	}
}

func TestIntegrityChain_VerifyHash_UsesOwnKeyAndCanonicalPayload(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	wrapped, err := chain.Wrap([]byte(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	integrity := result["integrity"].(map[string]any)
	formatVersion := int(integrity["format_version"].(float64))
	sequence := int64(integrity["sequence"].(float64))
	prevHash := integrity["prev_hash"].(string)
	entryHash := integrity["entry_hash"].(string)

	ok, err := chain.VerifyHash(formatVersion, sequence, prevHash, []byte(`{"b":2,"a":1}`), entryHash)
	if err != nil {
		t.Fatalf("VerifyHash() error = %v", err)
	}
	if !ok {
		t.Fatal("VerifyHash() = false, want true")
	}

	ok, err = chain.VerifyHash(formatVersion, sequence, prevHash, []byte(`{"b":3,"a":1}`), entryHash)
	if err != nil {
		t.Fatalf("VerifyHash() tampered error = %v", err)
	}
	if ok {
		t.Fatal("VerifyHash() = true for tampered payload, want false")
	}
}

func TestVerifyHash_AcceptsPersistedWrappedEntry(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	wrapped, err := chain.Wrap([]byte(`{"type":"persisted","fields":{"value":"ok"}}`))
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	integrity := result["integrity"].(map[string]any)
	ok, err := VerifyHash(
		testKey,
		"hmac-sha256",
		int(integrity["format_version"].(float64)),
		int64(integrity["sequence"].(float64)),
		integrity["prev_hash"].(string),
		wrapped,
		integrity["entry_hash"].(string),
	)
	if err != nil {
		t.Fatalf("VerifyHash() error = %v", err)
	}
	if !ok {
		t.Fatal("VerifyHash() = false, want true for persisted wrapped entry")
	}
}

func TestVerifyHash_PreservesLargePayloadIntegers(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	wrapped, err := chain.Wrap([]byte(`{"type":"persisted","fields":{"big":9007199254740993}}`))
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	integrity := result["integrity"].(map[string]any)
	ok, err := VerifyHash(
		testKey,
		"hmac-sha256",
		int(integrity["format_version"].(float64)),
		int64(integrity["sequence"].(float64)),
		integrity["prev_hash"].(string),
		wrapped,
		integrity["entry_hash"].(string),
	)
	if err != nil {
		t.Fatalf("VerifyHash() error = %v", err)
	}
	if !ok {
		t.Fatal("VerifyHash() = false, want true for large payload integer")
	}
}

func TestVerifyHash_PreservesNumericLexemes(t *testing.T) {
	for _, payload := range []string{
		`{"type":"persisted","fields":{"value":1.0}}`,
		`{"type":"persisted","fields":{"value":1e0}}`,
		`{"type":"persisted","fields":{"value":-0}}`,
	} {
		t.Run(payload, func(t *testing.T) {
			chain, err := NewIntegrityChain(testKey)
			if err != nil {
				t.Fatalf("NewIntegrityChain() error = %v", err)
			}

			wrapped, err := chain.Wrap([]byte(payload))
			if err != nil {
				t.Fatalf("Wrap() error = %v", err)
			}

			var result map[string]any
			if err := json.Unmarshal(wrapped, &result); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			integrity := result["integrity"].(map[string]any)
			ok, err := VerifyHash(
				testKey,
				"hmac-sha256",
				int(integrity["format_version"].(float64)),
				int64(integrity["sequence"].(float64)),
				integrity["prev_hash"].(string),
				wrapped,
				integrity["entry_hash"].(string),
			)
			if err != nil {
				t.Fatalf("VerifyHash() error = %v", err)
			}
			if !ok {
				t.Fatalf("VerifyHash() = false, want true for payload %s", payload)
			}
		})
	}
}

func TestIntegrityChain_VerifyWrapped_FailsWhenFormatVersionMutates(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	wrapped, err := chain.Wrap([]byte(`{"event":"format_version"}`))
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	ok, err := chain.VerifyWrapped(wrapped)
	if err != nil {
		t.Fatalf("VerifyWrapped() error = %v", err)
	}
	if !ok {
		t.Fatal("VerifyWrapped() = false, want true for original payload")
	}

	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	integrity := result["integrity"].(map[string]any)
	integrity["format_version"] = float64(IntegrityFormatVersion + 1)

	mutated, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	ok, err = chain.VerifyWrapped(mutated)
	if err != nil {
		t.Fatalf("VerifyWrapped() mutated error = %v", err)
	}
	if ok {
		t.Fatal("VerifyWrapped() = true after format_version mutation, want false")
	}
}

func TestIntegrityChain_VerifyWrapped_FailsWhenFormatVersionMissing(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	wrapped, err := chain.Wrap([]byte(`{"event":"missing_format_version"}`))
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	integrity := result["integrity"].(map[string]any)
	delete(integrity, "format_version")

	mutated, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	ok, err := chain.VerifyWrapped(mutated)
	if err != nil {
		t.Fatalf("VerifyWrapped() missing format_version error = %v", err)
	}
	if ok {
		t.Fatal("VerifyWrapped() = true after removing format_version, want false")
	}
}

func TestIntegrityChain_SHA512VerifyWrapped(t *testing.T) {
	chain, err := NewIntegrityChainWithAlgorithm(testKey, "hmac-sha512")
	if err != nil {
		t.Fatalf("NewIntegrityChainWithAlgorithm() error = %v", err)
	}

	wrapped, err := chain.Wrap([]byte(`{"event":"sha512_verify"}`))
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	ok, err := chain.VerifyWrapped(wrapped)
	if err != nil {
		t.Fatalf("VerifyWrapped() error = %v", err)
	}
	if !ok {
		t.Fatal("VerifyWrapped() = false, want true")
	}
}

func TestIntegrityChain_VerifyWrapped_PreservesLargeSequencePrecision(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	const lastWrittenSequence int64 = 9007199254740992
	if err := chain.Restore(lastWrittenSequence, ""); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}

	wrapped, err := chain.Wrap([]byte(`{"event":"high_sequence"}`))
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	if state := chain.State(); state.Sequence != lastWrittenSequence+1 {
		t.Fatalf("State().Sequence = %d, want %d", state.Sequence, lastWrittenSequence+1)
	}

	ok, err := chain.VerifyWrapped(wrapped)
	if err != nil {
		t.Fatalf("VerifyWrapped() error = %v", err)
	}
	if !ok {
		t.Fatal("VerifyWrapped() = false, want true for untouched wrapped entry")
	}
}

func TestIntegrityChain_VerifyWrapped_RejectsTrailingData(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	wrapped, err := chain.Wrap([]byte(`{"event":"trailing_data"}`))
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "garbage",
			payload: append(append([]byte{}, wrapped...), []byte("garbage")...),
		},
		{
			name:    "second_object",
			payload: append(append([]byte{}, wrapped...), []byte(` {"extra":true}`)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := chain.VerifyWrapped(tt.payload)
			if err == nil {
				t.Fatalf("VerifyWrapped() error = nil, want rejection, ok = %v", ok)
			}
		})
	}
}

func TestIntegrityChain_ChainContinuity(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	// Wrap multiple payloads
	payloads := []string{
		`{"event":"first"}`,
		`{"event":"second"}`,
		`{"event":"third"}`,
	}

	var prevEntryHash string
	for i, payload := range payloads {
		wrapped, err := chain.Wrap([]byte(payload))
		if err != nil {
			t.Fatalf("Wrap() %d error = %v", i, err)
		}

		var result map[string]any
		if err := json.Unmarshal(wrapped, &result); err != nil {
			t.Fatalf("unmarshal %d: %v", i, err)
		}

		integrity := result["integrity"].(map[string]any)
		seq := int64(integrity["sequence"].(float64))
		prevHash := integrity["prev_hash"].(string)
		entryHash := integrity["entry_hash"].(string)

		// Verify sequence increments
		if seq != int64(i) {
			t.Errorf("entry %d: sequence = %d, want %d", i, seq, i)
		}

		// Verify prev_hash equals previous entry_hash
		if prevHash != prevEntryHash {
			t.Errorf("entry %d: prev_hash = %q, want %q", i, prevHash, prevEntryHash)
		}

		// Save entry_hash for next iteration
		prevEntryHash = entryHash
	}
}

func TestIntegrityChain_Restore(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	// Wrap a few entries
	for i := 0; i < 3; i++ {
		_, err := chain.Wrap([]byte(`{"event":"test"}`))
		if err != nil {
			t.Fatalf("Wrap() error = %v", err)
		}
	}

	// Get current state
	state := chain.State()
	if state.Sequence != 2 {
		t.Errorf("State().Sequence = %d, want 2", state.Sequence)
	}

	// Create new chain and restore state
	newChain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}
	if err := newChain.Restore(state.Sequence, state.PrevHash); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}

	// Wrap a new entry
	wrapped, err := newChain.Wrap([]byte(`{"event":"after_restore"}`))
	if err != nil {
		t.Fatalf("Wrap() after restore error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	integrity := result["integrity"].(map[string]any)

	// Should continue from sequence 3
	if seq := int64(integrity["sequence"].(float64)); seq != 3 {
		t.Errorf("sequence after restore = %d, want 3", seq)
	}

	// prev_hash should match the state we restored
	if prevHash := integrity["prev_hash"].(string); prevHash != state.PrevHash {
		t.Errorf("prev_hash after restore = %q, want %q", prevHash, state.PrevHash)
	}
}

func TestLoadKey_FromEnv(t *testing.T) {
	envVar := "AGENTSH_TEST_AUDIT_KEY"
	keyValue := "my-secret-key-from-env"

	t.Setenv(envVar, keyValue)

	key, err := LoadKey("", envVar)
	if err != nil {
		t.Fatalf("LoadKey() error = %v", err)
	}

	if string(key) != keyValue {
		t.Errorf("LoadKey() = %q, want %q", string(key), keyValue)
	}
}

func TestLoadKey_FromFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "hmac.key")
	keyValue := "my-secret-key-from-file"

	if err := os.WriteFile(keyFile, []byte(keyValue), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	key, err := LoadKey(keyFile, "")
	if err != nil {
		t.Fatalf("LoadKey() error = %v", err)
	}

	if string(key) != keyValue {
		t.Errorf("LoadKey() = %q, want %q", string(key), keyValue)
	}
}

func TestLoadKey_FileTrimsWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "hmac.key")
	keyValue := "my-secret-key"

	// Write key with trailing newline (common from echo)
	if err := os.WriteFile(keyFile, []byte(keyValue+"\n"), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	key, err := LoadKey(keyFile, "")
	if err != nil {
		t.Fatalf("LoadKey() error = %v", err)
	}

	if string(key) != keyValue {
		t.Errorf("LoadKey() = %q, want %q", string(key), keyValue)
	}
}

func TestLoadKey_FilePriorityOverEnv(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "hmac.key")
	fileKey := "key-from-file"
	envKey := "key-from-env"
	envVar := "AGENTSH_TEST_AUDIT_KEY_PRIORITY"

	if err := os.WriteFile(keyFile, []byte(fileKey), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	t.Setenv(envVar, envKey)

	key, err := LoadKey(keyFile, envVar)
	if err != nil {
		t.Fatalf("LoadKey() error = %v", err)
	}

	// File should take priority
	if string(key) != fileKey {
		t.Errorf("LoadKey() = %q, want %q (file should take priority)", string(key), fileKey)
	}
}

func TestLoadKey_NoSource(t *testing.T) {
	_, err := LoadKey("", "")
	if err == nil {
		t.Fatal("LoadKey() expected error when no source specified")
	}
}

func TestLoadKey_EmptyEnvVar(t *testing.T) {
	envVar := "AGENTSH_TEST_EMPTY_KEY"
	t.Setenv(envVar, "")

	_, err := LoadKey("", envVar)
	if err == nil {
		t.Fatal("LoadKey() expected error for empty env var")
	}
}

func TestLoadKey_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "empty.key")

	if err := os.WriteFile(keyFile, []byte(""), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	_, err := LoadKey(keyFile, "")
	if err == nil {
		t.Fatal("LoadKey() expected error for empty file")
	}
}

func TestLoadKey_NonexistentFile(t *testing.T) {
	_, err := LoadKey("/nonexistent/path/key.file", "")
	if err == nil {
		t.Fatal("LoadKey() expected error for nonexistent file")
	}
}

func TestIntegrityChain_SHA512Algorithm(t *testing.T) {
	chain, err := NewIntegrityChainWithAlgorithm(testKey, "hmac-sha512")
	if err != nil {
		t.Fatalf("NewIntegrityChainWithAlgorithm() error = %v", err)
	}

	payload := []byte(`{"event":"test"}`)
	wrapped, err := chain.Wrap(payload)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	integrity := result["integrity"].(map[string]any)
	entryHash := integrity["entry_hash"].(string)

	// SHA-512 produces 128 hex characters (64 bytes)
	if len(entryHash) != 128 {
		t.Errorf("entry_hash length = %d, want 128 for SHA-512", len(entryHash))
	}
}

func TestIntegrityChain_SHA256Algorithm(t *testing.T) {
	chain, err := NewIntegrityChain(testKey) // default is SHA-256
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	payload := []byte(`{"event":"test"}`)
	wrapped, err := chain.Wrap(payload)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	integrity := result["integrity"].(map[string]any)
	entryHash := integrity["entry_hash"].(string)

	// SHA-256 produces 64 hex characters (32 bytes)
	if len(entryHash) != 64 {
		t.Errorf("entry_hash length = %d, want 64 for SHA-256", len(entryHash))
	}
}

func TestIntegrityChain_InvalidPayload(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	// Invalid JSON
	_, err = chain.Wrap([]byte("not valid json"))
	if err == nil {
		t.Fatal("Wrap() expected error for invalid JSON")
	}
}

func TestIntegrityChain_DifferentKeysProduceDifferentHashes(t *testing.T) {
	payload := []byte(`{"event":"test"}`)

	// Use 32-byte keys that meet minimum length
	chain1, err := NewIntegrityChain([]byte("key-one-that-is-32-bytes-long!!!"))
	if err != nil {
		t.Fatalf("NewIntegrityChain() chain1 error = %v", err)
	}
	chain2, err := NewIntegrityChain([]byte("key-two-that-is-32-bytes-long!!!"))
	if err != nil {
		t.Fatalf("NewIntegrityChain() chain2 error = %v", err)
	}

	wrapped1, err := chain1.Wrap(payload)
	if err != nil {
		t.Fatalf("Wrap() chain1 error = %v", err)
	}

	wrapped2, err := chain2.Wrap(payload)
	if err != nil {
		t.Fatalf("Wrap() chain2 error = %v", err)
	}

	var result1, result2 map[string]any
	json.Unmarshal(wrapped1, &result1)
	json.Unmarshal(wrapped2, &result2)

	hash1 := result1["integrity"].(map[string]any)["entry_hash"].(string)
	hash2 := result2["integrity"].(map[string]any)["entry_hash"].(string)

	if hash1 == hash2 {
		t.Error("different keys should produce different hashes")
	}
}

func TestNewIntegrityChain_KeyTooShort(t *testing.T) {
	shortKey := []byte("short") // less than MinKeyLength

	_, err := NewIntegrityChain(shortKey)
	if err == nil {
		t.Fatal("NewIntegrityChain() expected error for short key")
	}
	if !strings.Contains(err.Error(), "key too short") {
		t.Errorf("error = %q, want to contain 'key too short'", err.Error())
	}
}

func TestNewIntegrityChainWithAlgorithm_KeyTooShort(t *testing.T) {
	shortKey := []byte("short") // less than MinKeyLength

	_, err := NewIntegrityChainWithAlgorithm(shortKey, "hmac-sha256")
	if err == nil {
		t.Fatal("NewIntegrityChainWithAlgorithm() expected error for short key")
	}
	if !strings.Contains(err.Error(), "key too short") {
		t.Errorf("error = %q, want to contain 'key too short'", err.Error())
	}
}

func TestNewIntegrityChainWithAlgorithm_InvalidAlgorithm(t *testing.T) {
	_, err := NewIntegrityChainWithAlgorithm(testKey, "invalid-algo")
	if err == nil {
		t.Fatal("NewIntegrityChainWithAlgorithm() expected error for invalid algorithm")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Errorf("error = %q, want to contain 'unsupported algorithm'", err.Error())
	}
}

func TestNewIntegrityChainWithAlgorithm_EmptyAlgorithmDefaultsToSHA256(t *testing.T) {
	chain, err := NewIntegrityChainWithAlgorithm(testKey, "")
	if err != nil {
		t.Fatalf("NewIntegrityChainWithAlgorithm() error = %v", err)
	}

	payload := []byte(`{"event":"test"}`)
	wrapped, err := chain.Wrap(payload)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	integrity := result["integrity"].(map[string]any)
	entryHash := integrity["entry_hash"].(string)

	// SHA-256 produces 64 hex characters (32 bytes)
	if len(entryHash) != 64 {
		t.Errorf("entry_hash length = %d, want 64 for SHA-256 (default)", len(entryHash))
	}
}

// TestIntegrityChain_Wrap_ConcurrentSafety verifies that the legacy
// IntegrityChain.Wrap() preserves the single-mutex atomicity contract
// when called concurrently. Without wrapper-level locking, alloc.Next()
// from one goroutine can interleave with chain.Compute() from another,
// producing chains where prev_hash[seq] != entry_hash[seq-1] (or
// latching the chain fatal with ErrStaleResult).
func TestIntegrityChain_Wrap_ConcurrentSafety(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	const goroutines = 50
	const perGoroutine = 20
	const total = goroutines * perGoroutine

	var (
		mu      sync.Mutex
		entries = make([][]byte, 0, total)
		wrapErr error
	)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				payload := []byte(fmt.Sprintf(`{"goroutine":%d,"iteration":%d}`, g, i))
				wrapped, err := chain.Wrap(payload)
				mu.Lock()
				if err != nil && wrapErr == nil {
					wrapErr = fmt.Errorf("g=%d i=%d: Wrap: %w", g, i, err)
				}
				if err == nil {
					entries = append(entries, wrapped)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if wrapErr != nil {
		t.Fatalf("concurrent Wrap returned error: %v", wrapErr)
	}
	if len(entries) != total {
		t.Fatalf("got %d wrapped entries, want %d", len(entries), total)
	}

	entryHash := make(map[int64]string, total)
	prevHash := make(map[int64]string, total)
	for i, wrapped := range entries {
		var result map[string]any
		if err := json.Unmarshal(wrapped, &result); err != nil {
			t.Fatalf("entry %d unmarshal: %v", i, err)
		}
		integrity, ok := result["integrity"].(map[string]any)
		if !ok {
			t.Fatalf("entry %d: integrity field missing or not an object", i)
		}
		seq := int64(integrity["sequence"].(float64))
		eh := integrity["entry_hash"].(string)
		ph := integrity["prev_hash"].(string)
		if existing, dup := entryHash[seq]; dup {
			t.Fatalf("duplicate sequence %d: entry_hash=%q vs %q", seq, existing, eh)
		}
		entryHash[seq] = eh
		prevHash[seq] = ph
	}

	for seq := int64(0); seq < int64(total); seq++ {
		if _, ok := entryHash[seq]; !ok {
			t.Fatalf("missing sequence %d (sequences must be exactly 0..%d)", seq, total-1)
		}
	}

	for seq := int64(1); seq < int64(total); seq++ {
		want := entryHash[seq-1]
		if got := prevHash[seq]; got != want {
			t.Fatalf("chain integrity break at seq=%d: prev_hash=%q, want entry_hash[%d]=%q",
				seq, got, seq-1, want)
		}
	}
	if got := prevHash[0]; got != "" {
		t.Fatalf("genesis seq=0: prev_hash=%q, want empty", got)
	}

	for i, wrapped := range entries {
		ok, err := chain.VerifyWrapped(wrapped)
		if err != nil {
			t.Fatalf("entry %d VerifyWrapped: %v", i, err)
		}
		if !ok {
			t.Fatalf("entry %d VerifyWrapped: false (chain integrity broken)", i)
		}
	}
}

// TestIntegrityChain_State_SnapshotConsistency verifies that State()
// returns a consistent (sequence, prev_hash) snapshot — never a torn
// read where Sequence is from a newer wrap than PrevHash, or vice versa.
//
// Without wrapper-level locking, State() reads alloc.State() then
// chain.State() with no atomicity, so a concurrent Wrap can advance the
// allocator between the two reads (producing state.Sequence=N but
// state.PrevHash=hash[N-1]) or advance both (producing state.Sequence=N
// but state.PrevHash=hash[N+1] if the chain commit lands between reads).
func TestIntegrityChain_State_SnapshotConsistency(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	const wraps = 200
	const samples = 200

	// entryHashBySeq[seq] = entry_hash for the entry at that sequence.
	var entryHashBySeq sync.Map

	done := make(chan struct{})
	var wrapErr error
	go func() {
		defer close(done)
		for i := 0; i < wraps; i++ {
			payload := []byte(fmt.Sprintf(`{"i":%d}`, i))
			wrapped, err := chain.Wrap(payload)
			if err != nil {
				wrapErr = fmt.Errorf("Wrap %d: %w", i, err)
				return
			}
			var result map[string]any
			if err := json.Unmarshal(wrapped, &result); err != nil {
				wrapErr = fmt.Errorf("unmarshal %d: %w", i, err)
				return
			}
			integrity := result["integrity"].(map[string]any)
			seq := int64(integrity["sequence"].(float64))
			eh := integrity["entry_hash"].(string)
			entryHashBySeq.Store(seq, eh)
		}
	}()

	// Sample State() in parallel.
	type torn struct {
		seq      int64
		prevHash string
		want     string
	}
	var tornReads []torn
	for s := 0; s < samples; s++ {
		st := chain.State()
		// Genesis: sequence == -1 means no Wrap has completed; prev_hash must be empty.
		if st.Sequence == -1 {
			if st.PrevHash != "" {
				tornReads = append(tornReads, torn{seq: -1, prevHash: st.PrevHash, want: ""})
			}
			continue
		}
		// For any committed sequence s, the legacy contract is:
		// state.PrevHash == entry_hash[s] (the chain head equals the
		// most-recently-committed entry's hash).
		v, ok := entryHashBySeq.Load(st.Sequence)
		if !ok {
			// Allocator advanced past s but Wrap hasn't recorded entry_hash[s] yet.
			// This is itself a torn snapshot: alloc reports seq=s but the
			// committing goroutine hasn't yet stored its entry_hash, meaning
			// the wrapper exposed an alloc-state that is ahead of the
			// chain-state caller would observe. Defer the check by retrying
			// once after the writer goroutine completes.
			<-done
			if wrapErr != nil {
				t.Fatalf("background Wrap failed: %v", wrapErr)
			}
			v, ok = entryHashBySeq.Load(st.Sequence)
			if !ok {
				t.Fatalf("no entry_hash recorded for sampled seq=%d", st.Sequence)
			}
		}
		want := v.(string)
		if st.PrevHash != want {
			tornReads = append(tornReads, torn{seq: st.Sequence, prevHash: st.PrevHash, want: want})
		}
	}
	<-done
	if wrapErr != nil {
		t.Fatalf("background Wrap failed: %v", wrapErr)
	}
	if len(tornReads) > 0 {
		t.Fatalf("State() returned %d torn snapshots; first: seq=%d prev_hash=%q want=%q",
			len(tornReads), tornReads[0].seq, tornReads[0].prevHash, tornReads[0].want)
	}
}

// TestIntegrityChain_Restore_PartialFailure_LeavesStateIntact verifies
// that a Restore call rejected by the chain (invalid prev_hash) leaves
// the allocator unchanged. Without rollback, the allocator would be
// advanced before the chain validation runs, leaving the wrapper in a
// half-restored state where State().Sequence and State().PrevHash are
// inconsistent.
func TestIntegrityChain_Restore_PartialFailure_LeavesStateIntact(t *testing.T) {
	chain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := chain.Wrap([]byte(`{"event":"warmup"}`)); err != nil {
			t.Fatalf("Wrap %d: %v", i, err)
		}
	}

	s0 := chain.State()
	if s0.Sequence != 2 {
		t.Fatalf("pre-Restore State().Sequence = %d, want 2", s0.Sequence)
	}

	err = chain.Restore(99, "not-valid-hex")
	if err == nil {
		t.Fatal("Restore(99, \"not-valid-hex\") returned nil error, want rejection")
	}
	if !errors.Is(err, ErrInvalidChainState) {
		t.Fatalf("Restore error = %v, want errors.Is(err, ErrInvalidChainState)", err)
	}

	s1 := chain.State()
	if s1.Sequence != s0.Sequence {
		t.Fatalf("post-failed-Restore State().Sequence = %d, want %d (pre-call S0)",
			s1.Sequence, s0.Sequence)
	}
	if s1.PrevHash != s0.PrevHash {
		t.Fatalf("post-failed-Restore State().PrevHash = %q, want %q (pre-call S0)",
			s1.PrevHash, s0.PrevHash)
	}

	wrapped, err := chain.Wrap([]byte(`{"event":"after_failed_restore"}`))
	if err != nil {
		t.Fatalf("Wrap after failed Restore: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(wrapped, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	integrity := result["integrity"].(map[string]any)
	if got := int64(integrity["sequence"].(float64)); got != s0.Sequence+1 {
		t.Fatalf("post-Restore Wrap sequence = %d, want %d (S0.Sequence+1; allocator advanced by failed Restore)",
			got, s0.Sequence+1)
	}
	if got := integrity["prev_hash"].(string); got != s0.PrevHash {
		t.Fatalf("post-Restore Wrap prev_hash = %q, want %q (chain advanced by failed Restore)",
			got, s0.PrevHash)
	}
}
