package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	if !ok || seq != 1 {
		t.Errorf("integrity.sequence = %v, want 1", integrity["sequence"])
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
		if seq != int64(i+1) {
			t.Errorf("entry %d: sequence = %d, want %d", i, seq, i+1)
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
	if state.Sequence != 3 {
		t.Errorf("State().Sequence = %d, want 3", state.Sequence)
	}

	// Create new chain and restore state
	newChain, err := NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain() error = %v", err)
	}
	newChain.Restore(state.Sequence, state.PrevHash)

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

	// Should continue from sequence 4
	if seq := int64(integrity["sequence"].(float64)); seq != 4 {
		t.Errorf("sequence after restore = %d, want 4", seq)
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
