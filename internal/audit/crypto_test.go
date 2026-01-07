package audit

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptor_RoundTrip(t *testing.T) {
	// Generate a valid 32-byte key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"small", []byte("hello world")},
		{"medium", bytes.Repeat([]byte("x"), 1000)},
		{"large", bytes.Repeat([]byte("y"), 100000)},
		{"json", []byte(`{"event":"test","timestamp":"2024-01-01T00:00:00Z"}`)},
		{"binary", []byte{0x00, 0xff, 0x01, 0xfe, 0x02, 0xfd}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			// Ciphertext should be different from plaintext
			if bytes.Equal(ciphertext, tc.plaintext) && len(tc.plaintext) > 0 {
				t.Error("ciphertext equals plaintext")
			}

			// Ciphertext should be longer than plaintext (nonce + tag)
			if len(ciphertext) <= len(tc.plaintext) {
				t.Errorf("ciphertext too short: got %d, want > %d", len(ciphertext), len(tc.plaintext))
			}

			decrypted, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("decrypted != plaintext: got %q, want %q", decrypted, tc.plaintext)
			}
		})
	}
}

func TestEncryptor_DifferentCiphertexts(t *testing.T) {
	// Same plaintext should produce different ciphertext each time (due to random nonce)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	plaintext := []byte("same plaintext")
	ciphertext1, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}

	ciphertext2, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("same plaintext produced identical ciphertexts (nonce reuse)")
	}
}

func TestEncryptor_InvalidKey(t *testing.T) {
	testCases := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{"too_short_16", 16, true},
		{"too_short_31", 31, true},
		{"valid_32", 32, false},
		{"too_long_33", 33, true},
		{"too_long_64", 64, true},
		{"empty", 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keyLen)
			_, err := NewEncryptor(key)
			if (err != nil) != tc.wantErr {
				t.Errorf("NewEncryptor(%d bytes): got err=%v, wantErr=%v", tc.keyLen, err, tc.wantErr)
			}
		})
	}
}

func TestEncryptor_TamperDetection(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	plaintext := []byte("sensitive audit data")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	testCases := []struct {
		name   string
		tamper func([]byte) []byte
	}{
		{
			"flip_first_byte",
			func(ct []byte) []byte {
				tampered := make([]byte, len(ct))
				copy(tampered, ct)
				tampered[0] ^= 0xff
				return tampered
			},
		},
		{
			"flip_middle_byte",
			func(ct []byte) []byte {
				tampered := make([]byte, len(ct))
				copy(tampered, ct)
				tampered[len(ct)/2] ^= 0xff
				return tampered
			},
		},
		{
			"flip_last_byte",
			func(ct []byte) []byte {
				tampered := make([]byte, len(ct))
				copy(tampered, ct)
				tampered[len(ct)-1] ^= 0xff
				return tampered
			},
		},
		{
			"truncate",
			func(ct []byte) []byte {
				return ct[:len(ct)-1]
			},
		},
		{
			"append_byte",
			func(ct []byte) []byte {
				return append(ct, 0x00)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := tc.tamper(ciphertext)
			_, err := enc.Decrypt(tampered)
			if err == nil {
				t.Error("expected decryption to fail with tampered ciphertext")
			}
		})
	}
}

func TestEncryptor_DecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	// GCM nonce size is 12 bytes, so anything shorter should fail
	shortCiphertexts := [][]byte{
		{},
		{0x01},
		{0x01, 0x02, 0x03},
		make([]byte, 11),
	}

	for i, ct := range shortCiphertexts {
		_, err := enc.Decrypt(ct)
		if err == nil {
			t.Errorf("test %d: expected error for ciphertext of length %d", i, len(ct))
		}
	}
}

func TestEncryptor_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	if _, err := rand.Read(key1); err != nil {
		t.Fatalf("generate key1: %v", err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatalf("generate key2: %v", err)
	}

	enc1, err := NewEncryptor(key1)
	if err != nil {
		t.Fatalf("NewEncryptor key1: %v", err)
	}
	enc2, err := NewEncryptor(key2)
	if err != nil {
		t.Fatalf("NewEncryptor key2: %v", err)
	}

	plaintext := []byte("encrypted with key1")
	ciphertext, err := enc1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Decrypting with wrong key should fail
	_, err = enc2.Decrypt(ciphertext)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

func TestLoadEncryptionKey_FromFile(t *testing.T) {
	// Create a temporary key file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test.key")

	// Write a 32-byte key
	keyContent := bytes.Repeat([]byte("k"), 32)
	if err := os.WriteFile(keyFile, keyContent, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	key, err := LoadEncryptionKey(keyFile, "")
	if err != nil {
		t.Fatalf("LoadEncryptionKey: %v", err)
	}

	if !bytes.Equal(key, keyContent) {
		t.Errorf("key mismatch: got %d bytes, want %d bytes", len(key), len(keyContent))
	}
}

func TestLoadEncryptionKey_FromFileTruncates(t *testing.T) {
	// Create a temporary key file with more than 32 bytes
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test.key")

	// Write a 64-byte key
	keyContent := bytes.Repeat([]byte("k"), 64)
	if err := os.WriteFile(keyFile, keyContent, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	key, err := LoadEncryptionKey(keyFile, "")
	if err != nil {
		t.Fatalf("LoadEncryptionKey: %v", err)
	}

	// Should truncate to 32 bytes
	if len(key) != 32 {
		t.Errorf("key should be truncated to 32 bytes, got %d", len(key))
	}
	if !bytes.Equal(key, keyContent[:32]) {
		t.Error("key content mismatch after truncation")
	}
}

func TestLoadEncryptionKey_FromEnv(t *testing.T) {
	envKey := "TEST_AGENTSH_ENCRYPTION_KEY"
	keyValue := bytes.Repeat([]byte("e"), 32)

	// Set the environment variable
	os.Setenv(envKey, string(keyValue))
	defer os.Unsetenv(envKey)

	key, err := LoadEncryptionKey("", envKey)
	if err != nil {
		t.Fatalf("LoadEncryptionKey: %v", err)
	}

	if !bytes.Equal(key, keyValue) {
		t.Errorf("key mismatch: got %d bytes, want %d bytes", len(key), len(keyValue))
	}
}

func TestLoadEncryptionKey_EnvTakesPrecedence(t *testing.T) {
	// Create a temporary key file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test.key")

	// Write a different key to the file
	fileKey := bytes.Repeat([]byte("f"), 32)
	if err := os.WriteFile(keyFile, fileKey, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	// Set environment variable with different key
	envKeyName := "TEST_AGENTSH_ENCRYPTION_KEY_PRECEDENCE"
	envKey := bytes.Repeat([]byte("e"), 32)
	os.Setenv(envKeyName, string(envKey))
	defer os.Unsetenv(envKeyName)

	// Env should take precedence
	key, err := LoadEncryptionKey(keyFile, envKeyName)
	if err != nil {
		t.Fatalf("LoadEncryptionKey: %v", err)
	}

	if !bytes.Equal(key, envKey) {
		t.Error("env key should take precedence over file key")
	}
}

func TestLoadEncryptionKey_FileTooShort(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "short.key")

	// Write a key that's too short
	shortKey := bytes.Repeat([]byte("s"), 16)
	if err := os.WriteFile(keyFile, shortKey, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	_, err := LoadEncryptionKey(keyFile, "")
	if err == nil {
		t.Error("expected error for key file that's too short")
	}
}

func TestLoadEncryptionKey_FileNotFound(t *testing.T) {
	_, err := LoadEncryptionKey("/nonexistent/key/file", "")
	if err == nil {
		t.Error("expected error for nonexistent key file")
	}
}

func TestLoadEncryptionKey_NoSource(t *testing.T) {
	_, err := LoadEncryptionKey("", "")
	if err == nil {
		t.Error("expected error when no key source is configured")
	}
}

func TestLoadEncryptionKey_EmptyEnvVar(t *testing.T) {
	envKeyName := "TEST_AGENTSH_ENCRYPTION_KEY_EMPTY"
	os.Setenv(envKeyName, "")
	defer os.Unsetenv(envKeyName)

	// Should fall back to returning "no encryption key configured"
	_, err := LoadEncryptionKey("", envKeyName)
	if err == nil {
		t.Error("expected error when env var is empty")
	}
}
