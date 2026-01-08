package kms

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileProvider_FromFile(t *testing.T) {
	// Create temp key file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test.key")
	testKey := "this-is-a-test-key-for-hmac-operations"
	if err := os.WriteFile(keyFile, []byte(testKey), 0600); err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}

	provider, err := NewFileProvider(keyFile, "")
	if err != nil {
		t.Fatalf("NewFileProvider failed: %v", err)
	}
	defer provider.Close()

	if provider.Name() != "file:"+keyFile {
		t.Errorf("Name() = %q, want %q", provider.Name(), "file:"+keyFile)
	}

	key, err := provider.GetKey(context.Background())
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if string(key) != testKey {
		t.Errorf("GetKey() = %q, want %q", string(key), testKey)
	}

	// Test caching - second call should return same result
	key2, err := provider.GetKey(context.Background())
	if err != nil {
		t.Fatalf("GetKey (cached) failed: %v", err)
	}
	if string(key2) != testKey {
		t.Errorf("GetKey (cached) = %q, want %q", string(key2), testKey)
	}
}

func TestFileProvider_FromEnv(t *testing.T) {
	envName := "TEST_KMS_KEY_" + t.Name()
	testKey := "env-based-test-key-for-hmac"
	os.Setenv(envName, testKey)
	defer os.Unsetenv(envName)

	provider, err := NewFileProvider("", envName)
	if err != nil {
		t.Fatalf("NewFileProvider failed: %v", err)
	}
	defer provider.Close()

	if provider.Name() != "env:"+envName {
		t.Errorf("Name() = %q, want %q", provider.Name(), "env:"+envName)
	}

	key, err := provider.GetKey(context.Background())
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if string(key) != testKey {
		t.Errorf("GetKey() = %q, want %q", string(key), testKey)
	}
}

func TestFileProvider_MissingFile(t *testing.T) {
	provider, err := NewFileProvider("/nonexistent/path/to/key", "")
	if err != nil {
		t.Fatalf("NewFileProvider failed: %v", err)
	}
	defer provider.Close()

	_, err = provider.GetKey(context.Background())
	if err == nil {
		t.Error("GetKey should fail for missing file")
	}
}

func TestFileProvider_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "empty.key")
	if err := os.WriteFile(keyFile, []byte("   \n  "), 0600); err != nil {
		t.Fatalf("Failed to write empty key: %v", err)
	}

	provider, err := NewFileProvider(keyFile, "")
	if err != nil {
		t.Fatalf("NewFileProvider failed: %v", err)
	}
	defer provider.Close()

	_, err = provider.GetKey(context.Background())
	if err == nil {
		t.Error("GetKey should fail for empty file")
	}
}

func TestFileProvider_MissingEnv(t *testing.T) {
	provider, err := NewFileProvider("", "NONEXISTENT_ENV_VAR_FOR_KMS_TEST")
	if err != nil {
		t.Fatalf("NewFileProvider failed: %v", err)
	}
	defer provider.Close()

	_, err = provider.GetKey(context.Background())
	if err == nil {
		t.Error("GetKey should fail for missing env var")
	}
}

func TestFileProvider_NoSource(t *testing.T) {
	_, err := NewFileProvider("", "")
	if err == nil {
		t.Error("NewFileProvider should fail with no source")
	}
}

func TestNewProvider_File(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test.key")
	testKey := "provider-factory-test-key"
	if err := os.WriteFile(keyFile, []byte(testKey), 0600); err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}

	provider, err := NewProvider(Config{
		Source:  "file",
		KeyFile: keyFile,
	})
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer provider.Close()

	key, err := provider.GetKey(context.Background())
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if string(key) != testKey {
		t.Errorf("GetKey() = %q, want %q", string(key), testKey)
	}
}

func TestNewProvider_Env(t *testing.T) {
	envName := "TEST_KMS_PROVIDER_" + t.Name()
	testKey := "provider-env-test-key"
	os.Setenv(envName, testKey)
	defer os.Unsetenv(envName)

	provider, err := NewProvider(Config{
		Source: "env",
		KeyEnv: envName,
	})
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer provider.Close()

	key, err := provider.GetKey(context.Background())
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if string(key) != testKey {
		t.Errorf("GetKey() = %q, want %q", string(key), testKey)
	}
}

func TestNewProvider_UnknownSource(t *testing.T) {
	_, err := NewProvider(Config{
		Source: "unknown_source",
	})
	if err == nil {
		t.Error("NewProvider should fail for unknown source")
	}
}

func TestAWSKMSProvider_Validation(t *testing.T) {
	_, err := NewAWSKMSProvider("", "us-east-1", "")
	if err == nil {
		t.Error("NewAWSKMSProvider should fail without key_id")
	}
}

func TestAzureKeyVaultProvider_Validation(t *testing.T) {
	_, err := NewAzureKeyVaultProvider("", "key-name", "")
	if err == nil {
		t.Error("NewAzureKeyVaultProvider should fail without vault_url")
	}

	_, err = NewAzureKeyVaultProvider("https://vault.azure.net", "", "")
	if err == nil {
		t.Error("NewAzureKeyVaultProvider should fail without key_name")
	}
}

func TestVaultProvider_Validation(t *testing.T) {
	_, err := NewVaultProvider(VaultConfig{
		Address:    "",
		SecretPath: "secret/data/test",
	})
	if err == nil {
		t.Error("NewVaultProvider should fail without address")
	}

	_, err = NewVaultProvider(VaultConfig{
		Address:    "https://vault.example.com",
		SecretPath: "",
	})
	if err == nil {
		t.Error("NewVaultProvider should fail without secret_path")
	}
}

func TestGCPKMSProvider_Validation(t *testing.T) {
	_, err := NewGCPKMSProvider("", "")
	if err == nil {
		t.Error("NewGCPKMSProvider should fail without key_name")
	}
}

// Note: Integration tests for actual KMS providers require credentials
// and are typically run in CI with appropriate secrets configured.
// These tests focus on validation and the file provider which can run locally.
