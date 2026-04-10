package session

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/internal/proxy/credsub"
	"github.com/agentsh/agentsh/internal/proxy/secrets"
)

// memoryProvider implements SecretFetcher for testing.
type memoryProvider struct {
	secrets map[string][]byte
}

func (p *memoryProvider) Fetch(_ context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	key := ref.Host + "/" + ref.Path
	if ref.Field != "" {
		key += "#" + ref.Field
	}
	val, ok := p.secrets[key]
	if !ok {
		return secrets.SecretValue{}, secrets.ErrNotFound
	}
	out := make([]byte, len(val))
	copy(out, val)
	return secrets.SecretValue{Value: out}, nil
}

func TestBootstrapCredentials_HappyPath(t *testing.T) {
	mp := &memoryProvider{
		secrets: map[string][]byte{
			// ghp_ (4) + 36 = 40 total
			"github/token": []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
		},
	}

	services := []ServiceConfig{
		{
			Name:       "github",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "github", Path: "token"},
			FakeFormat: "ghp_{rand:36}",
		},
	}

	table, cleanup, err := BootstrapCredentials(context.Background(), mp, services)
	if err != nil {
		t.Fatalf("BootstrapCredentials returned error: %v", err)
	}
	defer cleanup()

	if table.Len() != 1 {
		t.Errorf("table.Len() = %d, want 1", table.Len())
	}

	fake, ok := table.FakeForService("github")
	if !ok {
		t.Fatal("FakeForService(github) not found")
	}
	if len(fake) != 40 {
		t.Errorf("fake length = %d, want 40", len(fake))
	}
	if string(fake[:4]) != "ghp_" {
		t.Errorf("fake prefix = %q, want %q", string(fake[:4]), "ghp_")
	}
}

func TestBootstrapCredentials_FetchError_CleansUp(t *testing.T) {
	mp := &memoryProvider{secrets: map[string][]byte{}}

	services := []ServiceConfig{
		{
			Name:       "github",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "github", Path: "token"},
			FakeFormat: "ghp_{rand:36}",
		},
	}

	table, cleanup, err := BootstrapCredentials(context.Background(), mp, services)
	if err == nil {
		t.Fatal("expected error when secret not found")
	}
	if table != nil {
		t.Error("table should be nil on error")
	}
	if cleanup != nil {
		t.Error("cleanup should be nil on error")
	}
}

func TestBootstrapCredentials_InvalidFormat_CleansUp(t *testing.T) {
	mp := &memoryProvider{
		secrets: map[string][]byte{
			"github/token": []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ1234"),
		},
	}

	services := []ServiceConfig{
		{
			Name:       "github",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "github", Path: "token"},
			FakeFormat: "bad_format_no_placeholder",
		},
	}

	_, _, err := BootstrapCredentials(context.Background(), mp, services)
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !errors.Is(err, secrets.ErrInvalidFakeFormat) {
		t.Errorf("expected ErrInvalidFakeFormat, got: %v", err)
	}
}

func TestBootstrapCredentials_LengthMismatch_CleansUp(t *testing.T) {
	mp := &memoryProvider{
		secrets: map[string][]byte{
			// Real is 42 bytes, but format produces 51 (sk- + 48 = 51)
			"openai/key": []byte("sk-realABCDEFGHIJKLMNOPQRSTUVWXYZ12345678"),
		},
	}

	services := []ServiceConfig{
		{
			Name:       "openai",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "openai", Path: "key"},
			FakeFormat: "sk-{rand:48}",
		},
	}

	_, _, err := BootstrapCredentials(context.Background(), mp, services)
	if err == nil {
		t.Fatal("expected error for length mismatch")
	}
	if !errors.Is(err, secrets.ErrFakeLengthMismatch) {
		t.Errorf("expected ErrFakeLengthMismatch, got: %v", err)
	}
}

func TestBootstrapCredentials_MultipleServices(t *testing.T) {
	mp := &memoryProvider{
		secrets: map[string][]byte{
			"github/token": []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
			"openai/key":   []byte("sk-realXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDE"),
		},
	}

	services := []ServiceConfig{
		{
			Name:       "github",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "github", Path: "token"},
			FakeFormat: "ghp_{rand:36}",
		},
		{
			Name:       "openai",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "openai", Path: "key"},
			FakeFormat: "sk-{rand:48}",
		},
	}

	table, cleanup, err := BootstrapCredentials(context.Background(), mp, services)
	if err != nil {
		t.Fatalf("BootstrapCredentials returned error: %v", err)
	}
	defer cleanup()

	if table.Len() != 2 {
		t.Errorf("table.Len() = %d, want 2", table.Len())
	}
}

func TestBootstrapCredentials_Cleanup_ZerosTable(t *testing.T) {
	mp := &memoryProvider{
		secrets: map[string][]byte{
			"github/token": []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
		},
	}

	services := []ServiceConfig{
		{
			Name:       "github",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "github", Path: "token"},
			FakeFormat: "ghp_{rand:36}",
		},
	}

	table, cleanup, err := BootstrapCredentials(context.Background(), mp, services)
	if err != nil {
		t.Fatal(err)
	}

	if table.Len() != 1 {
		t.Fatalf("table should have 1 entry before cleanup")
	}

	cleanup()

	if table.Len() != 0 {
		t.Errorf("table.Len() = %d after cleanup, want 0", table.Len())
	}
}

func TestBuildServiceEnvVars(t *testing.T) {
	mp := &memoryProvider{
		secrets: map[string][]byte{
			"github/token": []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
		},
	}
	services := []ServiceConfig{
		{
			Name:       "github",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "github", Path: "token"},
			FakeFormat: "ghp_{rand:36}",
		},
	}
	table, cleanup, err := BootstrapCredentials(context.Background(), mp, services)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	envVars := []ServiceEnvVar{
		{ServiceName: "github", VarName: "GITHUB_TOKEN"},
	}
	result, err := BuildServiceEnvVars(envVars, table)
	if err != nil {
		t.Fatalf("BuildServiceEnvVars returned error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 env var, got %d", len(result))
	}
	val, ok := result["GITHUB_TOKEN"]
	if !ok {
		t.Fatal("GITHUB_TOKEN not in result")
	}
	if len(val) != 40 {
		t.Errorf("value length = %d, want 40", len(val))
	}
	if val[:4] != "ghp_" {
		t.Errorf("value prefix = %q, want ghp_", val[:4])
	}
}

func TestBuildServiceEnvVars_UnknownService(t *testing.T) {
	table := credsub.New()
	envVars := []ServiceEnvVar{
		{ServiceName: "nonexistent", VarName: "FOO"},
	}
	result, err := BuildServiceEnvVars(envVars, table)
	if err != nil {
		t.Fatalf("BuildServiceEnvVars returned error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestBuildServiceEnvVars_Empty(t *testing.T) {
	table := credsub.New()
	result, err := BuildServiceEnvVars(nil, table)
	if err != nil {
		t.Fatalf("BuildServiceEnvVars returned error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestBuildServiceEnvVars_DuplicateName(t *testing.T) {
	mp := &memoryProvider{
		secrets: map[string][]byte{
			"github/token": []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
			"gitlab/token": []byte("glpat-realABCDEFGHIJKLMNOPQRSTUVWXYZ12345"),
		},
	}
	services := []ServiceConfig{
		{
			Name:       "github",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "github", Path: "token"},
			FakeFormat: "ghp_{rand:36}",
		},
		{
			Name:       "gitlab",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "gitlab", Path: "token"},
			FakeFormat: "glpat-{rand:35}",
		},
	}
	table, cleanup, err := BootstrapCredentials(context.Background(), mp, services)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	envVars := []ServiceEnvVar{
		{ServiceName: "github", VarName: "TOKEN"},
		{ServiceName: "gitlab", VarName: "TOKEN"},
	}
	_, err = BuildServiceEnvVars(envVars, table)
	if err == nil {
		t.Fatal("expected error for duplicate env var name")
	}
	want := `duplicate service env var "TOKEN" (services "github" and "gitlab")`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestBuildServiceEnvVars_CaseDifferentNames(t *testing.T) {
	table := credsub.New()
	_ = table.Add("svc1", []byte("fake1_ABCDEFGHIJKLMNOPQRSTUVWX"), []byte("real1_ABCDEFGHIJKLMNOPQRSTUVWX"))
	_ = table.Add("svc2", []byte("fake2_ABCDEFGHIJKLMNOPQRSTUVWX"), []byte("real2_ABCDEFGHIJKLMNOPQRSTUVWX"))

	envVars := []ServiceEnvVar{
		{ServiceName: "svc1", VarName: "TOKEN"},
		{ServiceName: "svc2", VarName: "token"},
	}
	result, err := BuildServiceEnvVars(envVars, table)
	if runtime.GOOS == "windows" {
		// Windows: case-insensitive, should collide
		if err == nil {
			t.Fatal("expected collision on Windows")
		}
	} else {
		// POSIX: case-sensitive, both should work
		if err != nil {
			t.Fatalf("unexpected error on POSIX: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("expected 2 vars, got %d", len(result))
		}
	}
}

func TestBuildServiceEnvVars_DuplicateName_MissingFromTable(t *testing.T) {
	// Only github is in the table; gitlab is missing.
	// The duplicate should still be detected even though gitlab
	// would be skipped during table lookup.
	mp := &memoryProvider{
		secrets: map[string][]byte{
			"github/token": []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
		},
	}
	services := []ServiceConfig{
		{
			Name:       "github",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "github", Path: "token"},
			FakeFormat: "ghp_{rand:36}",
		},
	}
	table, cleanup, err := BootstrapCredentials(context.Background(), mp, services)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	envVars := []ServiceEnvVar{
		{ServiceName: "github", VarName: "TOKEN"},
		{ServiceName: "gitlab", VarName: "TOKEN"}, // gitlab not in table
	}
	_, err = BuildServiceEnvVars(envVars, table)
	if err == nil {
		t.Fatal("expected error for duplicate env var name even when service is missing from table")
	}
	want := `duplicate service env var "TOKEN" (services "github" and "gitlab")`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestBuildServiceEnvVars_NilTable(t *testing.T) {
	envVars := []ServiceEnvVar{
		{ServiceName: "github", VarName: "GITHUB_TOKEN"},
	}
	result, err := BuildServiceEnvVars(envVars, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestBuildServiceEnvVars_NilTable_StillValidates(t *testing.T) {
	envVars := []ServiceEnvVar{
		{ServiceName: "svc", VarName: ""},
	}
	_, err := BuildServiceEnvVars(envVars, nil)
	if err == nil {
		t.Fatal("expected validation error even with nil table")
	}
}

func TestBuildServiceEnvVars_InvalidName_Empty(t *testing.T) {
	table := credsub.New()
	envVars := []ServiceEnvVar{
		{ServiceName: "svc", VarName: ""},
	}
	_, err := BuildServiceEnvVars(envVars, table)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestBuildServiceEnvVars_InvalidName_ContainsEquals(t *testing.T) {
	table := credsub.New()
	envVars := []ServiceEnvVar{
		{ServiceName: "svc", VarName: "PATH=/tmp"},
	}
	_, err := BuildServiceEnvVars(envVars, table)
	if err == nil {
		t.Fatal("expected error for name containing =")
	}
}
