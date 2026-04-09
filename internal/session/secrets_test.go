package session

import (
	"context"
	"errors"
	"testing"

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
