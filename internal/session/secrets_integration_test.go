package session

import (
	"bytes"
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/proxy/secrets"
)

func TestCredentialPipeline_EndToEnd(t *testing.T) {
	// Set up a memory provider with a known secret.
	realSecret := []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
	mp := &memoryProvider{
		secrets: map[string][]byte{
			"github/token": realSecret,
		},
	}

	services := []ServiceConfig{
		{
			Name:       "github",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "github", Path: "token"},
			FakeFormat: "ghp_{rand:36}",
		},
	}

	// Bootstrap credentials.
	table, cleanup, err := BootstrapCredentials(context.Background(), mp, services)
	if err != nil {
		t.Fatalf("BootstrapCredentials: %v", err)
	}
	defer cleanup()

	// Get the fake that was generated.
	fake, ok := table.FakeForService("github")
	if !ok {
		t.Fatal("no fake for github")
	}

	// Verify fake->real substitution.
	reqBody := []byte(`{"token":"` + string(fake) + `"}`)
	replaced := table.ReplaceFakeToReal(reqBody)
	wantReq := []byte(`{"token":"` + string(realSecret) + `"}`)
	if !bytes.Equal(replaced, wantReq) {
		t.Errorf("ReplaceFakeToReal:\n  got:  %s\n  want: %s", replaced, wantReq)
	}

	// Verify real->fake scrubbing.
	respBody := []byte(`{"echoed":"` + string(realSecret) + `"}`)
	scrubbed := table.ReplaceRealToFake(respBody)
	wantResp := []byte(`{"echoed":"` + string(fake) + `"}`)
	if !bytes.Equal(scrubbed, wantResp) {
		t.Errorf("ReplaceRealToFake:\n  got:  %s\n  want: %s", scrubbed, wantResp)
	}

	// Verify leak guard detects fake in body.
	serviceName, found := table.ContainsFake(reqBody)
	if !found {
		t.Error("ContainsFake should detect fake in request body")
	}
	if serviceName != "github" {
		t.Errorf("serviceName = %q, want %q", serviceName, "github")
	}

	// Verify no false positive.
	cleanBody := []byte(`{"message":"hello world"}`)
	_, found = table.ContainsFake(cleanBody)
	if found {
		t.Error("ContainsFake should not flag clean body")
	}
}
