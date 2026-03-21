package hotreload

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy/signing"
)

// signingLoader implements PolicyLoader with real Ed25519 signature verification.
type signingLoader struct {
	mu         sync.Mutex
	trustStore *signing.TrustStore
	mode       string // "enforce", "warn", "off"
	loaded     []string
}

func (l *signingLoader) Validate(path string) error {
	switch l.mode {
	case "enforce":
		_, err := signing.VerifyPolicy(path, l.trustStore)
		if err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
		return nil
	case "warn":
		if _, err := os.Stat(path + ".sig"); err == nil {
			if _, err := signing.VerifyPolicy(path, l.trustStore); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: signature verification failed for %s: %v\n", path, err)
			}
		}
		return nil
	default:
		return nil
	}
}

func (l *signingLoader) LoadFromPath(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loaded = append(l.loaded, path)
	return nil
}

func (l *signingLoader) Loaded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.loaded...)
}

// TestStagingIntegration_SignStagePromoteReload exercises the full flow:
//  1. Generate Ed25519 keypair
//  2. Create trust store with public key
//  3. Write and sign a policy
//  4. Drop .sig then .yaml into .staging/
//  5. Watcher validates signature, promotes to live dir
//  6. Live dir change triggers reload (LoadFromPath called)
func TestStagingIntegration_SignStagePromoteReload(t *testing.T) {
	// --- Setup: keys and trust store ---
	keysDir := t.TempDir()
	_, err := signing.GenerateKeypair(keysDir, "integration-test")
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	trustStore, err := signing.LoadTrustStore(keysDir, true)
	if err != nil {
		t.Fatalf("load trust store: %v", err)
	}

	priv, err := signing.LoadPrivateKey(filepath.Join(keysDir, "private.key.json"))
	if err != nil {
		t.Fatalf("load private key: %v", err)
	}

	// --- Setup: policy directory ---
	policyDir := t.TempDir()
	stagingDir := filepath.Join(policyDir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	// --- Setup: loader with enforce mode ---
	loader := &signingLoader{
		trustStore: trustStore,
		mode:       "enforce",
	}

	// --- Setup: watcher ---
	stagingDone := make(chan string, 1)
	reloadDone := make(chan string, 1)

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       policyDir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 200 * time.Millisecond,
		OnStaging: func(path string, err error) {
			if err != nil {
				t.Errorf("staging error: %v", err)
			}
			select {
			case stagingDone <- path:
			default:
			}
		},
		OnChange: func(path string, err error) {
			select {
			case reloadDone <- path:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("NewPolicyWatcher: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer watcher.Stop()

	// --- Sign the policy ---
	policyContent := []byte("name: integration-test\nversion: 1\nrules:\n  - allow: all\n")
	sig, err := signing.Sign(policyContent, priv, "integration-test")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigJSON, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		t.Fatalf("marshal sig: %v", err)
	}

	// --- Stage: write .sig first, then .yaml (recommended order) ---
	if err := os.WriteFile(filepath.Join(stagingDir, "test-policy.yaml.sig"), sigJSON, 0644); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(stagingDir, "test-policy.yaml"), policyContent, 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	// --- Verify: staging promotion ---
	select {
	case promotedPath := <-stagingDone:
		expected := filepath.Join(policyDir, "test-policy.yaml")
		if promotedPath != expected {
			t.Fatalf("promoted path = %q, want %q", promotedPath, expected)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for staging promotion")
	}

	// --- Verify: files moved to live dir ---
	livePolicy := filepath.Join(policyDir, "test-policy.yaml")
	data, err := os.ReadFile(livePolicy)
	if err != nil {
		t.Fatalf("policy not in live dir: %v", err)
	}
	if string(data) != string(policyContent) {
		t.Fatalf("policy content mismatch")
	}

	liveSig := filepath.Join(policyDir, "test-policy.yaml.sig")
	if _, err := os.Stat(liveSig); err != nil {
		t.Fatalf(".sig not in live dir: %v", err)
	}

	// --- Verify: staging dir is clean ---
	if _, err := os.Stat(filepath.Join(stagingDir, "test-policy.yaml")); !os.IsNotExist(err) {
		t.Fatal("policy still in staging")
	}
	if _, err := os.Stat(filepath.Join(stagingDir, "test-policy.yaml.sig")); !os.IsNotExist(err) {
		t.Fatal(".sig still in staging")
	}

	// --- Verify: live reload triggered ---
	select {
	case reloadPath := <-reloadDone:
		if reloadPath != livePolicy {
			t.Fatalf("reload path = %q, want %q", reloadPath, livePolicy)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for live reload")
	}

	// --- Verify: loader was called ---
	loaded := loader.Loaded()
	if len(loaded) == 0 {
		t.Fatal("LoadFromPath never called")
	}

	// --- Verify: stats ---
	stats := watcher.Stats()
	if stats.StagingTotal == 0 {
		t.Error("StagingTotal should be > 0")
	}
	if stats.StagingSuccess == 0 {
		t.Error("StagingSuccess should be > 0")
	}
	if stats.StagingFailed != 0 {
		t.Errorf("StagingFailed should be 0, got %d", stats.StagingFailed)
	}
}

// TestStagingIntegration_TamperedPolicyRejected verifies that a policy with
// a tampered signature is rejected in enforce mode and stays in staging.
func TestStagingIntegration_TamperedPolicyRejected(t *testing.T) {
	// --- Setup: keys ---
	keysDir := t.TempDir()
	_, err := signing.GenerateKeypair(keysDir, "test")
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	trustStore, err := signing.LoadTrustStore(keysDir, true)
	if err != nil {
		t.Fatalf("load trust store: %v", err)
	}

	priv, err := signing.LoadPrivateKey(filepath.Join(keysDir, "private.key.json"))
	if err != nil {
		t.Fatalf("load private key: %v", err)
	}

	// --- Setup: policy dir and watcher ---
	policyDir := t.TempDir()
	stagingDir := filepath.Join(policyDir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	loader := &signingLoader{trustStore: trustStore, mode: "enforce"}

	stagingDone := make(chan error, 1)
	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       policyDir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 200 * time.Millisecond,
		OnStaging: func(path string, err error) {
			stagingDone <- err
		},
	})
	if err != nil {
		t.Fatalf("NewPolicyWatcher: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// --- Sign the original policy ---
	originalContent := []byte("name: original\n")
	sig, _ := signing.Sign(originalContent, priv, "test")
	sigJSON, _ := json.MarshalIndent(sig, "", "  ")

	// --- Tamper: write signature for original but different policy content ---
	tamperedContent := []byte("name: tampered\n")
	os.WriteFile(filepath.Join(stagingDir, "tampered.yaml.sig"), sigJSON, 0644)
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(filepath.Join(stagingDir, "tampered.yaml"), tamperedContent, 0644)

	// --- Verify: rejected ---
	select {
	case err := <-stagingDone:
		if err == nil {
			t.Fatal("expected tampered policy to be rejected")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	// File stays in staging
	if _, err := os.Stat(filepath.Join(stagingDir, "tampered.yaml")); err != nil {
		t.Fatal("tampered file should remain in staging")
	}

	// Not promoted
	if _, err := os.Stat(filepath.Join(policyDir, "tampered.yaml")); !os.IsNotExist(err) {
		t.Fatal("tampered policy should NOT be in live dir")
	}

	stats := watcher.Stats()
	if stats.StagingFailed == 0 {
		t.Error("StagingFailed should be > 0")
	}
}

// TestStagingIntegration_EnforceModeRejectsMissingSig verifies that enforce mode
// rejects a policy without a .sig file.
func TestStagingIntegration_EnforceModeRejectsMissingSig(t *testing.T) {
	keysDir := t.TempDir()
	signing.GenerateKeypair(keysDir, "test")
	trustStore, _ := signing.LoadTrustStore(keysDir, true)

	policyDir := t.TempDir()
	stagingDir := filepath.Join(policyDir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	loader := &signingLoader{trustStore: trustStore, mode: "enforce"}

	stagingDone := make(chan error, 1)
	watcher, _ := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       policyDir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 200 * time.Millisecond,
		OnStaging: func(path string, err error) {
			stagingDone <- err
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// Drop policy without .sig
	os.WriteFile(filepath.Join(stagingDir, "unsigned.yaml"), []byte("unsigned: true"), 0644)

	select {
	case err := <-stagingDone:
		if err == nil {
			t.Fatal("expected missing sig to be rejected in enforce mode")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	if _, err := os.Stat(filepath.Join(policyDir, "unsigned.yaml")); !os.IsNotExist(err) {
		t.Fatal("unsigned policy should NOT be promoted")
	}
}
