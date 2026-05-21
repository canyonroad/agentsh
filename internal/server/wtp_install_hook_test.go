package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agentsh/agentsh/internal/api"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/policy/signing"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/pkg/types"
)

// memEventStore is the minimal store.EventStore stub composite.New needs
// for tests that don't exercise the event-write path. Mirrors the same
// helper in internal/api/app_destroy_test.go (kept local because
// unexported test types don't cross package boundaries).
type memEventStore struct{}

func (memEventStore) AppendEvent(context.Context, types.Event) error { return nil }
func (memEventStore) QueryEvents(context.Context, types.EventQuery) ([]types.Event, error) {
	return nil, nil
}
func (memEventStore) Close() error { return nil }

// installHookFixture bundles everything makePolicyInstallHook needs and
// the side-effect anchors a test can introspect after invoking the hook.
type installHookFixture struct {
	policiesDir string
	trustDir    string
	keyID       string                    // hex(sha256(pub))
	privKey     ed25519.PrivateKey
	manager     *policy.Manager           // points at policiesDir
	appHolder   *atomic.Pointer[api.App]  // intentionally empty; SwapPolicy skipped
}

// newInstallHookFixture writes a real ed25519 keypair into the trust
// store and constructs a policy.Manager rooted at the policies dir.
// appHolder is left empty so the hook's app == nil branch runs and we
// don't need to construct a full *api.App for these tests.
func newInstallHookFixture(t *testing.T) *installHookFixture {
	t.Helper()
	dir := t.TempDir()
	policiesDir := filepath.Join(dir, "policies")
	trustDir := filepath.Join(dir, "trust")
	if err := os.MkdirAll(policiesDir, 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}
	if err := os.MkdirAll(trustDir, 0o755); err != nil {
		t.Fatalf("mkdir trust: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 GenerateKey: %v", err)
	}
	keyID := signing.KeyID(pub)
	kf := signing.PublicKeyFile{
		KeyID:     keyID,
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Label:     "test",
	}
	kfBytes, _ := json.MarshalIndent(kf, "", "  ")
	if err := os.WriteFile(filepath.Join(trustDir, keyID+".json"), kfBytes, 0o644); err != nil {
		t.Fatalf("write trust key: %v", err)
	}

	// Manager.Reload walks (dir, selectedName) → {dir}/{selectedName}.yaml.
	// Tests below use "demo" as the policy id and write to that path.
	const policyName = "demo"
	mgr := policy.NewManager(policiesDir, policyName, []string{policyName}, "", policyName)

	return &installHookFixture{
		policiesDir: policiesDir,
		trustDir:    trustDir,
		keyID:       keyID,
		privKey:     priv,
		manager:     mgr,
		appHolder:   &atomic.Pointer[api.App]{},
	}
}

// sign produces a (content, sigBytes, contentHash) triple suitable for
// stuffing into a transport.PolicyPushed.
func (f *installHookFixture) sign(content []byte) (sig []byte, hashWire string) {
	sig = ed25519.Sign(f.privKey, content)
	h := sha256.Sum256(content)
	hashWire = "sha256:" + hex.EncodeToString(h[:])
	return sig, hashWire
}

// hookFor returns a fresh hook bound to this fixture's config.
func (f *installHookFixture) hookFor() func(transport.PolicyPushed) {
	return makePolicyInstallHook(config.PoliciesConfig{
		Dir: f.policiesDir,
		Signing: config.SigningConfig{
			TrustStore: f.trustDir,
		},
	}, f.manager, f.appHolder, false)
}

// validYAML is a minimal Policy that policy.Manager can parse. Manager
// rejects empty files; "version + name" is the floor.
const validYAML = "version: 1\nname: demo\n"

func TestMakePolicyInstallHook_HappyPath_WritesYAMLAndSig(t *testing.T) {
	f := newInstallHookFixture(t)
	hook := f.hookFor()
	if hook == nil {
		t.Fatal("hook returned nil despite both dirs being set")
	}

	content := []byte(validYAML)
	sig, hashWire := f.sign(content)
	hook(transport.PolicyPushed{
		PolicyID:      "demo",
		PolicyVersion: 14,
		ContentHash:   hashWire,
		Content:       content,
		Signature:     sig,
		SignerKeyID:   "ed25519:" + f.keyID,
	})

	yamlPath := filepath.Join(f.policiesDir, "demo.yaml")
	sigPath := yamlPath + ".sig"
	got, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("read installed yaml: %v", err)
	}
	if string(got) != validYAML {
		t.Errorf("yaml content = %q, want %q", got, validYAML)
	}

	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read sig file: %v", err)
	}
	var sigFile signing.SigFile
	if err := json.Unmarshal(sigBytes, &sigFile); err != nil {
		t.Fatalf("sig file is not JSON: %v", err)
	}
	if sigFile.Algorithm != "ed25519" {
		t.Errorf("sig algorithm = %q, want ed25519", sigFile.Algorithm)
	}
	if sigFile.KeyID != f.keyID {
		t.Errorf("sig key_id = %q, want %q", sigFile.KeyID, f.keyID)
	}
	decoded, err := base64.StdEncoding.DecodeString(sigFile.Signature)
	if err != nil || string(decoded) != string(sig) {
		t.Errorf("sig file Signature does not round-trip the wire signature")
	}
}

func TestMakePolicyInstallHook_BadSignature_DoesNotInstall(t *testing.T) {
	f := newInstallHookFixture(t)
	hook := f.hookFor()

	content := []byte(validYAML)
	_, hashWire := f.sign(content)
	// Tamper: flip one byte of the signature.
	badSig := ed25519.Sign(f.privKey, content)
	badSig[0] ^= 0xFF

	hook(transport.PolicyPushed{
		PolicyID:      "demo",
		PolicyVersion: 1,
		ContentHash:   hashWire,
		Content:       content,
		Signature:     badSig,
		SignerKeyID:   "ed25519:" + f.keyID,
	})

	if _, err := os.Stat(filepath.Join(f.policiesDir, "demo.yaml")); !os.IsNotExist(err) {
		t.Fatalf("yaml installed despite signature failure (stat err = %v)", err)
	}
}

func TestMakePolicyInstallHook_BadHash_DoesNotInstall(t *testing.T) {
	f := newInstallHookFixture(t)
	hook := f.hookFor()

	content := []byte(validYAML)
	sig, _ := f.sign(content)
	// Hash mismatch: claim the hash of a different blob.
	wrongHash := sha256.Sum256([]byte("different bytes"))

	hook(transport.PolicyPushed{
		PolicyID:      "demo",
		PolicyVersion: 1,
		ContentHash:   "sha256:" + hex.EncodeToString(wrongHash[:]),
		Content:       content,
		Signature:     sig,
		SignerKeyID:   "ed25519:" + f.keyID,
	})

	if _, err := os.Stat(filepath.Join(f.policiesDir, "demo.yaml")); !os.IsNotExist(err) {
		t.Fatalf("yaml installed despite content_hash mismatch (stat err = %v)", err)
	}
}

func TestMakePolicyInstallHook_UnknownSignerKey_DoesNotInstall(t *testing.T) {
	f := newInstallHookFixture(t)
	hook := f.hookFor()

	// Sign with the trusted key but report a different key_id on the wire.
	content := []byte(validYAML)
	sig, hashWire := f.sign(content)

	hook(transport.PolicyPushed{
		PolicyID:      "demo",
		PolicyVersion: 1,
		ContentHash:   hashWire,
		Content:       content,
		Signature:     sig,
		SignerKeyID:   "ed25519:" + strings.Repeat("0", 64),
	})

	if _, err := os.Stat(filepath.Join(f.policiesDir, "demo.yaml")); !os.IsNotExist(err) {
		t.Fatalf("yaml installed despite unknown signer_key_id")
	}
}

func TestMakePolicyInstallHook_EmptyContent_NoOp(t *testing.T) {
	f := newInstallHookFixture(t)
	hook := f.hookFor()

	// PolicyID set, content empty → the install guard rejects before
	// any signature check. Documents the input contract.
	hook(transport.PolicyPushed{
		PolicyID:    "demo",
		ContentHash: "sha256:deadbeef",
	})
	if _, err := os.Stat(filepath.Join(f.policiesDir, "demo.yaml")); !os.IsNotExist(err) {
		t.Fatalf("yaml installed for empty-content push")
	}
}

func TestMakePolicyInstallHook_NoTrustStore_ReturnsNil(t *testing.T) {
	// makePolicyInstallHook returns nil when either Dir or TrustStore is
	// unset — appropriate for deployments that observe but never install.
	hook := makePolicyInstallHook(config.PoliciesConfig{Dir: "/tmp/anything"}, nil, nil, false)
	if hook != nil {
		t.Fatal("hook non-nil despite empty trust store")
	}
	hook = makePolicyInstallHook(config.PoliciesConfig{Signing: config.SigningConfig{TrustStore: "/tmp/x"}}, nil, nil, false)
	if hook != nil {
		t.Fatal("hook non-nil despite empty policies dir")
	}
}

// TestMakePolicyInstallHook_IdempotentReinstall verifies the dedup
// short-circuit: re-delivering the same (policy_id, content_hash) is
// a no-op even when the on-disk file has been removed underneath us.
// This protects against tight reconnect loops re-running the full
// verify + write + reload + swap pipeline on every SessionAck.
//
// Two arms:
//
//   1. EngineSwapped path: pm + a non-nil App in the appHolder so the
//      first call reaches SwapPolicy and flips the dedup gate. The
//      second call with matching (id, hash) MUST short-circuit; the
//      proof is that a file deleted between the two calls stays gone.
//
//   2. EngineNotSwapped path: appHolder.Load() returns nil so the
//      first call skips SwapPolicy. The second call MUST re-run the
//      install — dedup requires engineSwapped=true.
func TestMakePolicyInstallHook_IdempotentReinstall(t *testing.T) {
	t.Run("dedups after engine swap", func(t *testing.T) {
		f := newInstallHookFixture(t)
		// Build a minimal App, plant it in the holder. SwapPolicy only
		// touches policyMu + policy fields, so the rest of the App
		// graph can stay zero/nil.
		initial, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "initial"}, false, true)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		app := api.NewApp(
			&config.Config{},
			session.NewManager(1),
			composite.New(memEventStore{}, nil),
			initial,
			events.NewBroker(),
			nil, nil, nil, nil, nil, nil,
		)
		f.appHolder.Store(app)

		hook := f.hookFor()
		content := []byte(validYAML)
		sig, hashWire := f.sign(content)
		push := transport.PolicyPushed{
			PolicyID:      "demo",
			PolicyVersion: 1,
			ContentHash:   hashWire,
			Content:       content,
			Signature:     sig,
			SignerKeyID:   "ed25519:" + f.keyID,
		}

		hook(push)
		yamlPath := filepath.Join(f.policiesDir, "demo.yaml")
		if _, err := os.Stat(yamlPath); err != nil {
			t.Fatalf("first install did not write yaml: %v", err)
		}

		// Delete the file. With dedup working, the second call must
		// NOT re-run the install (file stays gone).
		if err := os.Remove(yamlPath); err != nil {
			t.Fatalf("remove yaml: %v", err)
		}
		hook(push)
		if _, err := os.Stat(yamlPath); !os.IsNotExist(err) {
			t.Fatalf("dedup failed: yaml re-written after delete (stat err = %v)", err)
		}
	})

	t.Run("re-runs install when engine was not swapped", func(t *testing.T) {
		f := newInstallHookFixture(t)
		// appHolder is empty — engineSwapped never flips on the first
		// call, so the second call MUST re-run the install regardless
		// of matching (id, hash).
		hook := f.hookFor()

		content := []byte(validYAML)
		sig, hashWire := f.sign(content)
		push := transport.PolicyPushed{
			PolicyID:      "demo",
			PolicyVersion: 1,
			ContentHash:   hashWire,
			Content:       content,
			Signature:     sig,
			SignerKeyID:   "ed25519:" + f.keyID,
		}

		hook(push)
		yamlPath := filepath.Join(f.policiesDir, "demo.yaml")
		if _, err := os.Stat(yamlPath); err != nil {
			t.Fatalf("first install did not write yaml: %v", err)
		}

		if err := os.Remove(yamlPath); err != nil {
			t.Fatalf("remove yaml: %v", err)
		}
		hook(push)
		if _, err := os.Stat(yamlPath); err != nil {
			t.Fatalf("second install (engine swap skipped) did not re-run: %v", err)
		}
	})

	t.Run("different content_hash bypasses dedup", func(t *testing.T) {
		f := newInstallHookFixture(t)
		initial, _ := policy.NewEngine(&policy.Policy{Version: 1, Name: "initial"}, false, true)
		app := api.NewApp(
			&config.Config{},
			session.NewManager(1),
			composite.New(memEventStore{}, nil),
			initial,
			events.NewBroker(),
			nil, nil, nil, nil, nil, nil,
		)
		f.appHolder.Store(app)

		hook := f.hookFor()

		// First install.
		c1 := []byte(validYAML)
		s1, h1 := f.sign(c1)
		hook(transport.PolicyPushed{
			PolicyID: "demo", PolicyVersion: 1,
			ContentHash: h1, Content: c1, Signature: s1,
			SignerKeyID: "ed25519:" + f.keyID,
		})

		// Second install with DIFFERENT content → different content_hash,
		// dedup must NOT short-circuit even though engineSwapped is true.
		c2 := []byte("version: 1\nname: demo\n# v2 comment\n")
		s2, h2 := f.sign(c2)
		hook(transport.PolicyPushed{
			PolicyID: "demo", PolicyVersion: 2,
			ContentHash: h2, Content: c2, Signature: s2,
			SignerKeyID: "ed25519:" + f.keyID,
		})

		got, err := os.ReadFile(filepath.Join(f.policiesDir, "demo.yaml"))
		if err != nil {
			t.Fatalf("read yaml: %v", err)
		}
		if string(got) != string(c2) {
			t.Errorf("yaml content = %q, want second install's content", got)
		}
	})
}
