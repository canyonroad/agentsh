package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// VerifyResult holds the outcome of a successful signature verification.
type VerifyResult struct {
	KeyID    string
	Signer   string
	SignedAt string
}

// Verify checks that policyBytes was signed by a key in the trust store
// using the signature described by sig.
func Verify(policyBytes []byte, sig *SigFile, ts *TrustStore) error {
	if err := sig.Validate(); err != nil {
		return fmt.Errorf("invalid signature file: %w", err)
	}
	kf, err := ts.FindKey(sig.KeyID)
	if err != nil {
		return err
	}
	pubBytes, err := base64.StdEncoding.DecodeString(kf.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d", len(pubBytes))
	}
	pub := ed25519.PublicKey(pubBytes)
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, policyBytes, sigBytes) {
		return fmt.Errorf("invalid_signature: Ed25519 verification failed")
	}
	return nil
}

// VerifyPolicy reads policyPath and its companion .sig file, then verifies
// the signature against the trust store.
func VerifyPolicy(policyPath string, ts *TrustStore) (*VerifyResult, error) {
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return VerifyPolicyBytes(policyBytes, policyPath+".sig", ts)
}

// VerifyPolicyBytes verifies policyBytes using a signature file at sigPath.
func VerifyPolicyBytes(policyBytes []byte, sigPath string, ts *TrustStore) (*VerifyResult, error) {
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, fmt.Errorf("missing_signature: %w", err)
	}
	var sig SigFile
	if err := json.Unmarshal(sigData, &sig); err != nil {
		return nil, fmt.Errorf("parse signature file: %w", err)
	}
	if err := Verify(policyBytes, &sig, ts); err != nil {
		return nil, err
	}
	return &VerifyResult{KeyID: sig.KeyID, Signer: sig.Signer, SignedAt: sig.SignedAt}, nil
}
