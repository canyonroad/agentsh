package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func Sign(policyBytes []byte, privKey ed25519.PrivateKey, signer string) (*SigFile, error) {
	sig := ed25519.Sign(privKey, policyBytes)
	pub := privKey.Public().(ed25519.PublicKey)
	return &SigFile{
		Version: 1, Algorithm: "ed25519", KeyID: KeyID(pub), Signer: signer,
		SignedAt:  time.Now().UTC().Format(time.RFC3339),
		Signature: base64.StdEncoding.EncodeToString(sig),
		CertChain: []string{},
	}, nil
}

func SignFile(policyPath, privKeyPath, outputPath, signer string) error {
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	privKey, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return err
	}
	sigFile, err := Sign(policyBytes, privKey, signer)
	if err != nil {
		return err
	}
	sigJSON, err := json.MarshalIndent(sigFile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal signature: %w", err)
	}
	dest := outputPath
	if dest == "" {
		dest = policyPath + ".sig"
	}
	if err := os.WriteFile(dest, sigJSON, 0o644); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}
	return nil
}
