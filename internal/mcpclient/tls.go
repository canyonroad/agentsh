// Package mcpclient provides helpers for connecting to HTTP/SSE MCP servers.
package mcpclient

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
)

// ValidateTLSFingerprint checks that a fingerprint string has the correct format.
// Valid format: "sha256:<64-hex-chars>" or empty string.
func ValidateTLSFingerprint(fingerprint string) error {
	if fingerprint == "" {
		return nil
	}
	if !strings.HasPrefix(fingerprint, "sha256:") {
		return fmt.Errorf("TLS fingerprint must start with 'sha256:', got %q", fingerprint)
	}
	hexPart := strings.TrimPrefix(fingerprint, "sha256:")
	if len(hexPart) != 64 {
		return fmt.Errorf("TLS fingerprint hex must be 64 characters (SHA-256), got %d", len(hexPart))
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return fmt.Errorf("TLS fingerprint contains invalid hex: %w", err)
	}
	return nil
}

// VerifyTLSFingerprint checks that a TLS connection's peer certificate
// matches the expected SPKI SHA-256 fingerprint.
// Call this after the TLS handshake completes.
func VerifyTLSFingerprint(conn *tls.Conn, expected string) error {
	if expected == "" {
		return nil
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificates presented")
	}

	leaf := state.PeerCertificates[0]
	spkiHash := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	actual := "sha256:" + hex.EncodeToString(spkiHash[:])

	if actual != expected {
		return fmt.Errorf("TLS fingerprint mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}
