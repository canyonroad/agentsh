package watchtower

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// CredentialSource yields the bearer credential agentsh presents on each
// WTP Dial. Returning "" means "present no credential" (anonymous; for
// local/test servers). It is called once per Dial so a future rotating or
// attested source (Phase 2) can return fresh values on reconnect with no
// change to the transport.
type CredentialSource interface {
	Bearer(ctx context.Context) (string, error)
}

// staticCredentialSource always yields the same token. Used for v1
// env/file credentials resolved once at startup.
type staticCredentialSource struct{ token string }

func (s staticCredentialSource) Bearer(context.Context) (string, error) { return s.token, nil }

// NewStaticCredentialSource returns a CredentialSource that always yields
// token, or nil when token is empty (nothing to present).
func NewStaticCredentialSource(token string) CredentialSource {
	if token == "" {
		return nil
	}
	return staticCredentialSource{token: token}
}

// credLogID returns a non-sensitive identifier for logging a presented
// credential: the key ID (the substring before the first '.') when the
// credential is in "<kid>.<secret>" form, or a short sha256 prefix for a
// legacy dot-less token. The secret is never returned.
func credLogID(token string) string {
	if i := strings.IndexByte(token, '.'); i > 0 {
		return token[:i]
	}
	sum := sha256.Sum256([]byte("agentsh-wt-cred\x00" + token))
	return "sha256:" + hex.EncodeToString(sum[:4])
}
