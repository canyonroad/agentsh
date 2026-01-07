package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnCredential represents a stored WebAuthn credential with metadata.
type WebAuthnCredential struct {
	ID           int64
	UserID       string
	CredentialID []byte
	PublicKey    []byte
	Attestation  string
	Transport    []protocol.AuthenticatorTransport
	SignCount    uint32
	CreatedAt    time.Time
	LastUsed     *time.Time
	Name         string
}

// WebAuthnStore manages WebAuthn credential persistence.
type WebAuthnStore struct {
	db *sql.DB
}

// NewWebAuthnStore creates a new WebAuthn credential store.
func NewWebAuthnStore(db *sql.DB) *WebAuthnStore {
	return &WebAuthnStore{db: db}
}

// SaveCredential persists a new WebAuthn credential for a user.
func (s *WebAuthnStore) SaveCredential(ctx context.Context, userID string, cred *webauthn.Credential, name string) error {
	if cred == nil {
		return fmt.Errorf("credential is nil")
	}
	if userID == "" {
		return fmt.Errorf("userID is required")
	}

	transport := encodeTransport(cred.Transport)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (
			user_id, credential_id, public_key, attestation_type,
			transport, sign_count, created_at_ns, name
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID,
		cred.ID,
		cred.PublicKey,
		nullable(cred.AttestationType),
		nullable(transport),
		cred.Authenticator.SignCount,
		time.Now().UTC().UnixNano(),
		nullable(name),
	)
	if err != nil {
		return fmt.Errorf("save webauthn credential: %w", err)
	}
	return nil
}

// GetCredentials retrieves all WebAuthn credentials for a user as webauthn.Credential structs.
func (s *WebAuthnStore) GetCredentials(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT credential_id, public_key, attestation_type, transport, sign_count
		FROM webauthn_credentials
		WHERE user_id = ?
		ORDER BY created_at_ns ASC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("query webauthn credentials: %w", err)
	}
	defer rows.Close()

	var creds []webauthn.Credential
	for rows.Next() {
		var credID, publicKey []byte
		var attestation, transport sql.NullString
		var signCount uint32

		if err := rows.Scan(&credID, &publicKey, &attestation, &transport, &signCount); err != nil {
			return nil, fmt.Errorf("scan webauthn credential: %w", err)
		}

		cred := webauthn.Credential{
			ID:              credID,
			PublicKey:       publicKey,
			AttestationType: attestation.String,
			Transport:       decodeTransport(transport.String),
			Authenticator: webauthn.Authenticator{
				SignCount: signCount,
			},
		}
		creds = append(creds, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webauthn credentials: %w", err)
	}
	return creds, nil
}

// UpdateSignCount updates the sign count for a credential after successful authentication.
func (s *WebAuthnStore) UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE webauthn_credentials
		SET sign_count = ?, last_used_ns = ?
		WHERE credential_id = ?`,
		signCount,
		time.Now().UTC().UnixNano(),
		credentialID,
	)
	if err != nil {
		return fmt.Errorf("update sign count: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

// DeleteCredential removes a credential for a user.
func (s *WebAuthnStore) DeleteCredential(ctx context.Context, userID string, credentialID []byte) error {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM webauthn_credentials
		WHERE user_id = ? AND credential_id = ?`,
		userID,
		credentialID,
	)
	if err != nil {
		return fmt.Errorf("delete webauthn credential: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

// ListCredentials returns all credentials for a user with full metadata.
func (s *WebAuthnStore) ListCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, credential_id, public_key, attestation_type,
		       transport, sign_count, created_at_ns, last_used_ns, name
		FROM webauthn_credentials
		WHERE user_id = ?
		ORDER BY created_at_ns ASC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("query webauthn credentials: %w", err)
	}
	defer rows.Close()

	var creds []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		var attestation, transport, name sql.NullString
		var createdNs int64
		var lastUsedNs sql.NullInt64

		if err := rows.Scan(
			&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey,
			&attestation, &transport, &c.SignCount, &createdNs, &lastUsedNs, &name,
		); err != nil {
			return nil, fmt.Errorf("scan webauthn credential: %w", err)
		}

		c.Attestation = attestation.String
		c.Transport = decodeTransport(transport.String)
		c.CreatedAt = time.Unix(0, createdNs)
		if lastUsedNs.Valid {
			t := time.Unix(0, lastUsedNs.Int64)
			c.LastUsed = &t
		}
		c.Name = name.String
		creds = append(creds, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webauthn credentials: %w", err)
	}
	return creds, nil
}

func encodeTransport(transports []protocol.AuthenticatorTransport) string {
	if len(transports) == 0 {
		return ""
	}
	strs := make([]string, len(transports))
	for i, t := range transports {
		strs[i] = string(t)
	}
	b, _ := json.Marshal(strs)
	return string(b)
}

func decodeTransport(s string) []protocol.AuthenticatorTransport {
	if s == "" {
		return nil
	}
	var strs []string
	if err := json.Unmarshal([]byte(s), &strs); err != nil {
		// Fallback for comma-separated format
		strs = strings.Split(s, ",")
	}
	transports := make([]protocol.AuthenticatorTransport, 0, len(strs))
	for _, str := range strs {
		str = strings.TrimSpace(str)
		if str != "" {
			transports = append(transports, protocol.AuthenticatorTransport(str))
		}
	}
	return transports
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
