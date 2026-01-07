package auth

import (
	"context"
	"database/sql"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}

	// Create the webauthn_credentials table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id TEXT NOT NULL,
			credential_id BLOB NOT NULL UNIQUE,
			public_key BLOB NOT NULL,
			attestation_type TEXT,
			transport TEXT,
			sign_count INTEGER NOT NULL DEFAULT 0,
			created_at_ns INTEGER NOT NULL,
			last_used_ns INTEGER,
			name TEXT
		)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id)`)
	if err != nil {
		t.Fatalf("create index: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
	})

	return db
}

func TestWebAuthnStore_SaveAndGet(t *testing.T) {
	db := setupTestDB(t)
	store := NewWebAuthnStore(db)
	ctx := context.Background()

	userID := "user-123"
	cred := &webauthn.Credential{
		ID:              []byte("credential-id-abc"),
		PublicKey:       []byte("public-key-xyz"),
		AttestationType: "none",
		Transport:       []protocol.AuthenticatorTransport{protocol.USB, protocol.Internal},
		Authenticator: webauthn.Authenticator{
			SignCount: 0,
		},
	}

	// Save the credential
	err := store.SaveCredential(ctx, userID, cred, "My Security Key")
	if err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}

	// Get credentials back
	creds, err := store.GetCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}

	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}

	got := creds[0]
	if string(got.ID) != string(cred.ID) {
		t.Errorf("credential ID mismatch: got %q, want %q", got.ID, cred.ID)
	}
	if string(got.PublicKey) != string(cred.PublicKey) {
		t.Errorf("public key mismatch: got %q, want %q", got.PublicKey, cred.PublicKey)
	}
	if got.AttestationType != cred.AttestationType {
		t.Errorf("attestation type mismatch: got %q, want %q", got.AttestationType, cred.AttestationType)
	}
	if len(got.Transport) != len(cred.Transport) {
		t.Errorf("transport count mismatch: got %d, want %d", len(got.Transport), len(cred.Transport))
	}

	// List credentials with full metadata
	list, err := store.ListCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}

	if len(list) != 1 {
		t.Fatalf("expected 1 credential in list, got %d", len(list))
	}

	if list[0].Name != "My Security Key" {
		t.Errorf("name mismatch: got %q, want %q", list[0].Name, "My Security Key")
	}
	if list[0].UserID != userID {
		t.Errorf("userID mismatch: got %q, want %q", list[0].UserID, userID)
	}
	if list[0].CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestWebAuthnStore_UpdateSignCount(t *testing.T) {
	db := setupTestDB(t)
	store := NewWebAuthnStore(db)
	ctx := context.Background()

	userID := "user-456"
	credID := []byte("credential-id-update-test")
	cred := &webauthn.Credential{
		ID:        credID,
		PublicKey: []byte("public-key-456"),
		Authenticator: webauthn.Authenticator{
			SignCount: 5,
		},
	}

	err := store.SaveCredential(ctx, userID, cred, "Test Key")
	if err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}

	// Verify initial sign count
	creds, err := store.GetCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if creds[0].Authenticator.SignCount != 5 {
		t.Errorf("initial sign count: got %d, want %d", creds[0].Authenticator.SignCount, 5)
	}

	// Update sign count
	err = store.UpdateSignCount(ctx, credID, 10)
	if err != nil {
		t.Fatalf("UpdateSignCount: %v", err)
	}

	// Verify updated sign count
	creds, err = store.GetCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("GetCredentials after update: %v", err)
	}
	if creds[0].Authenticator.SignCount != 10 {
		t.Errorf("updated sign count: got %d, want %d", creds[0].Authenticator.SignCount, 10)
	}

	// Verify last_used was set
	list, err := store.ListCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if list[0].LastUsed == nil {
		t.Error("expected LastUsed to be set after sign count update")
	}
}

func TestWebAuthnStore_DeleteCredential(t *testing.T) {
	db := setupTestDB(t)
	store := NewWebAuthnStore(db)
	ctx := context.Background()

	userID := "user-789"
	credID := []byte("credential-to-delete")
	cred := &webauthn.Credential{
		ID:        credID,
		PublicKey: []byte("public-key-789"),
	}

	err := store.SaveCredential(ctx, userID, cred, "Deletable Key")
	if err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}

	// Verify credential exists
	creds, err := store.GetCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}

	// Delete credential
	err = store.DeleteCredential(ctx, userID, credID)
	if err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	// Verify credential is gone
	creds, err = store.GetCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("GetCredentials after delete: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials after delete, got %d", len(creds))
	}

	// Delete non-existent credential should return error
	err = store.DeleteCredential(ctx, userID, []byte("non-existent"))
	if err == nil {
		t.Error("expected error when deleting non-existent credential")
	}
}

func TestWebAuthnStore_MultipleCredentials(t *testing.T) {
	db := setupTestDB(t)
	store := NewWebAuthnStore(db)
	ctx := context.Background()

	userID := "user-multi"

	// Save multiple credentials
	for i := 0; i < 3; i++ {
		cred := &webauthn.Credential{
			ID:        []byte{byte(i), byte(i + 1), byte(i + 2)},
			PublicKey: []byte{byte(i * 10)},
		}
		if err := store.SaveCredential(ctx, userID, cred, ""); err != nil {
			t.Fatalf("SaveCredential %d: %v", i, err)
		}
	}

	// Verify all credentials returned
	creds, err := store.GetCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if len(creds) != 3 {
		t.Errorf("expected 3 credentials, got %d", len(creds))
	}

	// Different user should have no credentials
	otherCreds, err := store.GetCredentials(ctx, "other-user")
	if err != nil {
		t.Fatalf("GetCredentials other user: %v", err)
	}
	if len(otherCreds) != 0 {
		t.Errorf("expected 0 credentials for other user, got %d", len(otherCreds))
	}
}

func TestWebAuthnStore_ValidationErrors(t *testing.T) {
	db := setupTestDB(t)
	store := NewWebAuthnStore(db)
	ctx := context.Background()

	// Nil credential
	err := store.SaveCredential(ctx, "user", nil, "")
	if err == nil {
		t.Error("expected error for nil credential")
	}

	// Empty userID
	cred := &webauthn.Credential{
		ID:        []byte("cred"),
		PublicKey: []byte("key"),
	}
	err = store.SaveCredential(ctx, "", cred, "")
	if err == nil {
		t.Error("expected error for empty userID")
	}

	// Update non-existent credential
	err = store.UpdateSignCount(ctx, []byte("non-existent"), 10)
	if err == nil {
		t.Error("expected error when updating non-existent credential")
	}
}
