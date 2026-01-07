package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Default session TTL for WebAuthn ceremonies
const defaultSessionTTL = 5 * time.Minute

// sessionEntry wraps session data with expiration time
type sessionEntry struct {
	data      *webauthn.SessionData
	expiresAt time.Time
}

// WebAuthnUser implements the webauthn.User interface.
type WebAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

// NewWebAuthnUser creates a new WebAuthnUser.
func NewWebAuthnUser(id, name, displayName string, credentials []webauthn.Credential) *WebAuthnUser {
	return &WebAuthnUser{
		id:          []byte(id),
		name:        name,
		displayName: displayName,
		credentials: credentials,
	}
}

// WebAuthnID returns the user's unique identifier.
func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.id
}

// WebAuthnName returns the user's username.
func (u *WebAuthnUser) WebAuthnName() string {
	return u.name
}

// WebAuthnDisplayName returns the user's display name.
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.displayName
}

// WebAuthnCredentials returns the user's credentials.
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// WebAuthnService handles WebAuthn registration and authentication ceremonies.
type WebAuthnService struct {
	wa         *webauthn.WebAuthn
	store      *WebAuthnStore
	mu         sync.RWMutex
	sessions   map[string]*sessionEntry
	sessionTTL time.Duration
}

// NewWebAuthnService creates a new WebAuthn service.
func NewWebAuthnService(rpID, rpName string, rpOrigins []string, userVerification string, store *WebAuthnStore) (*WebAuthnService, error) {
	if rpID == "" {
		return nil, fmt.Errorf("rpID is required")
	}
	if rpName == "" {
		return nil, fmt.Errorf("rpName is required")
	}
	if len(rpOrigins) == 0 {
		return nil, fmt.Errorf("at least one rpOrigin is required")
	}
	if store == nil {
		return nil, fmt.Errorf("store is required")
	}

	// Map user verification string to protocol constant
	var uv protocol.UserVerificationRequirement
	switch userVerification {
	case "required":
		uv = protocol.VerificationRequired
	case "discouraged":
		uv = protocol.VerificationDiscouraged
	case "preferred", "":
		uv = protocol.VerificationPreferred
	default:
		return nil, fmt.Errorf("invalid user verification mode: %s", userVerification)
	}

	cfg := &webauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         rpName,
		RPOrigins:             rpOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: uv,
		},
	}

	wa, err := webauthn.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create webauthn: %w", err)
	}

	return &WebAuthnService{
		wa:         wa,
		store:      store,
		sessions:   make(map[string]*sessionEntry),
		sessionTTL: defaultSessionTTL,
	}, nil
}

// BeginRegistration starts a WebAuthn registration ceremony for a user.
func (s *WebAuthnService) BeginRegistration(ctx context.Context, userID, userName, displayName string) (*protocol.CredentialCreation, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID is required")
	}
	if userName == "" {
		return nil, fmt.Errorf("userName is required")
	}
	if displayName == "" {
		displayName = userName
	}

	// Get existing credentials to exclude from registration
	existingCreds, err := s.store.GetCredentials(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get existing credentials: %w", err)
	}

	user := NewWebAuthnUser(userID, userName, displayName, existingCreds)

	options, session, err := s.wa.BeginRegistration(user)
	if err != nil {
		return nil, fmt.Errorf("begin registration: %w", err)
	}

	// Store session data for verification
	s.mu.Lock()
	s.cleanupExpiredSessionsLocked()
	s.sessions[userID] = &sessionEntry{
		data:      session,
		expiresAt: time.Now().Add(s.sessionTTL),
	}
	s.mu.Unlock()

	return options, nil
}

// FinishRegistration completes a WebAuthn registration ceremony.
func (s *WebAuthnService) FinishRegistration(ctx context.Context, userID, userName, displayName, credName string, response *protocol.ParsedCredentialCreationData) error {
	if userID == "" {
		return fmt.Errorf("userID is required")
	}
	if response == nil {
		return fmt.Errorf("response is required")
	}

	// Retrieve session data
	s.mu.Lock()
	entry, ok := s.sessions[userID]
	if ok {
		delete(s.sessions, userID)
	}
	s.mu.Unlock()

	if !ok {
		return fmt.Errorf("no registration session found for user")
	}

	// Check if session has expired
	if time.Now().After(entry.expiresAt) {
		return fmt.Errorf("registration session has expired")
	}

	session := entry.data

	// Get existing credentials
	existingCreds, err := s.store.GetCredentials(ctx, userID)
	if err != nil {
		return fmt.Errorf("get existing credentials: %w", err)
	}

	user := NewWebAuthnUser(userID, userName, displayName, existingCreds)

	credential, err := s.wa.CreateCredential(user, *session, response)
	if err != nil {
		return fmt.Errorf("create credential: %w", err)
	}

	// Store the credential
	if err := s.store.SaveCredential(ctx, userID, credential, credName); err != nil {
		return fmt.Errorf("save credential: %w", err)
	}

	return nil
}

// BeginAuthentication starts a WebAuthn authentication ceremony for a user.
func (s *WebAuthnService) BeginAuthentication(ctx context.Context, userID string) (*protocol.CredentialAssertion, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID is required")
	}

	// Get user's credentials
	credentials, err := s.store.GetCredentials(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get credentials: %w", err)
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("user has no registered credentials")
	}

	user := NewWebAuthnUser(userID, userID, userID, credentials)

	options, session, err := s.wa.BeginLogin(user)
	if err != nil {
		return nil, fmt.Errorf("begin login: %w", err)
	}

	// Store session data for verification
	s.mu.Lock()
	s.cleanupExpiredSessionsLocked()
	s.sessions[userID] = &sessionEntry{
		data:      session,
		expiresAt: time.Now().Add(s.sessionTTL),
	}
	s.mu.Unlock()

	return options, nil
}

// FinishAuthentication completes a WebAuthn authentication ceremony.
func (s *WebAuthnService) FinishAuthentication(ctx context.Context, userID string, response *protocol.ParsedCredentialAssertionData) error {
	if userID == "" {
		return fmt.Errorf("userID is required")
	}
	if response == nil {
		return fmt.Errorf("response is required")
	}

	// Retrieve session data
	s.mu.Lock()
	entry, ok := s.sessions[userID]
	if ok {
		delete(s.sessions, userID)
	}
	s.mu.Unlock()

	if !ok {
		return fmt.Errorf("no authentication session found for user")
	}

	// Check if session has expired
	if time.Now().After(entry.expiresAt) {
		return fmt.Errorf("authentication session has expired")
	}

	session := entry.data

	// Get user's credentials
	credentials, err := s.store.GetCredentials(ctx, userID)
	if err != nil {
		return fmt.Errorf("get credentials: %w", err)
	}

	user := NewWebAuthnUser(userID, userID, userID, credentials)

	credential, err := s.wa.ValidateLogin(user, *session, response)
	if err != nil {
		return fmt.Errorf("validate login: %w", err)
	}

	// Update sign count
	if err := s.store.UpdateSignCount(ctx, credential.ID, credential.Authenticator.SignCount); err != nil {
		return fmt.Errorf("update sign count: %w", err)
	}

	return nil
}

// HasCredentials checks if a user has any registered WebAuthn credentials.
func (s *WebAuthnService) HasCredentials(ctx context.Context, userID string) (bool, error) {
	if userID == "" {
		return false, fmt.Errorf("userID is required")
	}

	credentials, err := s.store.GetCredentials(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("get credentials: %w", err)
	}

	return len(credentials) > 0, nil
}

// cleanupExpiredSessionsLocked removes expired sessions from the map.
// Must be called with s.mu already held.
func (s *WebAuthnService) cleanupExpiredSessionsLocked() {
	now := time.Now()
	for userID, entry := range s.sessions {
		if now.After(entry.expiresAt) {
			delete(s.sessions, userID)
		}
	}
}
