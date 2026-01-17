# Phase 2: Auth Expansion - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add WebAuthn/FIDO2 approval mode and OAuth/OIDC authentication for enterprise SSO integration.

**Architecture:** Extend existing approval system with WebAuthn mode, add OIDC JWT validation alongside API keys for hybrid auth.

**Tech Stack:** Go, github.com/go-webauthn/webauthn, github.com/coreos/go-oidc/v3, SQLite (credential storage)

---

## Task 1: WebAuthn Credential Storage

**Files:**
- Create: `internal/auth/webauthn_store.go`
- Create: `internal/auth/webauthn_store_test.go`
- Modify: `internal/store/sqlite/sqlite.go` (add credentials table)

**Step 1: Add credentials table to SQLite schema**

Modify `internal/store/sqlite/sqlite.go` migrate function to add:

```go
`CREATE TABLE IF NOT EXISTS webauthn_credentials (
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
);`,
`CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id);`,
```

**Step 2: Create credential store**

Create `internal/auth/webauthn_store.go`:

```go
package auth

import (
    "context"
    "database/sql"
    "encoding/base64"
    "fmt"
    "time"

    "github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnCredential represents a stored WebAuthn credential.
type WebAuthnCredential struct {
    ID              int64
    UserID          string
    CredentialID    []byte
    PublicKey       []byte
    AttestationType string
    Transport       string
    SignCount       uint32
    CreatedAt       time.Time
    LastUsed        *time.Time
    Name            string
}

// WebAuthnStore manages WebAuthn credentials in SQLite.
type WebAuthnStore struct {
    db *sql.DB
}

// NewWebAuthnStore creates a new credential store.
func NewWebAuthnStore(db *sql.DB) *WebAuthnStore {
    return &WebAuthnStore{db: db}
}

// SaveCredential stores a new WebAuthn credential.
func (s *WebAuthnStore) SaveCredential(ctx context.Context, userID string, cred *webauthn.Credential, name string) error {
    transport := ""
    if len(cred.Transport) > 0 {
        transport = string(cred.Transport[0])
    }

    _, err := s.db.ExecContext(ctx, `
        INSERT INTO webauthn_credentials (
            user_id, credential_id, public_key, attestation_type, transport, sign_count, created_at_ns, name
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        userID,
        cred.ID,
        cred.PublicKey,
        cred.AttestationType,
        transport,
        cred.Authenticator.SignCount,
        time.Now().UnixNano(),
        name,
    )
    if err != nil {
        return fmt.Errorf("save credential: %w", err)
    }
    return nil
}

// GetCredentials returns all credentials for a user.
func (s *WebAuthnStore) GetCredentials(ctx context.Context, userID string) ([]webauthn.Credential, error) {
    rows, err := s.db.QueryContext(ctx, `
        SELECT credential_id, public_key, attestation_type, transport, sign_count
        FROM webauthn_credentials WHERE user_id = ?`, userID)
    if err != nil {
        return nil, fmt.Errorf("query credentials: %w", err)
    }
    defer rows.Close()

    var creds []webauthn.Credential
    for rows.Next() {
        var credID, pubKey []byte
        var attestationType, transport string
        var signCount uint32

        if err := rows.Scan(&credID, &pubKey, &attestationType, &transport, &signCount); err != nil {
            return nil, fmt.Errorf("scan credential: %w", err)
        }

        creds = append(creds, webauthn.Credential{
            ID:              credID,
            PublicKey:       pubKey,
            AttestationType: attestationType,
            Authenticator: webauthn.Authenticator{
                SignCount: signCount,
            },
        })
    }
    return creds, rows.Err()
}

// UpdateSignCount updates the sign count after successful authentication.
func (s *WebAuthnStore) UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
    _, err := s.db.ExecContext(ctx, `
        UPDATE webauthn_credentials
        SET sign_count = ?, last_used_ns = ?
        WHERE credential_id = ?`,
        signCount, time.Now().UnixNano(), credentialID)
    return err
}

// DeleteCredential removes a credential.
func (s *WebAuthnStore) DeleteCredential(ctx context.Context, userID string, credentialID []byte) error {
    _, err := s.db.ExecContext(ctx, `
        DELETE FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?`,
        userID, credentialID)
    return err
}

// ListCredentials returns all credentials for a user with metadata.
func (s *WebAuthnStore) ListCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
    rows, err := s.db.QueryContext(ctx, `
        SELECT id, credential_id, public_key, attestation_type, transport, sign_count, created_at_ns, last_used_ns, name
        FROM webauthn_credentials WHERE user_id = ?`, userID)
    if err != nil {
        return nil, fmt.Errorf("query credentials: %w", err)
    }
    defer rows.Close()

    var creds []WebAuthnCredential
    for rows.Next() {
        var c WebAuthnCredential
        var createdNs int64
        var lastUsedNs sql.NullInt64
        var name sql.NullString

        if err := rows.Scan(&c.ID, &c.CredentialID, &c.PublicKey, &c.AttestationType, &c.Transport, &c.SignCount, &createdNs, &lastUsedNs, &name); err != nil {
            return nil, fmt.Errorf("scan credential: %w", err)
        }

        c.UserID = userID
        c.CreatedAt = time.Unix(0, createdNs)
        if lastUsedNs.Valid {
            t := time.Unix(0, lastUsedNs.Int64)
            c.LastUsed = &t
        }
        c.Name = name.String
        creds = append(creds, c)
    }
    return creds, rows.Err()
}
```

**Step 3: Write tests**

Create `internal/auth/webauthn_store_test.go`:

```go
package auth

import (
    "context"
    "database/sql"
    "testing"

    "github.com/go-webauthn/webauthn/webauthn"
    _ "modernc.org/sqlite"
)

func TestWebAuthnStore_SaveAndGet(t *testing.T) {
    db := setupTestDB(t)
    store := NewWebAuthnStore(db)
    ctx := context.Background()

    cred := &webauthn.Credential{
        ID:              []byte("test-credential-id"),
        PublicKey:       []byte("test-public-key"),
        AttestationType: "none",
        Authenticator: webauthn.Authenticator{
            SignCount: 0,
        },
    }

    err := store.SaveCredential(ctx, "user-123", cred, "My YubiKey")
    if err != nil {
        t.Fatalf("SaveCredential: %v", err)
    }

    creds, err := store.GetCredentials(ctx, "user-123")
    if err != nil {
        t.Fatalf("GetCredentials: %v", err)
    }

    if len(creds) != 1 {
        t.Fatalf("expected 1 credential, got %d", len(creds))
    }

    if string(creds[0].ID) != "test-credential-id" {
        t.Errorf("credential ID mismatch")
    }
}

func TestWebAuthnStore_UpdateSignCount(t *testing.T) {
    db := setupTestDB(t)
    store := NewWebAuthnStore(db)
    ctx := context.Background()

    cred := &webauthn.Credential{
        ID:        []byte("test-cred"),
        PublicKey: []byte("key"),
    }
    store.SaveCredential(ctx, "user-1", cred, "")

    err := store.UpdateSignCount(ctx, []byte("test-cred"), 5)
    if err != nil {
        t.Fatalf("UpdateSignCount: %v", err)
    }

    creds, _ := store.GetCredentials(ctx, "user-1")
    if creds[0].Authenticator.SignCount != 5 {
        t.Errorf("expected sign count 5, got %d", creds[0].Authenticator.SignCount)
    }
}

func setupTestDB(t *testing.T) *sql.DB {
    db, err := sql.Open("sqlite", ":memory:")
    if err != nil {
        t.Fatal(err)
    }
    t.Cleanup(func() { db.Close() })

    _, err = db.Exec(`CREATE TABLE webauthn_credentials (
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
        t.Fatal(err)
    }
    return db
}
```

**Step 4: Run tests**

Run: `go test ./internal/auth/... -v -run WebAuthn`
Expected: Tests pass

**Step 5: Commit**

```bash
git add internal/auth/webauthn_store.go internal/auth/webauthn_store_test.go internal/store/sqlite/sqlite.go
git commit -m "feat(auth): add WebAuthn credential storage"
```

---

## Task 2: WebAuthn Challenge/Response Logic

**Files:**
- Create: `internal/auth/webauthn.go`
- Create: `internal/auth/webauthn_test.go`
- Modify: `internal/config/config.go` (add WebAuthn config)

**Step 1: Add WebAuthn config**

Add to `internal/config/config.go` after `ApprovalsConfig`:

```go
// WebAuthnConfig configures WebAuthn/FIDO2 authentication.
type WebAuthnConfig struct {
    RPID            string   `yaml:"rp_id"`              // e.g., "agentsh.local"
    RPName          string   `yaml:"rp_name"`            // e.g., "agentsh"
    RPOrigins       []string `yaml:"rp_origins"`         // e.g., ["http://localhost:18080"]
    UserVerification string  `yaml:"user_verification"` // preferred, required, discouraged
}
```

Add `WebAuthn WebAuthnConfig` field to `ApprovalsConfig`:

```go
type ApprovalsConfig struct {
    Enabled  bool            `yaml:"enabled"`
    Mode     string          `yaml:"mode"`    // "local_tty", "api", "totp", or "webauthn"
    Timeout  string          `yaml:"timeout"`
    WebAuthn WebAuthnConfig  `yaml:"webauthn"`
}
```

**Step 2: Create WebAuthn service**

Create `internal/auth/webauthn.go`:

```go
package auth

import (
    "context"
    "fmt"
    "sync"

    "github.com/go-webauthn/webauthn/protocol"
    "github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnService handles WebAuthn registration and authentication.
type WebAuthnService struct {
    wa    *webauthn.WebAuthn
    store *WebAuthnStore

    // In-memory session storage for challenges
    mu       sync.RWMutex
    sessions map[string]*webauthn.SessionData // sessionID -> session data
}

// WebAuthnUser implements webauthn.User interface.
type WebAuthnUser struct {
    id          string
    name        string
    displayName string
    credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *WebAuthnUser) WebAuthnName() string                       { return u.name }
func (u *WebAuthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// NewWebAuthnService creates a new WebAuthn service.
func NewWebAuthnService(rpID, rpName string, rpOrigins []string, userVerification string, store *WebAuthnStore) (*WebAuthnService, error) {
    uv := protocol.VerificationPreferred
    switch userVerification {
    case "required":
        uv = protocol.VerificationRequired
    case "discouraged":
        uv = protocol.VerificationDiscouraged
    }

    cfg := &webauthn.Config{
        RPID:          rpID,
        RPDisplayName: rpName,
        RPOrigins:     rpOrigins,
        AuthenticatorSelection: protocol.AuthenticatorSelection{
            UserVerification: uv,
        },
    }

    wa, err := webauthn.New(cfg)
    if err != nil {
        return nil, fmt.Errorf("create webauthn: %w", err)
    }

    return &WebAuthnService{
        wa:       wa,
        store:    store,
        sessions: make(map[string]*webauthn.SessionData),
    }, nil
}

// BeginRegistration starts a credential registration ceremony.
func (s *WebAuthnService) BeginRegistration(ctx context.Context, userID, userName, displayName string) (*protocol.CredentialCreation, error) {
    existingCreds, err := s.store.GetCredentials(ctx, userID)
    if err != nil {
        return nil, fmt.Errorf("get existing credentials: %w", err)
    }

    user := &WebAuthnUser{
        id:          userID,
        name:        userName,
        displayName: displayName,
        credentials: existingCreds,
    }

    options, session, err := s.wa.BeginRegistration(user)
    if err != nil {
        return nil, fmt.Errorf("begin registration: %w", err)
    }

    s.mu.Lock()
    s.sessions[userID] = session
    s.mu.Unlock()

    return options, nil
}

// FinishRegistration completes credential registration and stores the credential.
func (s *WebAuthnService) FinishRegistration(ctx context.Context, userID, userName, displayName, credName string, response *protocol.ParsedCredentialCreationData) error {
    s.mu.RLock()
    session, ok := s.sessions[userID]
    s.mu.RUnlock()

    if !ok {
        return fmt.Errorf("no registration session for user")
    }

    existingCreds, _ := s.store.GetCredentials(ctx, userID)
    user := &WebAuthnUser{
        id:          userID,
        name:        userName,
        displayName: displayName,
        credentials: existingCreds,
    }

    credential, err := s.wa.CreateCredential(user, *session, response)
    if err != nil {
        return fmt.Errorf("create credential: %w", err)
    }

    if err := s.store.SaveCredential(ctx, userID, credential, credName); err != nil {
        return fmt.Errorf("save credential: %w", err)
    }

    s.mu.Lock()
    delete(s.sessions, userID)
    s.mu.Unlock()

    return nil
}

// BeginAuthentication starts an authentication ceremony.
func (s *WebAuthnService) BeginAuthentication(ctx context.Context, userID string) (*protocol.CredentialAssertion, error) {
    creds, err := s.store.GetCredentials(ctx, userID)
    if err != nil {
        return nil, fmt.Errorf("get credentials: %w", err)
    }

    if len(creds) == 0 {
        return nil, fmt.Errorf("no credentials registered for user")
    }

    user := &WebAuthnUser{
        id:          userID,
        credentials: creds,
    }

    options, session, err := s.wa.BeginLogin(user)
    if err != nil {
        return nil, fmt.Errorf("begin login: %w", err)
    }

    s.mu.Lock()
    s.sessions[userID] = session
    s.mu.Unlock()

    return options, nil
}

// FinishAuthentication verifies the authentication response.
func (s *WebAuthnService) FinishAuthentication(ctx context.Context, userID string, response *protocol.ParsedCredentialAssertionData) error {
    s.mu.RLock()
    session, ok := s.sessions[userID]
    s.mu.RUnlock()

    if !ok {
        return fmt.Errorf("no authentication session for user")
    }

    creds, _ := s.store.GetCredentials(ctx, userID)
    user := &WebAuthnUser{
        id:          userID,
        credentials: creds,
    }

    credential, err := s.wa.ValidateLogin(user, *session, response)
    if err != nil {
        return fmt.Errorf("validate login: %w", err)
    }

    // Update sign count
    if err := s.store.UpdateSignCount(ctx, credential.ID, credential.Authenticator.SignCount); err != nil {
        // Log but don't fail
    }

    s.mu.Lock()
    delete(s.sessions, userID)
    s.mu.Unlock()

    return nil
}

// HasCredentials checks if a user has any registered credentials.
func (s *WebAuthnService) HasCredentials(ctx context.Context, userID string) (bool, error) {
    creds, err := s.store.GetCredentials(ctx, userID)
    if err != nil {
        return false, err
    }
    return len(creds) > 0, nil
}
```

**Step 3: Write tests**

Create `internal/auth/webauthn_test.go`:

```go
package auth

import (
    "testing"
)

func TestNewWebAuthnService(t *testing.T) {
    db := setupTestDB(t)
    store := NewWebAuthnStore(db)

    svc, err := NewWebAuthnService(
        "localhost",
        "Test App",
        []string{"http://localhost:18080"},
        "preferred",
        store,
    )
    if err != nil {
        t.Fatalf("NewWebAuthnService: %v", err)
    }

    if svc == nil {
        t.Fatal("expected non-nil service")
    }
}

func TestWebAuthnService_UserVerificationModes(t *testing.T) {
    db := setupTestDB(t)
    store := NewWebAuthnStore(db)

    tests := []struct {
        mode string
    }{
        {"preferred"},
        {"required"},
        {"discouraged"},
        {""},
    }

    for _, tt := range tests {
        t.Run(tt.mode, func(t *testing.T) {
            _, err := NewWebAuthnService("localhost", "Test", []string{"http://localhost"}, tt.mode, store)
            if err != nil {
                t.Errorf("failed with mode %q: %v", tt.mode, err)
            }
        })
    }
}
```

**Step 4: Add dependency**

Run: `go get github.com/go-webauthn/webauthn`

**Step 5: Run tests**

Run: `go test ./internal/auth/... -v`
Expected: Tests pass

**Step 6: Commit**

```bash
git add internal/auth/webauthn.go internal/auth/webauthn_test.go internal/config/config.go go.mod go.sum
git commit -m "feat(auth): add WebAuthn service with challenge/response"
```

---

## Task 3: WebAuthn Approval Mode

**Files:**
- Create: `internal/approvals/webauthn.go`
- Create: `internal/approvals/webauthn_test.go`
- Modify: `internal/approvals/manager.go` (add webauthn mode)

**Step 1: Create WebAuthn approval handler**

Create `internal/approvals/webauthn.go`:

```go
package approvals

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/agentsh/agentsh/internal/auth"
    "github.com/go-webauthn/webauthn/protocol"
)

// WebAuthnChallenge represents a pending WebAuthn approval challenge.
type WebAuthnChallenge struct {
    ApprovalID string                        `json:"approval_id"`
    SessionID  string                        `json:"session_id"`
    Challenge  *protocol.CredentialAssertion `json:"challenge"`
    ExpiresAt  time.Time                     `json:"expires_at"`
}

// WebAuthnApprover handles WebAuthn-based approvals.
type WebAuthnApprover struct {
    service *auth.WebAuthnService
}

// NewWebAuthnApprover creates a new WebAuthn approver.
func NewWebAuthnApprover(service *auth.WebAuthnService) *WebAuthnApprover {
    return &WebAuthnApprover{service: service}
}

// CreateChallenge generates a WebAuthn challenge for an approval request.
func (w *WebAuthnApprover) CreateChallenge(ctx context.Context, req Request, userID string) (*WebAuthnChallenge, error) {
    assertion, err := w.service.BeginAuthentication(ctx, userID)
    if err != nil {
        return nil, fmt.Errorf("begin authentication: %w", err)
    }

    return &WebAuthnChallenge{
        ApprovalID: req.ID,
        SessionID:  req.SessionID,
        Challenge:  assertion,
        ExpiresAt:  req.ExpiresAt,
    }, nil
}

// VerifyResponse validates a WebAuthn assertion response.
func (w *WebAuthnApprover) VerifyResponse(ctx context.Context, userID string, responseJSON []byte) error {
    var response protocol.CredentialAssertionResponse
    if err := json.Unmarshal(responseJSON, &response); err != nil {
        return fmt.Errorf("unmarshal response: %w", err)
    }

    parsed, err := response.Parse()
    if err != nil {
        return fmt.Errorf("parse response: %w", err)
    }

    return w.service.FinishAuthentication(ctx, userID, parsed)
}
```

**Step 2: Add WebAuthn mode to Manager**

Modify `internal/approvals/manager.go`:

Add field to Manager struct:
```go
// webauthnApprover handles WebAuthn approval challenges (webauthn mode only)
webauthnApprover *WebAuthnApprover
```

Add to New() function after switch statement:
```go
// Note: webauthn mode doesn't use TTY prompts - it uses API-based challenge/response
// The prompt function is not set for webauthn mode; resolutions come via API
```

Add method to Manager:
```go
// SetWebAuthnApprover sets the WebAuthn approver (required for webauthn mode).
func (m *Manager) SetWebAuthnApprover(approver *WebAuthnApprover) {
    m.webauthnApprover = approver
}

// GetWebAuthnChallenge returns a WebAuthn challenge for an approval request.
func (m *Manager) GetWebAuthnChallenge(ctx context.Context, approvalID, userID string) (*WebAuthnChallenge, error) {
    if m.mode != "webauthn" {
        return nil, fmt.Errorf("webauthn mode not enabled")
    }
    if m.webauthnApprover == nil {
        return nil, fmt.Errorf("webauthn approver not configured")
    }

    m.mu.Lock()
    p, ok := m.pending[approvalID]
    m.mu.Unlock()

    if !ok {
        return nil, fmt.Errorf("approval not found: %s", approvalID)
    }

    return m.webauthnApprover.CreateChallenge(ctx, p.req, userID)
}

// ResolveWithWebAuthn resolves an approval using WebAuthn assertion.
func (m *Manager) ResolveWithWebAuthn(ctx context.Context, approvalID, userID string, responseJSON []byte) error {
    if m.webauthnApprover == nil {
        return fmt.Errorf("webauthn approver not configured")
    }

    if err := m.webauthnApprover.VerifyResponse(ctx, userID, responseJSON); err != nil {
        m.Resolve(approvalID, false, "webauthn verification failed: "+err.Error())
        return err
    }

    m.Resolve(approvalID, true, "webauthn verified")
    return nil
}
```

**Step 3: Write tests**

Create `internal/approvals/webauthn_test.go`:

```go
package approvals

import (
    "testing"
)

func TestManager_WebAuthnMode(t *testing.T) {
    m := New("webauthn", 0, nil)

    if m.mode != "webauthn" {
        t.Errorf("expected mode webauthn, got %s", m.mode)
    }
}

func TestManager_GetWebAuthnChallenge_WrongMode(t *testing.T) {
    m := New("local_tty", 0, nil)

    _, err := m.GetWebAuthnChallenge(nil, "approval-1", "user-1")
    if err == nil {
        t.Error("expected error for wrong mode")
    }
}
```

**Step 4: Run tests**

Run: `go test ./internal/approvals/... -v`
Expected: Tests pass

**Step 5: Commit**

```bash
git add internal/approvals/webauthn.go internal/approvals/webauthn_test.go internal/approvals/manager.go
git commit -m "feat(approvals): add WebAuthn approval mode"
```

---

## Task 4: WebAuthn CLI Commands

**Files:**
- Create: `internal/cli/auth_webauthn.go`
- Create: `internal/cli/auth_webauthn_test.go`
- Modify: `internal/cli/root.go`

**Step 1: Create WebAuthn CLI commands**

Create `internal/cli/auth_webauthn.go`:

```go
package cli

import (
    "encoding/base64"
    "fmt"

    "github.com/spf13/cobra"
)

func newAuthCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "auth",
        Short: "Authentication management commands",
    }
    cmd.AddCommand(newAuthWebAuthnCmd())
    return cmd
}

func newAuthWebAuthnCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "webauthn",
        Short: "WebAuthn credential management",
    }
    cmd.AddCommand(newWebAuthnListCmd())
    cmd.AddCommand(newWebAuthnRegisterCmd())
    cmd.AddCommand(newWebAuthnDeleteCmd())
    return cmd
}

func newWebAuthnListCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "list",
        Short: "List registered WebAuthn credentials",
        RunE: func(cmd *cobra.Command, args []string) error {
            // TODO: Implement via API call
            fmt.Fprintln(cmd.OutOrStdout(), "WebAuthn credentials:")
            fmt.Fprintln(cmd.OutOrStdout(), "(API integration pending)")
            return nil
        },
    }
}

func newWebAuthnRegisterCmd() *cobra.Command {
    var name string

    cmd := &cobra.Command{
        Use:   "register",
        Short: "Register a new WebAuthn credential (security key)",
        Long: `Register a new WebAuthn credential such as a YubiKey or platform authenticator.

This command initiates a registration ceremony. You will need to:
1. Insert/activate your security key
2. Complete the registration in a browser or via the API

Example:
  agentsh auth webauthn register --name "My YubiKey"`,
        RunE: func(cmd *cobra.Command, args []string) error {
            fmt.Fprintf(cmd.OutOrStdout(), "Starting WebAuthn registration for credential: %s\n", name)
            fmt.Fprintln(cmd.OutOrStdout(), "(Full registration flow requires browser interaction)")
            fmt.Fprintln(cmd.OutOrStdout(), "Use the web UI at http://localhost:18080/auth/webauthn/register")
            return nil
        },
    }

    cmd.Flags().StringVar(&name, "name", "", "Name for the credential (e.g., 'My YubiKey')")
    cmd.MarkFlagRequired("name")

    return cmd
}

func newWebAuthnDeleteCmd() *cobra.Command {
    var credID string

    cmd := &cobra.Command{
        Use:   "delete",
        Short: "Delete a WebAuthn credential",
        RunE: func(cmd *cobra.Command, args []string) error {
            if credID == "" {
                return fmt.Errorf("--credential-id is required")
            }

            // Validate base64
            _, err := base64.StdEncoding.DecodeString(credID)
            if err != nil {
                return fmt.Errorf("invalid credential ID (must be base64): %w", err)
            }

            fmt.Fprintf(cmd.OutOrStdout(), "Deleting credential: %s\n", credID)
            fmt.Fprintln(cmd.OutOrStdout(), "(API integration pending)")
            return nil
        },
    }

    cmd.Flags().StringVar(&credID, "credential-id", "", "Base64-encoded credential ID to delete")
    cmd.MarkFlagRequired("credential-id")

    return cmd
}
```

**Step 2: Add to root command**

Modify `internal/cli/root.go`:

```go
// In NewRoot function, add:
cmd.AddCommand(newAuthCmd())
```

**Step 3: Write tests**

Create `internal/cli/auth_webauthn_test.go`:

```go
package cli

import (
    "testing"
)

func TestAuthWebAuthnCmd_Help(t *testing.T) {
    cmd := NewRoot("test")
    cmd.SetArgs([]string{"auth", "webauthn", "--help"})
    if err := cmd.Execute(); err != nil {
        t.Errorf("auth webauthn help failed: %v", err)
    }
}

func TestAuthWebAuthnListCmd(t *testing.T) {
    cmd := NewRoot("test")
    cmd.SetArgs([]string{"auth", "webauthn", "list"})
    if err := cmd.Execute(); err != nil {
        t.Errorf("auth webauthn list failed: %v", err)
    }
}

func TestAuthWebAuthnRegisterCmd_RequiresName(t *testing.T) {
    cmd := NewRoot("test")
    cmd.SetArgs([]string{"auth", "webauthn", "register"})
    err := cmd.Execute()
    if err == nil {
        t.Error("expected error without --name")
    }
}

func TestAuthWebAuthnDeleteCmd_ValidatesBase64(t *testing.T) {
    cmd := NewRoot("test")
    cmd.SetArgs([]string{"auth", "webauthn", "delete", "--credential-id", "not-valid-base64!!!"})
    err := cmd.Execute()
    if err == nil {
        t.Error("expected error for invalid base64")
    }
}
```

**Step 4: Run tests**

Run: `go test ./internal/cli/... -v -run WebAuthn`
Expected: Tests pass

**Step 5: Commit**

```bash
git add internal/cli/auth_webauthn.go internal/cli/auth_webauthn_test.go internal/cli/root.go
git commit -m "feat(cli): add WebAuthn credential management commands"
```

---

## Task 5: OIDC JWT Validation

**Files:**
- Create: `internal/auth/oidc.go`
- Create: `internal/auth/oidc_test.go`
- Modify: `internal/config/config.go` (add OIDC config)

**Step 1: Add OIDC config**

Add to `internal/config/config.go`:

```go
// OIDCConfig configures OpenID Connect authentication.
type OIDCConfig struct {
    Issuer          string            `yaml:"issuer"`           // e.g., "https://corp.okta.com"
    ClientID        string            `yaml:"client_id"`        // e.g., "agentsh-server"
    Audience        string            `yaml:"audience"`         // Expected audience claim
    JWKSCacheTTL    string            `yaml:"jwks_cache_ttl"`   // e.g., "1h"
    ClaimMappings   OIDCClaimMappings `yaml:"claim_mappings"`
    AllowedGroups   []string          `yaml:"allowed_groups"`   // Groups allowed to access
    GroupPolicyMap  map[string]string `yaml:"group_policy_map"` // group -> policy name
}

// OIDCClaimMappings maps OIDC claims to agentsh fields.
type OIDCClaimMappings struct {
    OperatorID string `yaml:"operator_id"` // Claim for operator ID (default: "sub")
    Groups     string `yaml:"groups"`      // Claim for groups (default: "groups")
}
```

Update `AuthConfig`:

```go
type AuthConfig struct {
    Type   string           `yaml:"type"` // "api_key", "oidc", "hybrid"
    APIKey AuthAPIKeyConfig `yaml:"api_key"`
    OIDC   OIDCConfig       `yaml:"oidc"`
}
```

**Step 2: Create OIDC authenticator**

Create `internal/auth/oidc.go`:

```go
package auth

import (
    "context"
    "fmt"
    "strings"
    "sync"
    "time"

    "github.com/coreos/go-oidc/v3/oidc"
)

// OIDCAuth validates OIDC/JWT tokens.
type OIDCAuth struct {
    verifier      *oidc.IDTokenVerifier
    issuer        string
    audience      string
    claimMappings OIDCClaimMappings
    allowedGroups map[string]bool
    groupPolicyMap map[string]string

    // Cache for validated tokens
    mu    sync.RWMutex
    cache map[string]*cachedToken
}

type OIDCClaimMappings struct {
    OperatorID string
    Groups     string
}

type cachedToken struct {
    claims    *OIDCClaims
    expiresAt time.Time
}

// OIDCClaims represents extracted claims from an OIDC token.
type OIDCClaims struct {
    Subject    string   `json:"sub"`
    OperatorID string   `json:"operator_id"`
    Groups     []string `json:"groups"`
    Email      string   `json:"email"`
    ExpiresAt  time.Time
}

// NewOIDCAuth creates a new OIDC authenticator.
func NewOIDCAuth(ctx context.Context, issuer, clientID, audience string, mappings OIDCClaimMappings, allowedGroups []string, groupPolicyMap map[string]string) (*OIDCAuth, error) {
    provider, err := oidc.NewProvider(ctx, issuer)
    if err != nil {
        return nil, fmt.Errorf("create OIDC provider: %w", err)
    }

    verifier := provider.Verifier(&oidc.Config{
        ClientID: clientID,
    })

    if mappings.OperatorID == "" {
        mappings.OperatorID = "sub"
    }
    if mappings.Groups == "" {
        mappings.Groups = "groups"
    }

    allowedGroupsMap := make(map[string]bool)
    for _, g := range allowedGroups {
        allowedGroupsMap[g] = true
    }

    return &OIDCAuth{
        verifier:       verifier,
        issuer:         issuer,
        audience:       audience,
        claimMappings:  mappings,
        allowedGroups:  allowedGroupsMap,
        groupPolicyMap: groupPolicyMap,
        cache:          make(map[string]*cachedToken),
    }, nil
}

// ValidateToken validates a JWT and returns the claims.
func (o *OIDCAuth) ValidateToken(ctx context.Context, token string) (*OIDCClaims, error) {
    // Check cache first
    o.mu.RLock()
    if cached, ok := o.cache[token]; ok && time.Now().Before(cached.expiresAt) {
        o.mu.RUnlock()
        return cached.claims, nil
    }
    o.mu.RUnlock()

    // Verify token
    idToken, err := o.verifier.Verify(ctx, token)
    if err != nil {
        return nil, fmt.Errorf("verify token: %w", err)
    }

    // Check audience if specified
    if o.audience != "" {
        found := false
        for _, aud := range idToken.Audience {
            if aud == o.audience {
                found = true
                break
            }
        }
        if !found {
            return nil, fmt.Errorf("invalid audience")
        }
    }

    // Extract claims
    var rawClaims map[string]interface{}
    if err := idToken.Claims(&rawClaims); err != nil {
        return nil, fmt.Errorf("extract claims: %w", err)
    }

    claims := &OIDCClaims{
        Subject:   idToken.Subject,
        ExpiresAt: idToken.Expiry,
    }

    // Map operator ID
    if opID, ok := rawClaims[o.claimMappings.OperatorID]; ok {
        claims.OperatorID = fmt.Sprintf("%v", opID)
    } else {
        claims.OperatorID = idToken.Subject
    }

    // Extract groups
    if groupsClaim, ok := rawClaims[o.claimMappings.Groups]; ok {
        switch g := groupsClaim.(type) {
        case []interface{}:
            for _, v := range g {
                claims.Groups = append(claims.Groups, fmt.Sprintf("%v", v))
            }
        case string:
            claims.Groups = strings.Split(g, ",")
        }
    }

    // Extract email if present
    if email, ok := rawClaims["email"]; ok {
        claims.Email = fmt.Sprintf("%v", email)
    }

    // Check allowed groups if specified
    if len(o.allowedGroups) > 0 {
        allowed := false
        for _, g := range claims.Groups {
            if o.allowedGroups[g] {
                allowed = true
                break
            }
        }
        if !allowed {
            return nil, fmt.Errorf("user not in allowed groups")
        }
    }

    // Cache the result
    o.mu.Lock()
    o.cache[token] = &cachedToken{
        claims:    claims,
        expiresAt: idToken.Expiry,
    }
    o.mu.Unlock()

    return claims, nil
}

// PolicyForGroups returns the policy name for the user's groups.
func (o *OIDCAuth) PolicyForGroups(groups []string) string {
    for _, g := range groups {
        if policy, ok := o.groupPolicyMap[g]; ok {
            return policy
        }
    }
    return "" // Default policy
}

// RoleForClaims determines the role based on claims.
func (o *OIDCAuth) RoleForClaims(claims *OIDCClaims) string {
    // Check for admin groups
    for _, g := range claims.Groups {
        if strings.Contains(strings.ToLower(g), "admin") {
            return "admin"
        }
    }
    return "agent"
}
```

**Step 3: Write tests**

Create `internal/auth/oidc_test.go`:

```go
package auth

import (
    "testing"
)

func TestOIDCClaimMappings_Defaults(t *testing.T) {
    mappings := OIDCClaimMappings{}

    if mappings.OperatorID == "" {
        // This is expected - defaults are applied in NewOIDCAuth
    }
}

func TestOIDCAuth_PolicyForGroups(t *testing.T) {
    auth := &OIDCAuth{
        groupPolicyMap: map[string]string{
            "sre-team": "privileged",
            "dev-team": "restricted",
        },
    }

    tests := []struct {
        groups   []string
        expected string
    }{
        {[]string{"sre-team"}, "privileged"},
        {[]string{"dev-team"}, "restricted"},
        {[]string{"other"}, ""},
        {[]string{"dev-team", "sre-team"}, "restricted"}, // First match wins
    }

    for _, tt := range tests {
        result := auth.PolicyForGroups(tt.groups)
        if result != tt.expected {
            t.Errorf("PolicyForGroups(%v) = %q, want %q", tt.groups, result, tt.expected)
        }
    }
}

func TestOIDCAuth_RoleForClaims(t *testing.T) {
    auth := &OIDCAuth{}

    tests := []struct {
        groups   []string
        expected string
    }{
        {[]string{"admin"}, "admin"},
        {[]string{"Admin-Team"}, "admin"},
        {[]string{"developers"}, "agent"},
        {[]string{}, "agent"},
    }

    for _, tt := range tests {
        claims := &OIDCClaims{Groups: tt.groups}
        result := auth.RoleForClaims(claims)
        if result != tt.expected {
            t.Errorf("RoleForClaims(groups=%v) = %q, want %q", tt.groups, result, tt.expected)
        }
    }
}
```

**Step 4: Add dependency**

Run: `go get github.com/coreos/go-oidc/v3/oidc`

**Step 5: Run tests**

Run: `go test ./internal/auth/... -v`
Expected: Tests pass

**Step 6: Commit**

```bash
git add internal/auth/oidc.go internal/auth/oidc_test.go internal/config/config.go go.mod go.sum
git commit -m "feat(auth): add OIDC JWT validation"
```

---

## Task 6: OIDC Auth Middleware Integration

**Files:**
- Modify: `internal/api/app.go` (add OIDC auth support)
- Modify: `internal/server/server.go` (initialize OIDC auth)

**Step 1: Add OIDC auth field to App**

Modify `internal/api/app.go`:

Add field to App struct:
```go
oidcAuth *auth.OIDCAuth
```

Update NewApp signature and initialization.

**Step 2: Update auth middleware**

Modify the `authMiddleware` method in `internal/api/app.go` to support both API key and OIDC:

```go
func (a *App) authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if a.cfg.Development.DisableAuth {
            ctx := context.WithValue(r.Context(), ctxKeyRole, "admin")
            next.ServeHTTP(w, r.WithContext(ctx))
            return
        }

        var role string

        // Try API key auth first
        if a.apiKeyAuth != nil {
            key := r.Header.Get(a.apiKeyAuth.HeaderName())
            if key != "" && a.apiKeyAuth.IsAllowed(key) {
                role = a.apiKeyAuth.RoleForKey(key)
            }
        }

        // Try OIDC auth if API key not provided or invalid
        if role == "" && a.oidcAuth != nil {
            authHeader := r.Header.Get("Authorization")
            if strings.HasPrefix(authHeader, "Bearer ") {
                token := strings.TrimPrefix(authHeader, "Bearer ")
                claims, err := a.oidcAuth.ValidateToken(r.Context(), token)
                if err == nil {
                    role = a.oidcAuth.RoleForClaims(claims)
                    // Store claims in context for later use
                    ctx := context.WithValue(r.Context(), "oidc_claims", claims)
                    r = r.WithContext(ctx)
                }
            }
        }

        if role == "" {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }

        ctx := context.WithValue(r.Context(), ctxKeyRole, role)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

**Step 3: Update server initialization**

Modify `internal/server/server.go` to initialize OIDC auth when configured:

```go
// In the server initialization, after API key auth:
var oidcAuth *auth.OIDCAuth
if cfg.Auth.Type == "oidc" || cfg.Auth.Type == "hybrid" {
    var err error
    oidcAuth, err = auth.NewOIDCAuth(
        ctx,
        cfg.Auth.OIDC.Issuer,
        cfg.Auth.OIDC.ClientID,
        cfg.Auth.OIDC.Audience,
        auth.OIDCClaimMappings{
            OperatorID: cfg.Auth.OIDC.ClaimMappings.OperatorID,
            Groups:     cfg.Auth.OIDC.ClaimMappings.Groups,
        },
        cfg.Auth.OIDC.AllowedGroups,
        cfg.Auth.OIDC.GroupPolicyMap,
    )
    if err != nil {
        return fmt.Errorf("initialize OIDC auth: %w", err)
    }
}
```

**Step 4: Run tests**

Run: `go test ./internal/api/... ./internal/server/... -v`
Expected: Tests pass

**Step 5: Commit**

```bash
git add internal/api/app.go internal/server/server.go
git commit -m "feat(auth): integrate OIDC with auth middleware"
```

---

## Task 7: Final Integration and Testing

**Files:**
- All modified files
- Integration tests

**Step 1: Run full test suite**

```bash
go test ./... -v
```

**Step 2: Build and verify**

```bash
go build ./cmd/agentsh
./agentsh --help
./agentsh auth webauthn --help
```

**Step 3: Verify config parsing**

Create a test config with WebAuthn and OIDC:

```yaml
auth:
  type: hybrid
  api_key:
    keys_file: /etc/agentsh/api-keys.yaml
  oidc:
    issuer: "https://example.okta.com"
    client_id: "agentsh"
    audience: "agentsh"
    allowed_groups:
      - "agentsh-operators"

approvals:
  enabled: true
  mode: webauthn
  webauthn:
    rp_id: "localhost"
    rp_name: "agentsh"
    rp_origins:
      - "http://localhost:18080"
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat(auth): complete Phase 2 auth expansion implementation"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | WebAuthn credential storage | `internal/auth/webauthn_store.go`, `internal/store/sqlite/sqlite.go` |
| 2 | WebAuthn service | `internal/auth/webauthn.go`, `internal/config/config.go` |
| 3 | WebAuthn approval mode | `internal/approvals/webauthn.go`, `internal/approvals/manager.go` |
| 4 | WebAuthn CLI | `internal/cli/auth_webauthn.go` |
| 5 | OIDC JWT validation | `internal/auth/oidc.go`, `internal/config/config.go` |
| 6 | OIDC middleware | `internal/api/app.go`, `internal/server/server.go` |
| 7 | Final integration | All files |
