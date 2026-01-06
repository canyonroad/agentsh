# TOTP Approval Mode Design

## Overview

Add TOTP (Time-based One-Time Password) as a third approval mode for human-in-the-loop verification. This provides cryptographic proof that a human with access to an authenticator app approved the operation, stronger than the current math challenge approach.

**Goal:** Enable TOTP-based approval where users enter a 6-digit code from their authenticator app to approve sensitive operations.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Secret scope | Per-session | Fresh secret each session, no persistent state, secret dies with session |
| Secret display | CLI + ASCII QR code | Works in terminal, no external dependencies, easy to scan |
| Mode enablement | Config-based | `approvals.mode: totp` in agentsh.yaml, consistent with existing modes |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Session Creation                          │
│  1. Generate 20-byte secret (crypto/rand)                   │
│  2. Store in Session.TOTPSecret (hidden from API)           │
│  3. Display ASCII QR code + manual secret once              │
│  4. User scans with authenticator app                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Approval Request                          │
│  1. Display operation details on TTY                        │
│  2. Prompt: "Enter 6-digit TOTP code: "                     │
│  3. User enters code from authenticator app                 │
│  4. Validate with ±1 period skew tolerance                  │
│  5. Approve if valid, deny if invalid/timeout               │
└─────────────────────────────────────────────────────────────┘
```

## Data Model

### Session Changes (`pkg/types/session.go`)

```go
type Session struct {
    // ... existing fields ...
    TOTPSecret string `json:"-"` // Hidden from JSON/API responses
}
```

The `json:"-"` tag ensures the secret is never exposed via the API. The secret is stored in the session metadata in the SQLite database.

### Secret Generation

- **Size:** 20 bytes (160-bit) per RFC 4226 recommendation
- **Encoding:** Base32 (standard for TOTP URIs)
- **Source:** `crypto/rand` for cryptographic randomness

```go
func GenerateTOTPSecret() (string, error) {
    secret := make([]byte, 20)
    if _, err := rand.Read(secret); err != nil {
        return "", err
    }
    return base32.StdEncoding.EncodeToString(secret), nil
}
```

## QR Code Display

### URI Format

```
otpauth://totp/agentsh:{session_id_prefix}?secret={base32_secret}&issuer=agentsh
```

- **Label:** `agentsh:{first 8 chars of session ID}` for identification
- **Issuer:** `agentsh` for app organization
- **Algorithm:** SHA1 (default, widely supported)
- **Digits:** 6 (standard)
- **Period:** 30 seconds (standard)

### Display Format

```
╔══════════════════════════════════════════╗
║         TOTP Setup for Session           ║
╠══════════════════════════════════════════╣
║  Scan this QR code with your             ║
║  authenticator app:                      ║
║                                          ║
║  ▄▄▄▄▄▄▄ ▄▄▄▄▄ ▄▄▄▄▄▄▄                  ║
║  █ ▄▄▄ █ ▀ ▄▀█ █ ▄▄▄ █                  ║
║  █ ███ █ █▀▀▄▀ █ ███ █                  ║
║  █▄▄▄▄▄█ ▄ █ ▄ █▄▄▄▄▄█                  ║
║  ... (QR code continues)                 ║
║                                          ║
║  Or enter manually:                      ║
║  Secret: JBSWY3DPEHPK3PXP                ║
║                                          ║
║  Press Enter when ready...               ║
╚══════════════════════════════════════════╝
```

### Dependency

Use `github.com/skip2/go-qrcode` for ASCII QR generation:
- `qrcode.New(uri, qrcode.Medium)` creates QR
- `ToString(false)` renders as ASCII art

## TOTP Verification Flow

### Prompt Function

```go
func (m *Manager) promptTOTP(ctx context.Context, req Request) (Resolution, error) {
    // 1. Display approval request
    fmt.Fprintf(m.tty, "\n[APPROVAL REQUIRED]\n")
    fmt.Fprintf(m.tty, "Operation: %s\n", req.Operation)
    fmt.Fprintf(m.tty, "Target: %s\n", req.Target)
    fmt.Fprintf(m.tty, "Reason: %s\n\n", req.Reason)

    // 2. Prompt for TOTP code
    fmt.Fprintf(m.tty, "Enter 6-digit TOTP code: ")

    // 3. Read input with timeout
    code, err := readLineWithTimeout(m.tty, m.timeout)
    if err != nil {
        return Resolution{Approved: false, Reason: "timeout"}, nil
    }

    // 4. Validate TOTP
    valid := totp.Validate(code, m.totpSecret)
    if !valid {
        return Resolution{Approved: false, Reason: "invalid code"}, nil
    }

    return Resolution{Approved: true, Reason: "totp verified"}, nil
}
```

### Validation Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Algorithm | SHA1 | Maximum compatibility with authenticator apps |
| Digits | 6 | Standard, balance of security and usability |
| Period | 30 seconds | Standard TOTP period |
| Skew | ±1 period | Allows 30 seconds clock drift tolerance |

### Dependency

Use `github.com/pquerna/otp/totp` for validation:
- `totp.Validate(code, secret)` with default options
- Handles skew tolerance automatically

## Config Changes

### Schema Update

```yaml
# In agentsh.yaml
approvals:
  mode: totp           # Options: "local_tty" | "api" | "totp"
  timeout: 5m          # How long to wait for TOTP code
```

### Validation

Add `totp` to valid mode values in `internal/config/config.go`.

### Session Creation Flow

1. Parse config, check `approvals.mode`
2. If `totp`:
   - Generate secret via `GenerateTOTPSecret()`
   - Store in `Session.TOTPSecret`
   - Display QR code setup screen
   - Wait for user to press Enter
3. Create session with secret stored

## Testing Approach

### Unit Tests (`internal/approvals/totp_test.go`)

**Secret generation:**
- Verify 20 bytes generated
- Verify valid base32 encoding
- Verify uniqueness across calls

**TOTP validation:**
- Valid code within current period → approve
- Valid code within ±1 period (skew) → approve
- Invalid code → deny
- Expired/old code (outside skew) → deny
- Non-numeric input → deny
- Wrong length (not 6 digits) → deny

**QR code generation:**
- Verify otpauth:// URI format
- Verify ASCII output contains QR pattern

### Integration Tests (`internal/approvals/manager_test.go`)

- Test `promptTOTP` with mock stdin providing valid/invalid codes
- Test timeout behavior when no code entered
- Test mode selection creates correct prompt function

### Manual Testing

- Use Google Authenticator or similar to scan QR
- Verify codes work within time window

## Dependencies

| Package | Purpose | License |
|---------|---------|---------|
| `github.com/skip2/go-qrcode` | ASCII QR code generation | MIT |
| `github.com/pquerna/otp` | TOTP validation (RFC 6238) | Apache 2.0 |

## Security Considerations

1. **Secret storage:** Hidden from API responses via `json:"-"`, stored only in session DB
2. **Secret lifetime:** Per-session, destroyed when session ends
3. **Brute force:** 6-digit code = 1M possibilities, 30-second window limits attempts
4. **Clock sync:** ±1 period skew handles minor clock drift
5. **No secret logging:** Ensure secret never appears in logs

## File Changes Summary

| File | Change |
|------|--------|
| `pkg/types/session.go` | Add `TOTPSecret` field |
| `internal/approvals/totp.go` | New file: secret gen, QR display, validation |
| `internal/approvals/manager.go` | Add `promptTOTP`, mode selection |
| `internal/config/config.go` | Add `totp` to valid modes |
| `internal/cli/session.go` | Display QR on session create if TOTP mode |
| `go.mod` | Add qrcode and otp dependencies |
