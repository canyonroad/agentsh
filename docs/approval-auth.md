# agentsh Approval Authentication

**Version:** 0.2.0
**Date:** January 2025
**Status:** Implemented (WebAuthn, TOTP, API, local_tty modes)

---

## Overview

When agentsh requires human approval for dangerous operations, we must ensure that:

1. The approval actually comes from a human (not an AI or bot)
2. The human is authorized to approve this type of operation
3. The approval cannot be replayed or forged
4. The human understands what they're approving

### Current implementation note (auth transport)

- HTTP uses `X-API-Key` by default (configurable via `auth.api_key.header_name`).
- gRPC uses metadata: send the same key under `x-api-key` (and agentsh also accepts the configured header name lowercased).

### Current implementation note (preventing agent self-approval)

- The HTTP approvals API (`/api/v1/approvals/*`) is **disabled when auth is disabled** (`auth.type=none` or `development.disable_auth=true`).
- To use approvals over the API, enable `auth.type=api_key` and use **separate keys**:
  - agent key: `role: agent` (can exec, cannot approve)
  - approver key: `role: approver` or `admin` (can approve)
- If `approvals.mode=api` is configured while auth is disabled, the server refuses to start.

---

## 1. Threat Model

### 1.1 Threats We Protect Against

| Threat | Description | Mitigation |
|--------|-------------|------------|
| **Agent self-approval** | Agent calls approval API to approve its own requests | Credential separation, network isolation |
| **Agent-to-agent approval** | Agent A approves Agent B's requests | Human verification challenge |
| **Automated approval bots** | Scripts auto-approve without human review | Human verification challenge |
| **Replay attacks** | Reuse a previous valid approval | Nonces, timestamps, request binding |
| **Approval forgery** | Craft fake approval responses | Cryptographic signatures |
| **Social engineering** | Agent tricks human into approving dangerous action | Clear UI, context display, cooling-off period |
| **Session hijacking** | Attacker steals approval session | Short-lived tokens, binding to device |

### 1.2 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Trust Boundaries                                 │
│                                                                         │
│  UNTRUSTED                    │  TRUSTED                                │
│  ────────────────────────────│───────────────────────────────────────  │
│                               │                                         │
│  • Agent code                 │  • agentsh core                        │
│  • Agent network access       │  • Approval Gateway                    │
│  • Workspace filesystem       │  • Human verification service          │
│  • Agent API calls            │  • Signed approval tokens              │
│                               │  • Audit log                           │
│                               │                                         │
│  Agents CANNOT:               │  Humans CAN:                           │
│  • Access approval endpoints  │  • Receive approval requests           │
│  • Generate approval tokens   │  • Complete verification challenges    │
│  • Bypass verification        │  • Issue signed approvals              │
│                               │                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Credential Separation

The agent and the approver MUST have completely separate credentials that cannot be obtained from each other.

### 2.1 Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Credential Separation                                 │
│                                                                         │
│  ┌──────────────────────┐              ┌──────────────────────┐        │
│  │       Agent          │              │       Human          │        │
│  │                      │              │                      │        │
│  │  API Key:            │              │  Credentials:        │        │
│  │  sk-agent-xxxxx      │              │  • SSO login         │        │
│  │                      │              │  • WebAuthn key      │        │
│  │  Permissions:        │              │  • TOTP secret       │        │
│  │  • Execute commands  │              │                      │        │
│  │  • Read/write files  │              │  Permissions:        │        │
│  │  • Network access    │              │  • View approvals    │        │
│  │                      │              │  • Issue approvals   │        │
│  │  CANNOT:             │              │  • View audit logs   │        │
│  │  • Access /approvals │              │                      │        │
│  │  • Generate tokens   │              │                      │        │
│  └──────────────────────┘              └──────────────────────┘        │
│            │                                      │                     │
│            │                                      │                     │
│            ▼                                      ▼                     │
│  ┌──────────────────────┐              ┌──────────────────────┐        │
│  │   Agent API          │              │   Approval API       │        │
│  │   Port 8080          │              │   Port 8443          │        │
│  │                      │              │   (separate service) │        │
│  │  Endpoints:          │              │                      │        │
│  │  • /sessions         │              │  Endpoints:          │        │
│  │  • /exec             │              │  • /pending          │        │
│  │  • /events           │              │  • /approve          │        │
│  │                      │              │  • /deny             │        │
│  │  Auth: API Key       │              │  • /history          │        │
│  │                      │              │                      │        │
│  │                      │              │  Auth: SSO + MFA     │        │
│  └──────────────────────┘              └──────────────────────┘        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Network Isolation

```yaml
# Approval service runs on separate port/network
approval_service:
  # Separate from agent API
  listen: "0.0.0.0:8443"
  
  # Only accessible from trusted networks
  allowed_networks:
    - "10.0.0.0/8"      # Corporate VPN
    - "192.168.1.0/24"  # Local network
  
  # Block agent's network namespace from accessing
  block_agent_access: true
  
  # Require TLS with client certificates (optional)
  mtls:
    enabled: true
    ca_file: "/etc/agentsh/approval-ca.crt"
```

---

## 3. Human Verification Methods

### 3.1 WebAuthn/FIDO2 (Recommended)

WebAuthn provides cryptographic proof that a human with a physical device approved the request.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    WebAuthn Approval Flow                                │
│                                                                         │
│  1. Approval request created                                            │
│     └─▶ Server generates challenge (random nonce)                      │
│                                                                         │
│  2. Human receives notification                                         │
│     └─▶ Opens approval UI (web, mobile, or desktop app)                │
│                                                                         │
│  3. Human reviews request details                                       │
│     └─▶ Sees: operation, path, context, risk level                     │
│                                                                         │
│  4. Human initiates approval                                            │
│     └─▶ Clicks "Approve" button                                        │
│                                                                         │
│  5. WebAuthn challenge                                                  │
│     └─▶ Browser/app prompts for security key or biometric              │
│     └─▶ User touches YubiKey / scans fingerprint / Face ID             │
│                                                                         │
│  6. Authenticator signs challenge                                       │
│     └─▶ Private key signs: challenge + approval_id + timestamp         │
│     └─▶ Signature proves physical presence                             │
│                                                                         │
│  7. Server verifies                                                     │
│     └─▶ Validates signature against registered public key              │
│     └─▶ Checks challenge freshness (< 60 seconds)                      │
│     └─▶ Records approval with authenticator ID                         │
│                                                                         │
│  8. Approval granted                                                    │
│     └─▶ agentsh receives signed approval token                         │
│     └─▶ Operation proceeds                                             │
└─────────────────────────────────────────────────────────────────────────┘
```

**Implementation:**

```go
// Approval request with WebAuthn
type ApprovalChallenge struct {
    ApprovalID    string    `json:"approval_id"`
    Challenge     []byte    `json:"challenge"`      // Random 32 bytes
    Operation     string    `json:"operation"`
    Details       string    `json:"details"`
    CreatedAt     time.Time `json:"created_at"`
    ExpiresAt     time.Time `json:"expires_at"`     // Short-lived: 5 minutes
    
    // Bound to specific request - prevents replay
    RequestHash   string    `json:"request_hash"`   // SHA256 of operation details
}

// WebAuthn assertion for approval
type ApprovalAssertion struct {
    ApprovalID        string `json:"approval_id"`
    CredentialID      []byte `json:"credential_id"`
    AuthenticatorData []byte `json:"authenticator_data"`
    ClientDataJSON    []byte `json:"client_data_json"`
    Signature         []byte `json:"signature"`
    
    // User verification flag must be set
    // Proves biometric/PIN was used, not just presence
    UserVerification  bool   `json:"user_verification"`
}

func (s *ApprovalService) VerifyApproval(assertion ApprovalAssertion) (*ApprovalToken, error) {
    // 1. Get the challenge
    challenge, err := s.store.GetChallenge(assertion.ApprovalID)
    if err != nil {
        return nil, fmt.Errorf("invalid approval ID")
    }
    
    // 2. Check expiration
    if time.Now().After(challenge.ExpiresAt) {
        return nil, fmt.Errorf("challenge expired")
    }
    
    // 3. Get user's registered credential
    credential, err := s.store.GetCredential(assertion.CredentialID)
    if err != nil {
        return nil, fmt.Errorf("unknown credential")
    }
    
    // 4. Verify the signature
    if !webauthn.VerifyAssertion(credential.PublicKey, challenge.Challenge, assertion) {
        return nil, fmt.Errorf("invalid signature")
    }
    
    // 5. Check user verification flag
    if !assertion.UserVerification {
        return nil, fmt.Errorf("user verification required")
    }
    
    // 6. Mark challenge as used (prevent replay)
    if err := s.store.ConsumeChallenge(assertion.ApprovalID); err != nil {
        return nil, fmt.Errorf("challenge already used")
    }
    
    // 7. Generate signed approval token
    token := &ApprovalToken{
        ApprovalID:    assertion.ApprovalID,
        ApprovedBy:    credential.UserID,
        ApprovedAt:    time.Now(),
        CredentialID:  assertion.CredentialID,
        RequestHash:   challenge.RequestHash,
        ExpiresAt:     time.Now().Add(5 * time.Minute),
    }
    
    // Sign token so agentsh can verify it
    token.Signature = s.signToken(token)
    
    return token, nil
}
```

### 3.2 TOTP Challenge

For environments without WebAuthn, use time-based one-time passwords:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    TOTP Approval Flow                                    │
│                                                                         │
│  1. Human receives approval notification                                │
│                                                                         │
│  2. Human opens approval UI, reviews request                            │
│                                                                         │
│  3. UI displays: "Enter code from authenticator app"                    │
│                                                                         │
│  4. Human opens Google Authenticator / Authy / 1Password                │
│     └─▶ Gets current 6-digit code: 847293                              │
│                                                                         │
│  5. Human enters code in approval UI                                    │
│                                                                         │
│  6. Server validates TOTP                                               │
│     └─▶ Checks code matches expected value (±1 window)                 │
│     └─▶ Checks code not recently used (replay prevention)              │
│                                                                         │
│  7. Approval granted                                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

**Implementation:**

```go
type TOTPVerifier struct {
    secrets   map[string]string  // userID -> TOTP secret
    usedCodes sync.Map           // Track recently used codes
}

func (v *TOTPVerifier) Verify(userID, code string) error {
    secret, ok := v.secrets[userID]
    if !ok {
        return fmt.Errorf("user not enrolled in TOTP")
    }
    
    // Check if code was recently used (prevent replay within window)
    codeKey := fmt.Sprintf("%s:%s", userID, code)
    if _, used := v.usedCodes.Load(codeKey); used {
        return fmt.Errorf("code already used")
    }
    
    // Validate TOTP (allow ±1 time step for clock drift)
    if !totp.Validate(code, secret) {
        return fmt.Errorf("invalid code")
    }
    
    // Mark code as used for 90 seconds
    v.usedCodes.Store(codeKey, time.Now())
    go func() {
        time.Sleep(90 * time.Second)
        v.usedCodes.Delete(codeKey)
    }()
    
    return nil
}
```

### 3.3 Interactive Challenge (Anti-Bot)

Additional challenge to verify human cognition:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Interactive Challenge Types                           │
│                                                                         │
│  Type 1: Simple Math (low friction)                                     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  To approve deletion of /workspace/data.db, solve:               │   │
│  │                                                                   │   │
│  │  What is 7 + 15?  [____]                                        │   │
│  │                                                                   │   │
│  │  [Approve]  [Deny]                                               │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Type 2: Contextual Question (medium friction)                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Agent wants to delete: /workspace/important-data.db             │   │
│  │                                                                   │   │
│  │  This file was last modified 2 hours ago and is 45MB.           │   │
│  │                                                                   │   │
│  │  Type the filename to confirm: [__________________]              │   │
│  │                                                                   │   │
│  │  [Approve]  [Deny]                                               │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Type 3: Selection Challenge (CAPTCHA-like)                            │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Click the icons that represent "delete":                        │   │
│  │                                                                   │   │
│  │  [📁] [🗑️] [📝] [❌] [💾] [🔥]                                  │   │
│  │                                                                   │   │
│  │  [Approve]  [Deny]                                               │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Type 4: Timing-based (cognitive load)                                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Review period: You must wait 10 seconds before approving        │   │
│  │                                                                   │   │
│  │  Operation: rm -rf /workspace/node_modules                       │   │
│  │  Files affected: 12,847                                          │   │
│  │  Total size: 234 MB                                              │   │
│  │                                                                   │   │
│  │  [Approve in 7s...]  [Deny Now]                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Implementation:**

```go
type ChallengeType string

const (
    ChallengeMath       ChallengeType = "math"
    ChallengeFilename   ChallengeType = "filename"
    ChallengeSelection  ChallengeType = "selection"
    ChallengeTiming     ChallengeType = "timing"
)

type Challenge struct {
    Type     ChallengeType
    Question string
    Answer   string    // Expected answer (hashed for storage)
    Options  []string  // For selection type
    MinTime  time.Duration  // For timing type
}

func GenerateChallenge(risk RiskLevel, operation string) *Challenge {
    switch risk {
    case RiskLow:
        // Simple math
        a, b := rand.Intn(20), rand.Intn(20)
        return &Challenge{
            Type:     ChallengeMath,
            Question: fmt.Sprintf("What is %d + %d?", a, b),
            Answer:   hashAnswer(strconv.Itoa(a + b)),
        }
        
    case RiskMedium:
        // Type filename
        return &Challenge{
            Type:     ChallengeFilename,
            Question: "Type the filename to confirm deletion",
            Answer:   hashAnswer(filepath.Base(operation)),
        }
        
    case RiskHigh:
        // Forced delay
        return &Challenge{
            Type:    ChallengeTiming,
            MinTime: 10 * time.Second,
            Question: "Review the operation details. Approval available in 10 seconds.",
        }
        
    case RiskCritical:
        // Multiple challenges
        return &Challenge{
            Type:    ChallengeTiming,
            MinTime: 30 * time.Second,
            Question: "CRITICAL: Review carefully. Approval available in 30 seconds.",
        }
    }
    return nil
}
```

### 3.4 Push Notification with Biometric

For mobile approval:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Mobile Push + Biometric Flow                          │
│                                                                         │
│  ┌─────────────────┐                      ┌─────────────────────────┐  │
│  │    agentsh      │                      │     Mobile App          │  │
│  │                 │                      │                         │  │
│  │  Approval       │ ─── Push ──────────▶ │  📱 Notification:      │  │
│  │  requested      │     Notification     │  "Agent wants to        │  │
│  │                 │                      │   delete data.db"       │  │
│  └─────────────────┘                      │                         │  │
│                                           │  [View Details]         │  │
│                                           └───────────┬─────────────┘  │
│                                                       │                 │
│                                                       ▼                 │
│                                           ┌─────────────────────────┐  │
│                                           │  Full request details   │  │
│                                           │                         │  │
│                                           │  Operation: delete      │  │
│                                           │  Path: /workspace/...   │  │
│                                           │  Size: 45 MB            │  │
│                                           │  Agent: agent-prod-1    │  │
│                                           │                         │  │
│                                           │  [Approve] [Deny]       │  │
│                                           └───────────┬─────────────┘  │
│                                                       │                 │
│                                                       ▼                 │
│                                           ┌─────────────────────────┐  │
│                                           │                         │  │
│                                           │      🔐 Face ID         │  │
│                                           │                         │  │
│                                           │   Confirm approval      │  │
│                                           │   with Face ID          │  │
│                                           │                         │  │
│                                           └───────────┬─────────────┘  │
│                                                       │                 │
│  ┌─────────────────┐                                  │                 │
│  │    agentsh      │ ◀─── Signed approval ────────────┘                 │
│  │                 │                                                    │
│  │  ✓ Approved     │                                                    │
│  └─────────────────┘                                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Local Approval (Terminal)

For local development or when the human is at the same machine:

### 4.1 Terminal UI

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Local Terminal Approval                               │
│                                                                         │
│  $ agentsh server --approval-mode=local                                 │
│                                                                         │
│  ════════════════════════════════════════════════════════════════════  │
│  ⚠️  APPROVAL REQUIRED                                                  │
│  ════════════════════════════════════════════════════════════════════  │
│                                                                         │
│  Session:    session-abc123                                             │
│  Agent:      development-agent                                          │
│  Time:       2024-12-15 10:30:45                                        │
│                                                                         │
│  Operation:  DELETE FILE                                                │
│  Path:       /workspace/database.sqlite                                 │
│  Size:       45.2 MB                                                    │
│  Modified:   2 hours ago                                                │
│                                                                         │
│  Context:                                                               │
│  │ Recent commands in this session:                                    │
│  │   1. ls -la                                                         │
│  │   2. cat database.sqlite | head                                     │
│  │   3. rm database.sqlite  ← (triggered this approval)                │
│                                                                         │
│  ────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  To approve, solve: What is 12 + 7? [___]                              │
│                                                                         │
│  [A]pprove  [D]eny  [V]iew file  [H]istory  [?]Help                    │
│                                                                         │
│  > _                                                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Implementation

```go
type LocalApprover struct {
    tty      *os.File
    sessions map[string]*Session
}

func (a *LocalApprover) RequestApproval(req ApprovalRequest) (*ApprovalResponse, error) {
    // Must read from actual TTY, not stdin (which agent might control)
    tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
    if err != nil {
        return nil, fmt.Errorf("cannot open TTY for approval - no local human available")
    }
    defer tty.Close()
    
    // Display approval request
    a.renderApprovalUI(tty, req)
    
    // Generate challenge
    challenge := GenerateChallenge(req.RiskLevel, req.Operation)
    fmt.Fprintf(tty, "\nTo approve, solve: %s ", challenge.Question)
    
    // Read answer from TTY
    reader := bufio.NewReader(tty)
    answer, _ := reader.ReadString('\n')
    answer = strings.TrimSpace(answer)
    
    // Verify challenge
    if !challenge.Verify(answer) {
        return &ApprovalResponse{
            Decision: Denied,
            Reason:   "Failed verification challenge",
        }, nil
    }
    
    // Get final decision
    fmt.Fprintf(tty, "\n[A]pprove or [D]eny? ")
    decision, _ := reader.ReadString('\n')
    decision = strings.ToLower(strings.TrimSpace(decision))
    
    switch decision {
    case "a", "approve", "y", "yes":
        return &ApprovalResponse{
            Decision:   Approved,
            ApprovedBy: "local-user",
            ApprovedAt: time.Now(),
            Method:     "terminal-challenge",
        }, nil
    default:
        return &ApprovalResponse{
            Decision: Denied,
            Reason:   "User denied",
        }, nil
    }
}
```

### 4.3 TOTP Approval Mode

For environments where math challenges are insufficient but WebAuthn isn't available, agentsh supports TOTP (Time-based One-Time Password) as a standalone approval mode. This requires the approver to enter a 6-digit code from their authenticator app.

**Key difference from Section 3.2:** Section 3.2 describes TOTP as a *verification method* within remote approval flows (web UI, Slack). This section describes TOTP as a *standalone approval mode* (`approvals.mode: totp`) for terminal-based workflows.

#### Setup Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    TOTP Mode Session Creation                            │
│                                                                         │
│  1. User creates session with TOTP approval mode enabled                │
│     └─▶ agentsh generates per-session 20-byte secret                   │
│                                                                         │
│  2. ASCII QR code displayed on terminal                                 │
│     ┌──────────────────────────────────────────────────────────────┐   │
│     │ ╔══════════════════════════════════════════════════════════╗ │   │
│     │ ║              TOTP Setup for Session                      ║ │   │
│     │ ╠══════════════════════════════════════════════════════════╣ │   │
│     │ ║  Scan this QR code with your authenticator app:          ║ │   │
│     │ ║                                                          ║ │   │
│     │ ║  ▄▄▄▄▄▄▄ ▄▄▄▄▄ ▄▄▄▄▄▄▄                                  ║ │   │
│     │ ║  █ ▄▄▄ █ ▀ ▄▀█ █ ▄▄▄ █                                  ║ │   │
│     │ ║  █ ███ █ █▀▀▄▀ █ ███ █  (QR code)                       ║ │   │
│     │ ║  █▄▄▄▄▄█ ▄ █ ▄ █▄▄▄▄▄█                                  ║ │   │
│     │ ║  ...                                                     ║ │   │
│     │ ║                                                          ║ │   │
│     │ ║  Or enter manually:                                      ║ │   │
│     │ ║  Secret: JBSWY3DPEHPK3PXP...                            ║ │   │
│     │ ╚══════════════════════════════════════════════════════════╝ │   │
│     └──────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  3. User scans QR with Google Authenticator, Authy, 1Password, etc.    │
│     └─▶ Secret is now in authenticator app                             │
│                                                                         │
│  4. Session ready - secret stored in session metadata                   │
│     └─▶ Secret never exposed via API (json:"-" tag)                    │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Approval Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    TOTP Approval Request                                 │
│                                                                         │
│  $ agentsh exec $SID -- rm important-file.txt                           │
│                                                                         │
│  === APPROVAL REQUIRED (TOTP) ===                                       │
│  Session: abc12345                                                       │
│  Command: cmd-67890                                                      │
│  Kind: file                                                             │
│  Target: /workspace/important-file.txt                                  │
│  Rule: approve-workspace-delete                                         │
│  Message: Delete /workspace/important-file.txt?                         │
│                                                                         │
│  Enter 6-digit TOTP code: 847293                                        │
│                                                                         │
│  ✓ Approved (totp verified)                                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Configuration

```yaml
# /etc/agentsh/config.yaml or ~/.config/agentsh/config.yaml
approvals:
  enabled: true
  mode: totp       # Options: "local_tty" | "api" | "totp"
  timeout: 5m      # How long to wait for TOTP code entry
```

#### Security Properties

| Property | Value | Notes |
|----------|-------|-------|
| Secret size | 20 bytes (160-bit) | Per RFC 4226 recommendation |
| Encoding | Base32 | Standard for TOTP URIs |
| Algorithm | SHA1 | Maximum authenticator app compatibility |
| Digits | 6 | Standard TOTP |
| Period | 30 seconds | Standard TOTP |
| Skew tolerance | ±1 period | Allows 30 seconds clock drift |
| Secret lifetime | Per-session | Destroyed when session ends |
| Secret storage | Session metadata | Hidden from API responses |

#### Implementation Details

- **Secret generation:** Uses `crypto/rand` for cryptographic randomness
- **QR code:** Uses `github.com/skip2/go-qrcode` for ASCII art generation
- **Validation:** Uses `github.com/pquerna/otp/totp` (RFC 6238 compliant)
- **URI format:** `otpauth://totp/agentsh:{session_id_prefix}?secret={base32}&issuer=agentsh`

#### When to Use TOTP Mode

| Scenario | Recommended Mode |
|----------|-----------------|
| Local development, quick iteration | `local_tty` (math challenge) |
| Security-conscious local work | `totp` |
| Remote/headless with dedicated UI | `api` + WebAuthn |
| Air-gapped or no-network | `totp` (works offline) |

---

## 5. Remote Approval

### 5.1 Web UI

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Web Approval Dashboard                                │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  🔐 agentsh Approvals                    user@company.com  [⚙️] │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │                                                                  │   │
│  │  Pending Approvals (2)                                          │   │
│  │  ───────────────────────────────────────────────────────────    │   │
│  │                                                                  │   │
│  │  ┌────────────────────────────────────────────────────────┐    │   │
│  │  │ 🔴 HIGH RISK                              2 min ago    │    │   │
│  │  │                                                         │    │   │
│  │  │ Delete: /workspace/production-data.db                  │    │   │
│  │  │ Session: prod-agent-1                                   │    │   │
│  │  │ Size: 1.2 GB                                           │    │   │
│  │  │                                                         │    │   │
│  │  │ [View Details]  [✓ Approve]  [✗ Deny]                  │    │   │
│  │  └────────────────────────────────────────────────────────┘    │   │
│  │                                                                  │   │
│  │  ┌────────────────────────────────────────────────────────┐    │   │
│  │  │ 🟡 MEDIUM RISK                            5 min ago    │    │   │
│  │  │                                                         │    │   │
│  │  │ Network: Connect to api.external-service.com:443       │    │   │
│  │  │ Session: dev-agent-2                                    │    │   │
│  │  │                                                         │    │   │
│  │  │ [View Details]  [✓ Approve]  [✗ Deny]                  │    │   │
│  │  └────────────────────────────────────────────────────────┘    │   │
│  │                                                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

When user clicks "Approve":

┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│                    ┌────────────────────────────┐                       │
│                    │                            │                       │
│                    │    🔐 Verify Identity      │                       │
│                    │                            │                       │
│                    │    Use your security key   │                       │
│                    │    or biometric to         │                       │
│                    │    confirm this approval   │                       │
│                    │                            │                       │
│                    │    [Touch Security Key]    │                       │
│                    │                            │                       │
│                    │    ─── or ───              │                       │
│                    │                            │                       │
│                    │    Enter TOTP code:        │                       │
│                    │    [______]                │                       │
│                    │                            │                       │
│                    │    [Cancel]                │                       │
│                    │                            │                       │
│                    └────────────────────────────┘                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Slack Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│  #agent-approvals                                                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  🤖 agentsh                                              10:30 AM      │
│  ──────────────────────────────────────────────────────────────        │
│  ⚠️ *Approval Required*                                                │
│                                                                         │
│  *Operation:* Delete file                                              │
│  *Path:* `/workspace/database.sqlite`                                  │
│  *Size:* 45 MB                                                         │
│  *Session:* `dev-agent-1`                                              │
│  *Risk Level:* 🟡 Medium                                               │
│                                                                         │
│  *Recent commands:*                                                     │
│  ```                                                                    │
│  ls -la                                                                │
│  cat database.sqlite | head                                            │
│  rm database.sqlite                                                    │
│  ```                                                                    │
│                                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐                         │
│  │ ✓ Approve │  │ ✗ Deny  │  │ 📋 Details   │                         │
│  └──────────┘  └──────────┘  └──────────────┘                         │
│                                                                         │
│  ──────────────────────────────────────────────────────────────        │
│                                                                         │
│  👤 alice                                                10:32 AM      │
│  Clicked *Approve*                                                     │
│                                                                         │
│  🤖 agentsh                                              10:32 AM      │
│  @alice Please complete verification:                                  │
│  https://approvals.agentsh.io/verify/abc123                           │
│  (Link expires in 5 minutes)                                           │
│                                                                         │
│  👤 alice                                                10:33 AM      │
│  ✓ Verified with security key                                         │
│                                                                         │
│  🤖 agentsh                                              10:33 AM      │
│  ✅ *Approved* by @alice                                               │
│  Operation proceeding...                                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.3 Implementation

```go
type SlackApprover struct {
    client         *slack.Client
    channel        string
    verifyURL      string
    pendingActions map[string]*PendingApproval
}

func (s *SlackApprover) RequestApproval(req ApprovalRequest) error {
    // Create pending approval with verification token
    pending := &PendingApproval{
        ID:        uuid.New().String(),
        Request:   req,
        Token:     generateSecureToken(),
        ExpiresAt: time.Now().Add(5 * time.Minute),
    }
    s.pendingActions[pending.ID] = pending
    
    // Post to Slack
    _, _, err := s.client.PostMessage(s.channel, slack.MsgOptionBlocks(
        slack.NewSectionBlock(
            slack.NewTextBlockObject("mrkdwn", 
                fmt.Sprintf("⚠️ *Approval Required*\n\n*Operation:* %s\n*Path:* `%s`",
                    req.Operation, req.Path)),
            nil, nil,
        ),
        slack.NewActionBlock("approval_actions",
            slack.NewButtonBlockElement("approve", pending.ID,
                slack.NewTextBlockObject("plain_text", "✓ Approve", false, false)).
                WithStyle(slack.StylePrimary),
            slack.NewButtonBlockElement("deny", pending.ID,
                slack.NewTextBlockObject("plain_text", "✗ Deny", false, false)).
                WithStyle(slack.StyleDanger),
        ),
    ))
    
    return err
}

func (s *SlackApprover) HandleInteraction(callback slack.InteractionCallback) {
    action := callback.ActionCallback.BlockActions[0]
    pending := s.pendingActions[action.Value]
    
    if pending == nil || time.Now().After(pending.ExpiresAt) {
        s.respondEphemeral(callback, "This approval has expired.")
        return
    }
    
    switch action.ActionID {
    case "approve":
        // Don't approve yet - require verification
        verifyURL := fmt.Sprintf("%s/verify/%s?token=%s", 
            s.verifyURL, pending.ID, pending.Token)
        
        s.respondEphemeral(callback, 
            fmt.Sprintf("Please complete verification:\n%s\n(Link expires in 5 minutes)", verifyURL))
        
    case "deny":
        pending.Complete(Denied, callback.User.ID, "User denied via Slack")
        s.updateMessage(callback, "❌ *Denied* by <@%s>", callback.User.ID)
    }
}

// Verification endpoint - requires WebAuthn or TOTP
func (s *SlackApprover) HandleVerification(w http.ResponseWriter, r *http.Request) {
    pendingID := r.URL.Query().Get("id")
    token := r.URL.Query().Get("token")
    
    pending := s.pendingActions[pendingID]
    if pending == nil || pending.Token != token {
        http.Error(w, "Invalid or expired verification", 400)
        return
    }
    
    // Render verification page with WebAuthn challenge
    renderVerificationPage(w, pending)
}
```

---

## 6. Approval Tokens

Once verified, approvals are encoded as signed tokens:

```go
type ApprovalToken struct {
    // Unique identifier
    ID            string    `json:"id"`
    
    // What was approved
    ApprovalID    string    `json:"approval_id"`
    RequestHash   string    `json:"request_hash"`
    
    // Who approved
    ApprovedBy    string    `json:"approved_by"`
    Method        string    `json:"method"`        // "webauthn", "totp", "local"
    CredentialID  string    `json:"credential_id"` // For WebAuthn
    
    // When
    ApprovedAt    time.Time `json:"approved_at"`
    ExpiresAt     time.Time `json:"expires_at"`
    
    // Cryptographic signature
    Signature     []byte    `json:"signature"`
}

func (s *ApprovalService) signToken(token *ApprovalToken) []byte {
    // Sign with approval service's private key
    data := fmt.Sprintf("%s:%s:%s:%d:%d",
        token.ID,
        token.ApprovalID,
        token.RequestHash,
        token.ApprovedAt.Unix(),
        token.ExpiresAt.Unix(),
    )
    
    signature := ed25519.Sign(s.privateKey, []byte(data))
    return signature
}

func (a *agentsh) verifyApprovalToken(token *ApprovalToken, request *ApprovalRequest) error {
    // 1. Verify signature
    data := fmt.Sprintf("%s:%s:%s:%d:%d",
        token.ID,
        token.ApprovalID,
        token.RequestHash,
        token.ApprovedAt.Unix(),
        token.ExpiresAt.Unix(),
    )
    
    if !ed25519.Verify(a.approvalPublicKey, []byte(data), token.Signature) {
        return fmt.Errorf("invalid token signature")
    }
    
    // 2. Verify not expired
    if time.Now().After(token.ExpiresAt) {
        return fmt.Errorf("token expired")
    }
    
    // 3. Verify request hash matches
    expectedHash := hashRequest(request)
    if token.RequestHash != expectedHash {
        return fmt.Errorf("token does not match request")
    }
    
    // 4. Verify not already used
    if a.usedTokens.Contains(token.ID) {
        return fmt.Errorf("token already used")
    }
    a.usedTokens.Add(token.ID)
    
    return nil
}
```

---

## 7. Configuration

```yaml
# /etc/agentsh/config.yaml

approvals:
  # Approval mode: how approvals are handled
  # - "local_tty": Math challenge on terminal (default)
  # - "api": Remote approval via API (requires separate approver credentials)
  # - "totp": TOTP code from authenticator app (per-session secret)
  mode: local_tty

  # How long approvals are valid
  timeout: 5m

  # Verification methods (in order of preference) - for "api" mode
  verification:
    # WebAuthn/FIDO2 - highest security
    webauthn:
      enabled: true
      require_user_verification: true  # Require PIN/biometric, not just presence
      
    # TOTP as fallback
    totp:
      enabled: true
      issuer: "agentsh"
      
    # Interactive challenge (always enabled as final fallback)
    challenge:
      enabled: true
      types: ["math", "filename", "timing"]
      
  # Local approval (when human is at the terminal)
  local:
    enabled: true
    tty_required: true  # Must be real TTY, not piped
    
  # Remote approval channels
  remote:
    # Web UI
    web:
      enabled: true
      url: "https://approvals.agentsh.io"
      
    # Slack
    slack:
      enabled: true
      webhook_url: "${SLACK_WEBHOOK_URL}"
      channel: "#agent-approvals"
      
    # Mobile push
    push:
      enabled: false
      provider: "firebase"  # or "apns"
      
  # Network isolation
  isolation:
    # Approval API on separate port
    listen: "0.0.0.0:8443"
    
    # Only allow from trusted networks
    allowed_networks:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
      
    # Block access from agent's network namespace
    block_agent_network: true
    
  # Audit
  audit:
    log_all_requests: true
    log_verifications: true
    include_context: true
```

---

## 8. Security Checklist

### Before Deploying Approvals

- [ ] Approval service runs on separate port from agent API
- [ ] Agent credentials cannot access approval endpoints
- [ ] WebAuthn or TOTP verification is enabled
- [ ] Approval tokens are cryptographically signed
- [ ] Tokens are bound to specific requests (hash)
- [ ] Tokens expire quickly (5 minutes or less)
- [ ] Used tokens are tracked to prevent replay
- [ ] Network isolation prevents agent from reaching approval service
- [ ] All approvals are audit logged
- [ ] Challenge/response prevents automated approval

### TOTP Mode Specific

- [ ] TOTP secrets are generated with cryptographic randomness (20 bytes)
- [ ] Secrets are hidden from API responses (`json:"-"` tag)
- [ ] Secrets are never logged (check log output)
- [ ] Each session gets a unique secret (not shared across sessions)
- [ ] Authenticator app enrollment happens at session creation
- [ ] Old sessions/secrets are properly cleaned up

### Regular Security Review

- [ ] Review approval logs for anomalies
- [ ] Rotate approval service signing keys
- [ ] Audit WebAuthn credential registrations
- [ ] Test that agents cannot reach approval endpoints
- [ ] Verify token expiration is enforced
- [ ] Check for replay attack attempts in logs
