# Phase 3: MCP Security Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement MCP tool whitelisting, version pinning, and rate limiting to harden the MCP attack surface.

**Architecture:** Policy-based tool access control with persistent version pinning and token bucket rate limiting at domain and MCP server levels.

**Tech Stack:** Go, SQLite (existing store), token bucket algorithm (existing `pkg/ratelimit`)

---

## Task 1: MCP Policy Configuration Types

**Files:**
- Create: `internal/mcpinspect/policy.go`
- Create: `internal/mcpinspect/policy_test.go`
- Modify: `internal/config/config.go` (add MCP policy config to SandboxConfig)

**Step 1: Add MCP policy types to config**

In `internal/config/config.go`, add to `SandboxConfig`:

```go
type SandboxConfig struct {
    // ... existing fields ...
    MCP SandboxMCPConfig `yaml:"mcp"`
}

// SandboxMCPConfig configures MCP security policies.
type SandboxMCPConfig struct {
    EnforcePolicy bool           `yaml:"enforce_policy"`
    FailClosed    bool           `yaml:"fail_closed"` // Block unknown tools if true
    ToolPolicy    string         `yaml:"tool_policy"` // allowlist, denylist, none
    AllowedTools  []MCPToolRule  `yaml:"allowed_tools"`
    DeniedTools   []MCPToolRule  `yaml:"denied_tools"`
    VersionPinning MCPVersionPinningConfig `yaml:"version_pinning"`
    RateLimits    MCPRateLimitsConfig     `yaml:"rate_limits"`
}

// MCPToolRule defines a tool matching rule.
type MCPToolRule struct {
    Server      string `yaml:"server"`       // Server ID or "*" for any
    Tool        string `yaml:"tool"`         // Tool name or "*" for any
    ContentHash string `yaml:"content_hash"` // Optional SHA-256 hash
}

// MCPVersionPinningConfig configures version pinning behavior.
type MCPVersionPinningConfig struct {
    Enabled        bool   `yaml:"enabled"`
    OnChange       string `yaml:"on_change"`        // block, alert, allow
    AutoTrustFirst bool   `yaml:"auto_trust_first"` // Pin on first use
}

// MCPRateLimitsConfig configures MCP rate limiting.
type MCPRateLimitsConfig struct {
    Enabled        bool              `yaml:"enabled"`
    DefaultRPM     int               `yaml:"default_rpm"`     // Default calls per minute
    DefaultBurst   int               `yaml:"default_burst"`
    PerServer      map[string]MCPRateLimit `yaml:"per_server"`
}

// MCPRateLimit defines rate limit for a server.
type MCPRateLimit struct {
    CallsPerMinute int `yaml:"calls_per_minute"`
    Burst          int `yaml:"burst"`
}
```

**Step 2: Run tests**

Run: `go test ./internal/config/... -v`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): add MCP security policy configuration types"
```

---

## Task 2: MCP Tool Policy Evaluator

**Files:**
- Create: `internal/mcpinspect/policy.go`
- Create: `internal/mcpinspect/policy_test.go`

**Step 1: Write failing test for policy evaluator**

Create `internal/mcpinspect/policy_test.go`:

```go
package mcpinspect

import (
    "testing"

    "github.com/agentsh/agentsh/internal/config"
)

func TestPolicyEvaluator_AllowlistMode(t *testing.T) {
    cfg := config.SandboxMCPConfig{
        EnforcePolicy: true,
        ToolPolicy:    "allowlist",
        AllowedTools: []config.MCPToolRule{
            {Server: "filesystem", Tool: "read_file"},
            {Server: "github", Tool: "*"},
        },
    }

    eval := NewPolicyEvaluator(cfg)

    tests := []struct {
        server   string
        tool     string
        expected bool
    }{
        {"filesystem", "read_file", true},
        {"filesystem", "write_file", false},
        {"github", "create_issue", true},
        {"github", "any_tool", true},
        {"unknown", "any", false},
    }

    for _, tc := range tests {
        result := eval.IsAllowed(tc.server, tc.tool)
        if result != tc.expected {
            t.Errorf("IsAllowed(%q, %q) = %v, want %v", tc.server, tc.tool, result, tc.expected)
        }
    }
}

func TestPolicyEvaluator_DenylistMode(t *testing.T) {
    cfg := config.SandboxMCPConfig{
        EnforcePolicy: true,
        ToolPolicy:    "denylist",
        DeniedTools: []config.MCPToolRule{
            {Server: "*", Tool: "execute_shell"},
            {Server: "dangerous", Tool: "*"},
        },
    }

    eval := NewPolicyEvaluator(cfg)

    tests := []struct {
        server   string
        tool     string
        expected bool
    }{
        {"filesystem", "execute_shell", false},
        {"github", "execute_shell", false},
        {"dangerous", "any_tool", false},
        {"filesystem", "read_file", true},
        {"github", "create_issue", true},
    }

    for _, tc := range tests {
        result := eval.IsAllowed(tc.server, tc.tool)
        if result != tc.expected {
            t.Errorf("IsAllowed(%q, %q) = %v, want %v", tc.server, tc.tool, result, tc.expected)
        }
    }
}

func TestPolicyEvaluator_HashVerification(t *testing.T) {
    cfg := config.SandboxMCPConfig{
        EnforcePolicy: true,
        ToolPolicy:    "allowlist",
        AllowedTools: []config.MCPToolRule{
            {Server: "custom", Tool: "query_db", ContentHash: "sha256:abc123"},
        },
    }

    eval := NewPolicyEvaluator(cfg)

    if eval.IsAllowedWithHash("custom", "query_db", "sha256:abc123") != true {
        t.Error("Expected allowed with matching hash")
    }
    if eval.IsAllowedWithHash("custom", "query_db", "sha256:different") != false {
        t.Error("Expected denied with different hash")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpinspect/... -run TestPolicyEvaluator -v`
Expected: FAIL (PolicyEvaluator not defined)

**Step 3: Implement PolicyEvaluator**

Create `internal/mcpinspect/policy.go`:

```go
package mcpinspect

import (
    "strings"

    "github.com/agentsh/agentsh/internal/config"
)

// PolicyDecision represents the result of a policy evaluation.
type PolicyDecision struct {
    Allowed bool
    Reason  string
    Rule    *config.MCPToolRule // The rule that matched, if any
}

// PolicyEvaluator evaluates MCP tool access based on configured policies.
type PolicyEvaluator struct {
    cfg config.SandboxMCPConfig
}

// NewPolicyEvaluator creates a new policy evaluator.
func NewPolicyEvaluator(cfg config.SandboxMCPConfig) *PolicyEvaluator {
    return &PolicyEvaluator{cfg: cfg}
}

// IsAllowed checks if a tool invocation is permitted.
func (p *PolicyEvaluator) IsAllowed(serverID, toolName string) bool {
    decision := p.Evaluate(serverID, toolName, "")
    return decision.Allowed
}

// IsAllowedWithHash checks if a tool invocation is permitted with hash verification.
func (p *PolicyEvaluator) IsAllowedWithHash(serverID, toolName, hash string) bool {
    decision := p.Evaluate(serverID, toolName, hash)
    return decision.Allowed
}

// Evaluate performs a full policy evaluation and returns the decision.
func (p *PolicyEvaluator) Evaluate(serverID, toolName, hash string) PolicyDecision {
    if !p.cfg.EnforcePolicy {
        return PolicyDecision{Allowed: true, Reason: "policy enforcement disabled"}
    }

    switch p.cfg.ToolPolicy {
    case "allowlist":
        return p.evaluateAllowlist(serverID, toolName, hash)
    case "denylist":
        return p.evaluateDenylist(serverID, toolName, hash)
    default:
        return PolicyDecision{Allowed: true, Reason: "no policy configured"}
    }
}

func (p *PolicyEvaluator) evaluateAllowlist(serverID, toolName, hash string) PolicyDecision {
    for _, rule := range p.cfg.AllowedTools {
        if p.matchesRule(rule, serverID, toolName, hash) {
            return PolicyDecision{Allowed: true, Reason: "matched allowlist rule", Rule: &rule}
        }
    }
    if p.cfg.FailClosed {
        return PolicyDecision{Allowed: false, Reason: "no matching allowlist rule (fail closed)"}
    }
    return PolicyDecision{Allowed: false, Reason: "no matching allowlist rule"}
}

func (p *PolicyEvaluator) evaluateDenylist(serverID, toolName, hash string) PolicyDecision {
    for _, rule := range p.cfg.DeniedTools {
        if p.matchesRule(rule, serverID, toolName, hash) {
            return PolicyDecision{Allowed: false, Reason: "matched denylist rule", Rule: &rule}
        }
    }
    return PolicyDecision{Allowed: true, Reason: "no matching denylist rule"}
}

func (p *PolicyEvaluator) matchesRule(rule config.MCPToolRule, serverID, toolName, hash string) bool {
    // Check server match
    if rule.Server != "*" && !strings.EqualFold(rule.Server, serverID) {
        return false
    }

    // Check tool match
    if rule.Tool != "*" && !strings.EqualFold(rule.Tool, toolName) {
        return false
    }

    // Check hash if specified in rule
    if rule.ContentHash != "" && rule.ContentHash != hash {
        return false
    }

    return true
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/mcpinspect/... -run TestPolicyEvaluator -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/mcpinspect/policy.go internal/mcpinspect/policy_test.go
git commit -m "feat(mcpinspect): add policy evaluator for MCP tool whitelisting"
```

---

## Task 3: Persistent Tool Pin Storage

**Files:**
- Create: `internal/mcpinspect/pins.go`
- Create: `internal/mcpinspect/pins_test.go`
- Modify: `internal/store/sqlite/sqlite.go` (add pin table and methods)

**Step 1: Write failing test for pin storage**

Create `internal/mcpinspect/pins_test.go`:

```go
package mcpinspect

import (
    "os"
    "path/filepath"
    "testing"
    "time"
)

func TestPinStore_TrustAndVerify(t *testing.T) {
    tmpDir := t.TempDir()
    store, err := NewPinStore(filepath.Join(tmpDir, "pins.db"))
    if err != nil {
        t.Fatalf("NewPinStore: %v", err)
    }
    defer store.Close()

    serverID := "github"
    toolName := "create_issue"
    hash := "sha256:abc123def456"

    // Trust a tool
    err = store.Trust(serverID, toolName, hash)
    if err != nil {
        t.Fatalf("Trust: %v", err)
    }

    // Verify same hash
    result, err := store.Verify(serverID, toolName, hash)
    if err != nil {
        t.Fatalf("Verify: %v", err)
    }
    if result.Status != PinStatusMatch {
        t.Errorf("Expected PinStatusMatch, got %v", result.Status)
    }

    // Verify different hash
    result, err = store.Verify(serverID, toolName, "sha256:different")
    if err != nil {
        t.Fatalf("Verify: %v", err)
    }
    if result.Status != PinStatusMismatch {
        t.Errorf("Expected PinStatusMismatch, got %v", result.Status)
    }
    if result.PinnedHash != hash {
        t.Errorf("Expected pinned hash %q, got %q", hash, result.PinnedHash)
    }
}

func TestPinStore_List(t *testing.T) {
    tmpDir := t.TempDir()
    store, err := NewPinStore(filepath.Join(tmpDir, "pins.db"))
    if err != nil {
        t.Fatalf("NewPinStore: %v", err)
    }
    defer store.Close()

    // Trust multiple tools
    store.Trust("github", "create_issue", "sha256:aaa")
    store.Trust("github", "list_repos", "sha256:bbb")
    store.Trust("filesystem", "read_file", "sha256:ccc")

    // List all
    pins, err := store.List("")
    if err != nil {
        t.Fatalf("List: %v", err)
    }
    if len(pins) != 3 {
        t.Errorf("Expected 3 pins, got %d", len(pins))
    }

    // List by server
    pins, err = store.List("github")
    if err != nil {
        t.Fatalf("List: %v", err)
    }
    if len(pins) != 2 {
        t.Errorf("Expected 2 pins for github, got %d", len(pins))
    }
}

func TestPinStore_Reset(t *testing.T) {
    tmpDir := t.TempDir()
    store, err := NewPinStore(filepath.Join(tmpDir, "pins.db"))
    if err != nil {
        t.Fatalf("NewPinStore: %v", err)
    }
    defer store.Close()

    store.Trust("github", "create_issue", "sha256:aaa")

    // Reset
    err = store.Reset("github", "create_issue")
    if err != nil {
        t.Fatalf("Reset: %v", err)
    }

    // Verify not pinned
    result, _ := store.Verify("github", "create_issue", "sha256:bbb")
    if result.Status != PinStatusNotPinned {
        t.Errorf("Expected PinStatusNotPinned after reset, got %v", result.Status)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpinspect/... -run TestPinStore -v`
Expected: FAIL (PinStore not defined)

**Step 3: Implement PinStore**

Create `internal/mcpinspect/pins.go`:

```go
package mcpinspect

import (
    "database/sql"
    "fmt"
    "time"

    _ "github.com/mattn/go-sqlite3"
)

// PinStatus indicates the result of a pin verification.
type PinStatus int

const (
    PinStatusNotPinned PinStatus = iota
    PinStatusMatch
    PinStatusMismatch
)

func (s PinStatus) String() string {
    switch s {
    case PinStatusNotPinned:
        return "not_pinned"
    case PinStatusMatch:
        return "match"
    case PinStatusMismatch:
        return "mismatch"
    default:
        return "unknown"
    }
}

// Pin represents a pinned tool version.
type Pin struct {
    ServerID   string    `json:"server_id"`
    ToolName   string    `json:"tool_name"`
    Hash       string    `json:"hash"`
    TrustedAt  time.Time `json:"trusted_at"`
    TrustedBy  string    `json:"trusted_by,omitempty"` // operator ID if known
}

// VerifyResult is returned from pin verification.
type VerifyResult struct {
    Status      PinStatus
    PinnedHash  string // Only set if pinned
    CurrentHash string // The hash being verified
}

// PinStore manages persistent tool version pins.
type PinStore struct {
    db *sql.DB
}

// NewPinStore creates a new pin store at the given path.
func NewPinStore(path string) (*PinStore, error) {
    db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
    if err != nil {
        return nil, fmt.Errorf("open database: %w", err)
    }

    if err := initPinSchema(db); err != nil {
        db.Close()
        return nil, err
    }

    return &PinStore{db: db}, nil
}

func initPinSchema(db *sql.DB) error {
    _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS mcp_pins (
            server_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            hash TEXT NOT NULL,
            trusted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            trusted_by TEXT,
            PRIMARY KEY (server_id, tool_name)
        );
        CREATE INDEX IF NOT EXISTS idx_pins_server ON mcp_pins(server_id);
    `)
    return err
}

// Close closes the pin store.
func (s *PinStore) Close() error {
    return s.db.Close()
}

// Trust pins a tool at the given hash.
func (s *PinStore) Trust(serverID, toolName, hash string) error {
    return s.TrustWithOperator(serverID, toolName, hash, "")
}

// TrustWithOperator pins a tool with operator attribution.
func (s *PinStore) TrustWithOperator(serverID, toolName, hash, operatorID string) error {
    _, err := s.db.Exec(`
        INSERT OR REPLACE INTO mcp_pins (server_id, tool_name, hash, trusted_at, trusted_by)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)
    `, serverID, toolName, hash, operatorID)
    return err
}

// Verify checks if a tool hash matches its pin.
func (s *PinStore) Verify(serverID, toolName, hash string) (*VerifyResult, error) {
    var pinnedHash string
    err := s.db.QueryRow(`
        SELECT hash FROM mcp_pins WHERE server_id = ? AND tool_name = ?
    `, serverID, toolName).Scan(&pinnedHash)

    if err == sql.ErrNoRows {
        return &VerifyResult{
            Status:      PinStatusNotPinned,
            CurrentHash: hash,
        }, nil
    }
    if err != nil {
        return nil, err
    }

    status := PinStatusMatch
    if pinnedHash != hash {
        status = PinStatusMismatch
    }

    return &VerifyResult{
        Status:      status,
        PinnedHash:  pinnedHash,
        CurrentHash: hash,
    }, nil
}

// List returns all pins, optionally filtered by server.
func (s *PinStore) List(serverFilter string) ([]Pin, error) {
    var rows *sql.Rows
    var err error

    if serverFilter == "" {
        rows, err = s.db.Query(`
            SELECT server_id, tool_name, hash, trusted_at, COALESCE(trusted_by, '')
            FROM mcp_pins ORDER BY server_id, tool_name
        `)
    } else {
        rows, err = s.db.Query(`
            SELECT server_id, tool_name, hash, trusted_at, COALESCE(trusted_by, '')
            FROM mcp_pins WHERE server_id = ? ORDER BY tool_name
        `, serverFilter)
    }
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var pins []Pin
    for rows.Next() {
        var p Pin
        if err := rows.Scan(&p.ServerID, &p.ToolName, &p.Hash, &p.TrustedAt, &p.TrustedBy); err != nil {
            return nil, err
        }
        pins = append(pins, p)
    }
    return pins, rows.Err()
}

// Get returns a specific pin.
func (s *PinStore) Get(serverID, toolName string) (*Pin, error) {
    var p Pin
    err := s.db.QueryRow(`
        SELECT server_id, tool_name, hash, trusted_at, COALESCE(trusted_by, '')
        FROM mcp_pins WHERE server_id = ? AND tool_name = ?
    `, serverID, toolName).Scan(&p.ServerID, &p.ToolName, &p.Hash, &p.TrustedAt, &p.TrustedBy)

    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    return &p, nil
}

// Reset removes a tool's pin.
func (s *PinStore) Reset(serverID, toolName string) error {
    _, err := s.db.Exec(`
        DELETE FROM mcp_pins WHERE server_id = ? AND tool_name = ?
    `, serverID, toolName)
    return err
}

// ResetServer removes all pins for a server.
func (s *PinStore) ResetServer(serverID string) error {
    _, err := s.db.Exec(`DELETE FROM mcp_pins WHERE server_id = ?`, serverID)
    return err
}

// ResetAll removes all pins.
func (s *PinStore) ResetAll() error {
    _, err := s.db.Exec(`DELETE FROM mcp_pins`)
    return err
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/mcpinspect/... -run TestPinStore -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/mcpinspect/pins.go internal/mcpinspect/pins_test.go
git commit -m "feat(mcpinspect): add persistent pin storage for version pinning"
```

---

## Task 4: MCP Pins CLI Commands

**Files:**
- Create: `internal/cli/mcp_pins.go`
- Create: `internal/cli/mcp_pins_test.go`
- Modify: `internal/cli/mcp_cmd.go` (add pins subcommand)

**Step 1: Write failing test for pins CLI**

Create `internal/cli/mcp_pins_test.go`:

```go
package cli

import (
    "bytes"
    "os"
    "path/filepath"
    "testing"
)

func TestMCPPinsListCmd(t *testing.T) {
    tmpDir := t.TempDir()
    pinPath := filepath.Join(tmpDir, "pins.db")
    os.Setenv("AGENTSH_PINS_PATH", pinPath)
    defer os.Unsetenv("AGENTSH_PINS_PATH")

    cmd := newMCPPinsCmd()
    cmd.SetArgs([]string{"list"})
    var buf bytes.Buffer
    cmd.SetOut(&buf)

    if err := cmd.Execute(); err != nil {
        t.Fatalf("Execute: %v", err)
    }

    if !bytes.Contains(buf.Bytes(), []byte("No pins found")) {
        t.Errorf("Expected 'No pins found', got: %s", buf.String())
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestMCPPins -v`
Expected: FAIL (newMCPPinsCmd not defined)

**Step 3: Implement pins CLI**

Create `internal/cli/mcp_pins.go`:

```go
package cli

import (
    "fmt"
    "os"

    "github.com/agentsh/agentsh/internal/mcpinspect"
    "github.com/spf13/cobra"
)

func newMCPPinsCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "pins",
        Short: "Manage MCP tool version pins",
    }

    cmd.AddCommand(newMCPPinsListCmd())
    cmd.AddCommand(newMCPPinsTrustCmd())
    cmd.AddCommand(newMCPPinsDiffCmd())
    cmd.AddCommand(newMCPPinsResetCmd())

    return cmd
}

func getPinStore() (*mcpinspect.PinStore, error) {
    path := os.Getenv("AGENTSH_PINS_PATH")
    if path == "" {
        path = getenvDefault("AGENTSH_DATA_DIR", "./data") + "/mcp_pins.db"
    }
    return mcpinspect.NewPinStore(path)
}

func newMCPPinsListCmd() *cobra.Command {
    var (
        serverID string
        jsonOut  bool
    )

    cmd := &cobra.Command{
        Use:   "list",
        Short: "List pinned tool versions",
        RunE: func(cmd *cobra.Command, args []string) error {
            store, err := getPinStore()
            if err != nil {
                return fmt.Errorf("open pin store: %w", err)
            }
            defer store.Close()

            pins, err := store.List(serverID)
            if err != nil {
                return err
            }

            if len(pins) == 0 {
                cmd.Println("No pins found")
                return nil
            }

            if jsonOut {
                return printJSON(cmd, pins)
            }

            cmd.Println("SERVER              TOOL                HASH                     TRUSTED AT")
            for _, p := range pins {
                cmd.Printf("%-19s %-19s %-24s %s\n",
                    truncate(p.ServerID, 19),
                    truncate(p.ToolName, 19),
                    truncate(p.Hash, 24),
                    p.TrustedAt.Format("2006-01-02 15:04:05"),
                )
            }
            return nil
        },
    }

    cmd.Flags().StringVar(&serverID, "server", "", "Filter by server ID")
    cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")

    return cmd
}

func newMCPPinsTrustCmd() *cobra.Command {
    var (
        serverID string
        toolName string
        hash     string
    )

    cmd := &cobra.Command{
        Use:   "trust",
        Short: "Pin a tool at its current or specified hash",
        RunE: func(cmd *cobra.Command, args []string) error {
            if serverID == "" || toolName == "" {
                return fmt.Errorf("--server and --tool are required")
            }

            store, err := getPinStore()
            if err != nil {
                return fmt.Errorf("open pin store: %w", err)
            }
            defer store.Close()

            // If hash not provided, we'd need to look it up from the registry
            // For now, require explicit hash
            if hash == "" {
                return fmt.Errorf("--hash is required (tool hash from tools list)")
            }

            if err := store.Trust(serverID, toolName, hash); err != nil {
                return err
            }

            cmd.Printf("Pinned %s:%s at %s\n", serverID, toolName, truncate(hash, 16))
            return nil
        },
    }

    cmd.Flags().StringVar(&serverID, "server", "", "Server ID")
    cmd.Flags().StringVar(&toolName, "tool", "", "Tool name")
    cmd.Flags().StringVar(&hash, "hash", "", "Content hash to pin")

    return cmd
}

func newMCPPinsDiffCmd() *cobra.Command {
    var (
        serverID string
        toolName string
    )

    cmd := &cobra.Command{
        Use:   "diff",
        Short: "Show difference between pinned and current tool version",
        RunE: func(cmd *cobra.Command, args []string) error {
            if serverID == "" || toolName == "" {
                return fmt.Errorf("--server and --tool are required")
            }

            store, err := getPinStore()
            if err != nil {
                return fmt.Errorf("open pin store: %w", err)
            }
            defer store.Close()

            pin, err := store.Get(serverID, toolName)
            if err != nil {
                return err
            }
            if pin == nil {
                return fmt.Errorf("tool %s:%s is not pinned", serverID, toolName)
            }

            cmd.Printf("Pinned hash: %s\n", pin.Hash)
            cmd.Printf("Trusted at:  %s\n", pin.TrustedAt.Format("2006-01-02 15:04:05"))
            cmd.Println("\nNote: To see current hash, use 'agentsh mcp tools --server <server>'")
            return nil
        },
    }

    cmd.Flags().StringVar(&serverID, "server", "", "Server ID")
    cmd.Flags().StringVar(&toolName, "tool", "", "Tool name")

    return cmd
}

func newMCPPinsResetCmd() *cobra.Command {
    var (
        serverID string
        toolName string
        all      bool
    )

    cmd := &cobra.Command{
        Use:   "reset",
        Short: "Remove a tool's version pin",
        RunE: func(cmd *cobra.Command, args []string) error {
            store, err := getPinStore()
            if err != nil {
                return fmt.Errorf("open pin store: %w", err)
            }
            defer store.Close()

            if all {
                if err := store.ResetAll(); err != nil {
                    return err
                }
                cmd.Println("All pins removed")
                return nil
            }

            if serverID == "" {
                return fmt.Errorf("--server is required (or use --all)")
            }

            if toolName == "" {
                if err := store.ResetServer(serverID); err != nil {
                    return err
                }
                cmd.Printf("All pins for server %s removed\n", serverID)
                return nil
            }

            if err := store.Reset(serverID, toolName); err != nil {
                return err
            }
            cmd.Printf("Pin for %s:%s removed\n", serverID, toolName)
            return nil
        },
    }

    cmd.Flags().StringVar(&serverID, "server", "", "Server ID")
    cmd.Flags().StringVar(&toolName, "tool", "", "Tool name")
    cmd.Flags().BoolVar(&all, "all", false, "Remove all pins")

    return cmd
}
```

**Step 4: Add pins subcommand to mcp_cmd.go**

In `internal/cli/mcp_cmd.go`, add to `newMCPCmd()`:

```go
cmd.AddCommand(newMCPPinsCmd())
```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/cli/... -run TestMCPPins -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/cli/mcp_pins.go internal/cli/mcp_pins_test.go internal/cli/mcp_cmd.go
git commit -m "feat(cli): add mcp pins commands for version pinning management"
```

---

## Task 5: MCP Rate Limiter Registry

**Files:**
- Create: `internal/mcpinspect/ratelimit.go`
- Create: `internal/mcpinspect/ratelimit_test.go`

**Step 1: Write failing test for rate limiter registry**

Create `internal/mcpinspect/ratelimit_test.go`:

```go
package mcpinspect

import (
    "testing"

    "github.com/agentsh/agentsh/internal/config"
)

func TestRateLimiterRegistry_DefaultLimits(t *testing.T) {
    cfg := config.MCPRateLimitsConfig{
        Enabled:      true,
        DefaultRPM:   60,
        DefaultBurst: 10,
    }

    reg := NewRateLimiterRegistry(cfg)

    // First call should be allowed
    if !reg.Allow("github", "create_issue") {
        t.Error("First call should be allowed")
    }

    // Exhaust burst
    for i := 0; i < 9; i++ {
        reg.Allow("github", "create_issue")
    }

    // Next call should be blocked (burst exhausted)
    if reg.Allow("github", "create_issue") {
        t.Error("Call after burst exhausted should be blocked")
    }
}

func TestRateLimiterRegistry_PerServerLimits(t *testing.T) {
    cfg := config.MCPRateLimitsConfig{
        Enabled:      true,
        DefaultRPM:   60,
        DefaultBurst: 10,
        PerServer: map[string]config.MCPRateLimit{
            "slow-server": {CallsPerMinute: 6, Burst: 2},
        },
    }

    reg := NewRateLimiterRegistry(cfg)

    // slow-server should have stricter limits
    reg.Allow("slow-server", "tool1")
    reg.Allow("slow-server", "tool2")
    if reg.Allow("slow-server", "tool3") {
        t.Error("slow-server should be limited after burst of 2")
    }

    // other servers use default
    for i := 0; i < 10; i++ {
        reg.Allow("fast-server", "tool1")
    }
    if reg.Allow("fast-server", "tool1") {
        t.Error("fast-server should be limited after burst of 10")
    }
}

func TestRateLimiterRegistry_Disabled(t *testing.T) {
    cfg := config.MCPRateLimitsConfig{
        Enabled: false,
    }

    reg := NewRateLimiterRegistry(cfg)

    // All calls should be allowed when disabled
    for i := 0; i < 1000; i++ {
        if !reg.Allow("any", "tool") {
            t.Error("All calls should be allowed when disabled")
        }
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpinspect/... -run TestRateLimiterRegistry -v`
Expected: FAIL (RateLimiterRegistry not defined)

**Step 3: Implement RateLimiterRegistry**

Create `internal/mcpinspect/ratelimit.go`:

```go
package mcpinspect

import (
    "sync"

    "github.com/agentsh/agentsh/internal/config"
    "github.com/agentsh/agentsh/pkg/ratelimit"
)

// RateLimiterRegistry manages rate limiters for MCP servers.
type RateLimiterRegistry struct {
    cfg      config.MCPRateLimitsConfig
    limiters map[string]*ratelimit.Limiter
    mu       sync.RWMutex
}

// NewRateLimiterRegistry creates a new rate limiter registry.
func NewRateLimiterRegistry(cfg config.MCPRateLimitsConfig) *RateLimiterRegistry {
    return &RateLimiterRegistry{
        cfg:      cfg,
        limiters: make(map[string]*ratelimit.Limiter),
    }
}

// Allow checks if a call to a server/tool is allowed under rate limits.
func (r *RateLimiterRegistry) Allow(serverID, toolName string) bool {
    if !r.cfg.Enabled {
        return true
    }

    limiter := r.getLimiter(serverID)
    return limiter.Allow()
}

// AllowN checks if n calls are allowed.
func (r *RateLimiterRegistry) AllowN(serverID, toolName string, n int) bool {
    if !r.cfg.Enabled {
        return true
    }

    limiter := r.getLimiter(serverID)
    return limiter.AllowN(n)
}

func (r *RateLimiterRegistry) getLimiter(serverID string) *ratelimit.Limiter {
    r.mu.RLock()
    limiter, ok := r.limiters[serverID]
    r.mu.RUnlock()

    if ok {
        return limiter
    }

    // Create new limiter
    r.mu.Lock()
    defer r.mu.Unlock()

    // Double-check after acquiring write lock
    if limiter, ok = r.limiters[serverID]; ok {
        return limiter
    }

    // Check for per-server config
    rate := float64(r.cfg.DefaultRPM) / 60.0 // Convert RPM to RPS
    burst := r.cfg.DefaultBurst

    if serverCfg, exists := r.cfg.PerServer[serverID]; exists {
        rate = float64(serverCfg.CallsPerMinute) / 60.0
        burst = serverCfg.Burst
    }

    limiter = ratelimit.NewLimiter(rate, burst)
    r.limiters[serverID] = limiter
    return limiter
}

// Reset clears all limiters (useful for testing or config reload).
func (r *RateLimiterRegistry) Reset() {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.limiters = make(map[string]*ratelimit.Limiter)
}

// Stats returns current token counts for all tracked servers.
func (r *RateLimiterRegistry) Stats() map[string]float64 {
    r.mu.RLock()
    defer r.mu.RUnlock()

    stats := make(map[string]float64, len(r.limiters))
    for serverID, limiter := range r.limiters {
        stats[serverID] = limiter.Tokens()
    }
    return stats
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/mcpinspect/... -run TestRateLimiterRegistry -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/mcpinspect/ratelimit.go internal/mcpinspect/ratelimit_test.go
git commit -m "feat(mcpinspect): add rate limiter registry for MCP servers"
```

---

## Task 6: Inspector Integration

**Files:**
- Modify: `internal/mcpinspect/inspector.go` (add policy and pin verification)
- Modify: `internal/mcpinspect/inspector_test.go` (add integration tests)

**Step 1: Write failing test for inspector integration**

Add to `internal/mcpinspect/inspector_test.go`:

```go
func TestInspector_PolicyEnforcement(t *testing.T) {
    cfg := config.SandboxMCPConfig{
        EnforcePolicy: true,
        ToolPolicy:    "allowlist",
        AllowedTools: []config.MCPToolRule{
            {Server: "github", Tool: "*"},
        },
    }

    events := make([]interface{}, 0)
    emitter := func(e interface{}) { events = append(events, e) }

    inspector := NewInspectorWithPolicy("session1", "github", emitter, cfg)

    // Allowed tool should pass
    allowed, reason := inspector.CheckPolicy("create_issue", "sha256:abc")
    if !allowed {
        t.Errorf("Expected github:create_issue to be allowed, got denied: %s", reason)
    }

    // Create inspector for disallowed server
    inspector2 := NewInspectorWithPolicy("session1", "blocked", emitter, cfg)
    allowed, reason = inspector2.CheckPolicy("any_tool", "sha256:def")
    if allowed {
        t.Error("Expected blocked:any_tool to be denied")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpinspect/... -run TestInspector_Policy -v`
Expected: FAIL (NewInspectorWithPolicy not defined)

**Step 3: Implement policy integration in Inspector**

Update `internal/mcpinspect/inspector.go`:

```go
package mcpinspect

import (
    "time"

    "github.com/agentsh/agentsh/internal/config"
)

// Inspector processes MCP messages and emits audit events.
type Inspector struct {
    sessionID     string
    serverID      string
    registry      *Registry
    detector      *Detector
    policyEval    *PolicyEvaluator
    rateLimiter   *RateLimiterRegistry
    emitEvent     EventEmitter
}

// NewInspector creates a new MCP inspector for a server connection.
func NewInspector(sessionID, serverID string, emitter EventEmitter) *Inspector {
    return &Inspector{
        sessionID: sessionID,
        serverID:  serverID,
        registry:  NewRegistry(true),
        detector:  nil,
        emitEvent: emitter,
    }
}

// NewInspectorWithDetection creates a new MCP inspector with pattern detection enabled.
func NewInspectorWithDetection(sessionID, serverID string, emitter EventEmitter) *Inspector {
    return &Inspector{
        sessionID: sessionID,
        serverID:  serverID,
        registry:  NewRegistry(true),
        detector:  NewDetector(),
        emitEvent: emitter,
    }
}

// NewInspectorWithPolicy creates an inspector with policy enforcement.
func NewInspectorWithPolicy(sessionID, serverID string, emitter EventEmitter, cfg config.SandboxMCPConfig) *Inspector {
    return &Inspector{
        sessionID:   sessionID,
        serverID:    serverID,
        registry:    NewRegistry(cfg.VersionPinning.AutoTrustFirst),
        detector:    NewDetector(),
        policyEval:  NewPolicyEvaluator(cfg),
        rateLimiter: NewRateLimiterRegistry(cfg.RateLimits),
        emitEvent:   emitter,
    }
}

// CheckPolicy checks if a tool invocation is allowed by policy.
func (i *Inspector) CheckPolicy(toolName, hash string) (allowed bool, reason string) {
    if i.policyEval == nil {
        return true, "no policy configured"
    }

    decision := i.policyEval.Evaluate(i.serverID, toolName, hash)
    return decision.Allowed, decision.Reason
}

// CheckRateLimit checks if a tool call is within rate limits.
func (i *Inspector) CheckRateLimit(toolName string) bool {
    if i.rateLimiter == nil {
        return true
    }
    return i.rateLimiter.Allow(i.serverID, toolName)
}

// Inspect processes an MCP message and emits relevant events.
func (i *Inspector) Inspect(data []byte, dir Direction) error {
    // ... existing implementation unchanged ...
}

// ... rest of existing code ...
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/mcpinspect/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/mcpinspect/inspector.go internal/mcpinspect/inspector_test.go
git commit -m "feat(mcpinspect): integrate policy and rate limiting into inspector"
```

---

## Task 7: Domain Rate Limiting for Network

**Files:**
- Create: `internal/netmonitor/ratelimit.go`
- Create: `internal/netmonitor/ratelimit_test.go`
- Modify: `internal/config/config.go` (add network rate limit config)

**Step 1: Add network rate limit config**

In `internal/config/config.go`, add to `SandboxNetworkConfig`:

```go
type SandboxNetworkConfig struct {
    // ... existing fields ...
    RateLimits NetworkRateLimitsConfig `yaml:"rate_limits"`
}

// NetworkRateLimitsConfig configures network rate limiting.
type NetworkRateLimitsConfig struct {
    Enabled      bool                       `yaml:"enabled"`
    GlobalRPM    int                        `yaml:"global_rpm"`
    GlobalBurst  int                        `yaml:"global_burst"`
    PerDomain    map[string]DomainRateLimit `yaml:"per_domain"`
}

// DomainRateLimit defines rate limits for a domain.
type DomainRateLimit struct {
    RequestsPerMinute int `yaml:"requests_per_minute"`
    Burst             int `yaml:"burst"`
}
```

**Step 2: Write failing test for domain rate limiter**

Create `internal/netmonitor/ratelimit_test.go`:

```go
package netmonitor

import (
    "testing"

    "github.com/agentsh/agentsh/internal/config"
)

func TestDomainRateLimiter_PerDomainLimits(t *testing.T) {
    cfg := config.NetworkRateLimitsConfig{
        Enabled:     true,
        GlobalRPM:   600,
        GlobalBurst: 50,
        PerDomain: map[string]config.DomainRateLimit{
            "api.openai.com": {RequestsPerMinute: 60, Burst: 10},
        },
    }

    limiter := NewDomainRateLimiter(cfg)

    // OpenAI should have strict limits
    for i := 0; i < 10; i++ {
        limiter.Allow("api.openai.com")
    }
    if limiter.Allow("api.openai.com") {
        t.Error("api.openai.com should be limited after burst of 10")
    }

    // Other domains use global limits
    for i := 0; i < 50; i++ {
        limiter.Allow("example.com")
    }
    if limiter.Allow("example.com") {
        t.Error("example.com should be limited after burst of 50")
    }
}
```

**Step 3: Run test to verify it fails**

Run: `go test ./internal/netmonitor/... -run TestDomainRateLimiter -v`
Expected: FAIL (DomainRateLimiter not defined)

**Step 4: Implement DomainRateLimiter**

Create `internal/netmonitor/ratelimit.go`:

```go
package netmonitor

import (
    "sync"

    "github.com/agentsh/agentsh/internal/config"
    "github.com/agentsh/agentsh/pkg/ratelimit"
)

// DomainRateLimiter manages rate limits for network domains.
type DomainRateLimiter struct {
    cfg      config.NetworkRateLimitsConfig
    global   *ratelimit.Limiter
    domains  map[string]*ratelimit.Limiter
    mu       sync.RWMutex
}

// NewDomainRateLimiter creates a new domain rate limiter.
func NewDomainRateLimiter(cfg config.NetworkRateLimitsConfig) *DomainRateLimiter {
    var global *ratelimit.Limiter
    if cfg.GlobalRPM > 0 {
        global = ratelimit.NewLimiter(float64(cfg.GlobalRPM)/60.0, cfg.GlobalBurst)
    }

    return &DomainRateLimiter{
        cfg:     cfg,
        global:  global,
        domains: make(map[string]*ratelimit.Limiter),
    }
}

// Allow checks if a request to a domain is allowed.
func (d *DomainRateLimiter) Allow(domain string) bool {
    if !d.cfg.Enabled {
        return true
    }

    // Check global limit first
    if d.global != nil && !d.global.Allow() {
        return false
    }

    // Check per-domain limit
    limiter := d.getDomainLimiter(domain)
    if limiter != nil {
        return limiter.Allow()
    }

    return true
}

func (d *DomainRateLimiter) getDomainLimiter(domain string) *ratelimit.Limiter {
    // Check if there's a specific config for this domain
    domainCfg, exists := d.cfg.PerDomain[domain]
    if !exists {
        // Check for wildcard
        domainCfg, exists = d.cfg.PerDomain["*"]
        if !exists {
            return nil
        }
    }

    d.mu.RLock()
    limiter, ok := d.domains[domain]
    d.mu.RUnlock()

    if ok {
        return limiter
    }

    // Create new limiter
    d.mu.Lock()
    defer d.mu.Unlock()

    if limiter, ok = d.domains[domain]; ok {
        return limiter
    }

    limiter = ratelimit.NewLimiter(
        float64(domainCfg.RequestsPerMinute)/60.0,
        domainCfg.Burst,
    )
    d.domains[domain] = limiter
    return limiter
}

// Stats returns current token counts.
func (d *DomainRateLimiter) Stats() map[string]float64 {
    d.mu.RLock()
    defer d.mu.RUnlock()

    stats := make(map[string]float64)
    if d.global != nil {
        stats["_global"] = d.global.Tokens()
    }
    for domain, limiter := range d.domains {
        stats[domain] = limiter.Tokens()
    }
    return stats
}
```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/netmonitor/... -run TestDomainRateLimiter -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/netmonitor/ratelimit.go internal/netmonitor/ratelimit_test.go internal/config/config.go
git commit -m "feat(netmonitor): add domain rate limiting for network requests"
```

---

## Task 8: Final Integration and Documentation

**Files:**
- Update: `docs/plans/2026-01-06-security-gaps-design.md` (mark Phase 3 complete)
- Update: `SECURITY.md` (add MCP security section)
- Update: `README.md` (add MCP security reference)

**Step 1: Update SECURITY.md**

Add MCP Security section to SECURITY.md:

```markdown
## MCP Security

### Tool Whitelisting

agentsh supports policy-based control over which MCP tools can be invoked:

```yaml
sandbox:
  mcp:
    enforce_policy: true
    fail_closed: true
    tool_policy: allowlist
    allowed_tools:
      - server: "filesystem"
        tool: "read_file"
      - server: "github"
        tool: "*"
```

| Policy Mode | Behavior |
|-------------|----------|
| `allowlist` | Only explicitly listed tools are permitted |
| `denylist` | Listed tools are blocked, all others allowed |
| `none` | No policy enforcement |

### Version Pinning

Detect and optionally block MCP tool definition changes (rug pull detection):

```yaml
sandbox:
  mcp:
    version_pinning:
      enabled: true
      on_change: block  # block, alert, allow
      auto_trust_first: true
```

CLI management:
```bash
agentsh mcp pins list
agentsh mcp pins trust --server github --tool create_issue --hash sha256:...
agentsh mcp pins reset --server github --tool create_issue
```

### Rate Limiting

Token bucket rate limiting for MCP calls:

```yaml
sandbox:
  mcp:
    rate_limits:
      enabled: true
      default_rpm: 120
      default_burst: 20
      per_server:
        "slow-api":
          calls_per_minute: 30
          burst: 5
```
```

**Step 2: Run full test suite**

Run: `go test ./... -v`
Expected: All tests pass

**Step 3: Commit documentation**

```bash
git add SECURITY.md README.md docs/plans/2026-01-06-security-gaps-design.md
git commit -m "docs: add MCP security documentation for Phase 3"
```

---

## Summary

| Task | Component | Tests |
|------|-----------|-------|
| 1 | Config types | - |
| 2 | Policy evaluator | 3 |
| 3 | Pin storage | 3 |
| 4 | Pins CLI | 1 |
| 5 | MCP rate limiter | 3 |
| 6 | Inspector integration | 1 |
| 7 | Domain rate limiter | 1 |
| 8 | Documentation | - |

**Total new tests:** 12
