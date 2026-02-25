package mcpinspect

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
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
	ServerID  string    `json:"server_id"`
	ToolName  string    `json:"tool_name"`
	Hash      string    `json:"hash"`
	TrustedAt time.Time `json:"trusted_at"`
	TrustedBy string    `json:"trusted_by,omitempty"`
}

// VerifyResult is returned from pin verification.
type VerifyResult struct {
	Status      PinStatus
	PinnedHash  string
	CurrentHash string
}

// PinStore manages persistent tool version pins.
type PinStore struct {
	db *sql.DB
}

// NewPinStore creates a new pin store at the given path.
func NewPinStore(path string) (*PinStore, error) {
	if path == "" {
		return nil, fmt.Errorf("pin store path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir db dir: %w", err)
	}

	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := initPinSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	return &PinStore{db: db}, nil
}

func initPinSchema(db *sql.DB) error {
	stmts := []string{
		`PRAGMA journal_mode=WAL;`,
		`CREATE TABLE IF NOT EXISTS mcp_pins (
			server_id TEXT NOT NULL,
			tool_name TEXT NOT NULL,
			hash TEXT NOT NULL,
			trusted_at_ns INTEGER NOT NULL,
			trusted_by TEXT,
			PRIMARY KEY (server_id, tool_name)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_pins_server ON mcp_pins(server_id);`,
		`CREATE TABLE IF NOT EXISTS mcp_server_pins (
			server_id TEXT NOT NULL PRIMARY KEY,
			binary_path TEXT NOT NULL,
			binary_hash TEXT NOT NULL,
			trusted_at_ns INTEGER NOT NULL,
			trusted_by TEXT
		);`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("init pin schema: %w", err)
		}
	}
	return nil
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
		INSERT OR REPLACE INTO mcp_pins (server_id, tool_name, hash, trusted_at_ns, trusted_by)
		VALUES (?, ?, ?, ?, ?)
	`, serverID, toolName, hash, time.Now().UTC().UnixNano(), nullable(operatorID))
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
			SELECT server_id, tool_name, hash, trusted_at_ns, COALESCE(trusted_by, '')
			FROM mcp_pins ORDER BY server_id, tool_name
		`)
	} else {
		rows, err = s.db.Query(`
			SELECT server_id, tool_name, hash, trusted_at_ns, COALESCE(trusted_by, '')
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
		var trustedAtNs int64
		if err := rows.Scan(&p.ServerID, &p.ToolName, &p.Hash, &trustedAtNs, &p.TrustedBy); err != nil {
			return nil, err
		}
		p.TrustedAt = time.Unix(0, trustedAtNs)
		pins = append(pins, p)
	}
	return pins, rows.Err()
}

// Get returns a specific pin.
func (s *PinStore) Get(serverID, toolName string) (*Pin, error) {
	var p Pin
	var trustedAtNs int64
	err := s.db.QueryRow(`
		SELECT server_id, tool_name, hash, trusted_at_ns, COALESCE(trusted_by, '')
		FROM mcp_pins WHERE server_id = ? AND tool_name = ?
	`, serverID, toolName).Scan(&p.ServerID, &p.ToolName, &p.Hash, &trustedAtNs, &p.TrustedBy)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.TrustedAt = time.Unix(0, trustedAtNs)
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

// nullable returns nil for empty strings, otherwise the string value.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// BinaryPin represents a pinned server binary.
type BinaryPin struct {
	ServerID   string    `json:"server_id"`
	BinaryPath string    `json:"binary_path"`
	BinaryHash string    `json:"binary_hash"`
	TrustedAt  time.Time `json:"trusted_at"`
	TrustedBy  string    `json:"trusted_by,omitempty"`
}

// TrustBinary pins a server binary at the given hash.
func (s *PinStore) TrustBinary(serverID, binaryPath, hash string) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO mcp_server_pins (server_id, binary_path, binary_hash, trusted_at_ns, trusted_by)
		VALUES (?, ?, ?, ?, NULL)
	`, serverID, binaryPath, hash, time.Now().UTC().UnixNano())
	return err
}

// VerifyBinary checks if a server binary hash matches its pin.
func (s *PinStore) VerifyBinary(serverID, hash string) (*VerifyResult, error) {
	var pinnedHash string
	err := s.db.QueryRow(`
		SELECT binary_hash FROM mcp_server_pins WHERE server_id = ?
	`, serverID).Scan(&pinnedHash)

	if err == sql.ErrNoRows {
		return &VerifyResult{Status: PinStatusNotPinned, CurrentHash: hash}, nil
	}
	if err != nil {
		return nil, err
	}

	status := PinStatusMatch
	if pinnedHash != hash {
		status = PinStatusMismatch
	}
	return &VerifyResult{Status: status, PinnedHash: pinnedHash, CurrentHash: hash}, nil
}

// ListBinaryPins returns all binary pins ordered by server ID.
func (s *PinStore) ListBinaryPins() ([]BinaryPin, error) {
	rows, err := s.db.Query(`
		SELECT server_id, binary_path, binary_hash, trusted_at_ns, COALESCE(trusted_by, '')
		FROM mcp_server_pins ORDER BY server_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pins []BinaryPin
	for rows.Next() {
		var p BinaryPin
		var trustedAtNs int64
		if err := rows.Scan(&p.ServerID, &p.BinaryPath, &p.BinaryHash, &trustedAtNs, &p.TrustedBy); err != nil {
			return nil, err
		}
		p.TrustedAt = time.Unix(0, trustedAtNs)
		pins = append(pins, p)
	}
	return pins, rows.Err()
}
