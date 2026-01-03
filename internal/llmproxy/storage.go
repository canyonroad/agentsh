package llmproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RequestLogEntry represents a logged request.
type RequestLogEntry struct {
	ID        string      `json:"id"`
	SessionID string      `json:"session_id"`
	Timestamp time.Time   `json:"timestamp"`
	Dialect   Dialect     `json:"dialect"`
	Request   RequestInfo `json:"request"`
	DLP       *DLPInfo    `json:"dlp,omitempty"`
}

// RequestInfo contains request details.
type RequestInfo struct {
	Method   string              `json:"method"`
	Path     string              `json:"path"`
	Headers  map[string][]string `json:"headers"`
	BodySize int                 `json:"body_size"`
	BodyHash string              `json:"body_hash"`
}

// ResponseLogEntry represents a logged response.
type ResponseLogEntry struct {
	RequestID  string       `json:"request_id"`
	SessionID  string       `json:"session_id"`
	Timestamp  time.Time    `json:"timestamp"`
	DurationMs int64        `json:"duration_ms"`
	Response   ResponseInfo `json:"response"`
	Usage      Usage        `json:"usage,omitempty"`
}

// ResponseInfo contains response details.
type ResponseInfo struct {
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers"`
	BodySize int                 `json:"body_size,omitempty"`
	BodyHash string              `json:"body_hash,omitempty"`
}

// DLPInfo contains DLP processing information.
type DLPInfo struct {
	Redactions []Redaction `json:"redactions"`
}

// Storage handles request/response logging to disk.
type Storage struct {
	basePath  string
	sessionID string
	file      *os.File
	mu        sync.Mutex
}

// NewStorage creates a new storage instance.
// basePath is the base storage directory (e.g., ~/.agentsh/sessions).
// sessionID is the current session ID.
func NewStorage(basePath, sessionID string) (*Storage, error) {
	if basePath == "" || sessionID == "" {
		// Return a no-op storage if not configured
		return &Storage{
			basePath:  basePath,
			sessionID: sessionID,
		}, nil
	}

	// Create session directory
	sessionDir := filepath.Join(basePath, sessionID)
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		return nil, fmt.Errorf("create session directory: %w", err)
	}

	// Create llm-bodies directory for full body storage (Phase 2 feature)
	bodiesDir := filepath.Join(sessionDir, "llm-bodies")
	if err := os.MkdirAll(bodiesDir, 0700); err != nil {
		return nil, fmt.Errorf("create bodies directory: %w", err)
	}

	// Open JSONL file for appending
	logPath := filepath.Join(sessionDir, "llm-requests.jsonl")
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	return &Storage{
		basePath:  basePath,
		sessionID: sessionID,
		file:      file,
	}, nil
}

// LogRequest logs a request entry to the JSONL file.
func (s *Storage) LogRequest(entry *RequestLogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file == nil {
		// No-op storage mode
		return nil
	}

	return s.writeEntry(entry)
}

// LogResponse logs a response entry to the JSONL file.
func (s *Storage) LogResponse(entry *ResponseLogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file == nil {
		// No-op storage mode
		return nil
	}

	return s.writeEntry(entry)
}

// writeEntry marshals and writes an entry to the JSONL file.
func (s *Storage) writeEntry(entry interface{}) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}

	// Append newline for JSONL format
	data = append(data, '\n')

	if _, err := s.file.Write(data); err != nil {
		return fmt.Errorf("write entry: %w", err)
	}

	return nil
}

// Close closes the storage file.
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file != nil {
		if err := s.file.Close(); err != nil {
			return fmt.Errorf("close log file: %w", err)
		}
		s.file = nil
	}
	return nil
}

// LogPath returns the path to the JSONL log file.
func (s *Storage) LogPath() string {
	if s.basePath == "" || s.sessionID == "" {
		return ""
	}
	return filepath.Join(s.basePath, s.sessionID, "llm-requests.jsonl")
}

// BodiesPath returns the path to the bodies directory.
func (s *Storage) BodiesPath() string {
	if s.basePath == "" || s.sessionID == "" {
		return ""
	}
	return filepath.Join(s.basePath, s.sessionID, "llm-bodies")
}

// HashBody computes a SHA256 hash of the body for integrity verification.
// Returns an empty string for empty bodies.
// Format: "sha256:hexdigest"
func HashBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	hash := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(hash[:])
}

// ReadLogEntries reads all log entries from storage.
// This is useful for testing and debugging.
func (s *Storage) ReadLogEntries() ([]json.RawMessage, error) {
	logPath := s.LogPath()
	if logPath == "" {
		return nil, nil
	}

	file, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open log file: %w", err)
	}
	defer file.Close()

	var entries []json.RawMessage
	decoder := json.NewDecoder(file)
	for {
		var entry json.RawMessage
		if err := decoder.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode entry: %w", err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}
