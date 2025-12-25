package session

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

var (
	ErrCheckpointNotFound   = errors.New("checkpoint not found")
	ErrRollbackNotSupported = errors.New("rollback not supported for this checkpoint")
)

// Checkpoint represents a snapshot of session state that can be used for recovery.
type Checkpoint struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
	Reason    string    `json:"reason"`

	// Snapshot of session state
	Stats types.SessionStats `json:"stats"`

	// File system state (for recovery)
	WorkspaceHash string   `json:"workspace_hash"`
	ModifiedFiles []string `json:"modified_files"`

	// Can be used for rollback
	CanRollback bool `json:"can_rollback"`
}

// CheckpointStorage provides persistence for checkpoints.
type CheckpointStorage interface {
	Save(cp *Checkpoint) error
	Load(sessionID, checkpointID string) (*Checkpoint, error)
	List(sessionID string) ([]*Checkpoint, error)
	Delete(sessionID, checkpointID string) error
}

// CheckpointManager handles checkpoint creation and recovery for sessions.
type CheckpointManager struct {
	mu      sync.RWMutex
	storage CheckpointStorage
}

// NewCheckpointManager creates a new checkpoint manager.
func NewCheckpointManager(storage CheckpointStorage) *CheckpointManager {
	return &CheckpointManager{
		storage: storage,
	}
}

// CreateCheckpoint creates a checkpoint for the given session.
func (m *CheckpointManager) CreateCheckpoint(s *Session, reason string) (*Checkpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s.mu.Lock()
	stats := s.stats
	workspace := s.Workspace
	sessionID := s.ID
	s.mu.Unlock()

	cp := &Checkpoint{
		ID:        uuid.New().String(),
		SessionID: sessionID,
		CreatedAt: time.Now().UTC(),
		Reason:    reason,
		Stats:     stats,
	}

	// Hash current workspace state
	hash, modifiedFiles, err := hashWorkspace(workspace)
	if err != nil {
		// Non-fatal: checkpoint still created but without workspace hash
		cp.CanRollback = false
	} else {
		cp.WorkspaceHash = hash
		cp.ModifiedFiles = modifiedFiles
		cp.CanRollback = true
	}

	// Save checkpoint
	if m.storage != nil {
		if err := m.storage.Save(cp); err != nil {
			return nil, err
		}
	}

	return cp, nil
}

// ListCheckpoints returns all checkpoints for a session.
func (m *CheckpointManager) ListCheckpoints(sessionID string) ([]*Checkpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.storage == nil {
		return nil, nil
	}

	return m.storage.List(sessionID)
}

// GetCheckpoint retrieves a specific checkpoint.
func (m *CheckpointManager) GetCheckpoint(sessionID, checkpointID string) (*Checkpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.storage == nil {
		return nil, ErrCheckpointNotFound
	}

	return m.storage.Load(sessionID, checkpointID)
}

// hashWorkspace calculates a hash of the workspace and returns modified files.
func hashWorkspace(workspacePath string) (string, []string, error) {
	h := sha256.New()
	var modifiedFiles []string

	err := filepath.WalkDir(workspacePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories
		if d.IsDir() && len(d.Name()) > 0 && d.Name()[0] == '.' {
			return filepath.SkipDir
		}

		// Skip directories for hashing
		if d.IsDir() {
			return nil
		}

		// Get relative path
		rel, err := filepath.Rel(workspacePath, path)
		if err != nil {
			return err
		}

		// Hash file content
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		// Write path to hash
		h.Write([]byte(rel))

		// Write content to hash
		if _, err := io.Copy(h, f); err != nil {
			return err
		}

		modifiedFiles = append(modifiedFiles, rel)
		return nil
	})

	if err != nil {
		return "", nil, err
	}

	return hex.EncodeToString(h.Sum(nil)), modifiedFiles, nil
}

// InMemoryCheckpointStorage provides in-memory checkpoint storage for testing.
type InMemoryCheckpointStorage struct {
	mu          sync.RWMutex
	checkpoints map[string]map[string]*Checkpoint // sessionID -> checkpointID -> checkpoint
}

// NewInMemoryCheckpointStorage creates a new in-memory checkpoint storage.
func NewInMemoryCheckpointStorage() *InMemoryCheckpointStorage {
	return &InMemoryCheckpointStorage{
		checkpoints: make(map[string]map[string]*Checkpoint),
	}
}

func (s *InMemoryCheckpointStorage) Save(cp *Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.checkpoints[cp.SessionID]; !ok {
		s.checkpoints[cp.SessionID] = make(map[string]*Checkpoint)
	}
	s.checkpoints[cp.SessionID][cp.ID] = cp
	return nil
}

func (s *InMemoryCheckpointStorage) Load(sessionID, checkpointID string) (*Checkpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.checkpoints[sessionID]
	if !ok {
		return nil, ErrCheckpointNotFound
	}

	cp, ok := session[checkpointID]
	if !ok {
		return nil, ErrCheckpointNotFound
	}

	return cp, nil
}

func (s *InMemoryCheckpointStorage) List(sessionID string) ([]*Checkpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.checkpoints[sessionID]
	if !ok {
		return nil, nil
	}

	result := make([]*Checkpoint, 0, len(session))
	for _, cp := range session {
		result = append(result, cp)
	}
	return result, nil
}

func (s *InMemoryCheckpointStorage) Delete(sessionID, checkpointID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if session, ok := s.checkpoints[sessionID]; ok {
		delete(session, checkpointID)
	}
	return nil
}
